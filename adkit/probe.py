"""Active-but-read-only probe runner.

The probe sends GET requests with a small, fixed set of payloads and reports
the evidence for each one: status, size, time, and whether the response
contains the marker that proves the payload reached the sink.

What it never does:

- send anything but GET
- touch a path that mentions the checker
- run more than MAX_REQUESTS requests
- loop over ids (no brute force)
- follow redirects (the redirect itself is the evidence)

Authorization is checked separately by `auth_diff`: the same path is fetched
twice, once without a session and once with the operator's own cookie. A route
that answers both the same way does not distinguish callers. That is the one
authorization test that needs no second account and no writes.
"""
from __future__ import annotations

import hashlib
import re
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request

from .payloads import Payload, is_probeable, payloads_for
from .ratelimit import BUDGET

MAX_REQUESTS = 14
MAX_BODY = 65536
DELAY = 0.15
MIN_DELAY = 0.10
TIMEOUT = 4.0
BLOCKED = ("/_checker", "putflag", "getflag", "checkflag")

# Журнал фактически отправленных запросов. Нужен как доказательство профиля
# трафика: сколько, когда, сколько байт. Пишется только на реальной отправке.
MAX_JOURNAL = 500
JOURNAL: list[dict] = []

# Флаг турнира в ответе — это не «ещё одна улика», это добыча. Ищем форму
# `prefix{...}` в любом ответе: если сервис отдал флаг на GET, он уже потерян.
FLAG_RE = re.compile(r"\b[A-Za-z][A-Za-z0-9_]{1,15}\{[^{}\s]{6,80}\}")

# Страница входа, отданная с кодом 200, — это не «доступ», это отказ в
# вежливой форме. Признаки ищем в теле и в заголовке Location.
LOGIN_MARKERS = re.compile(
    r"(?i)(name=[\"']password[\"']|type=[\"']password[\"']|sign[\s_-]?in|log[\s_-]?in"
    r"|войти|авторизац|\bcsrf\b|access[\s_-]?denied|unauthori[sz]ed|forbidden)"
)
LOGIN_REDIRECT = re.compile(r"(?i)/(login|log-in|signin|sign-in|auth|session|войти)")

PARAM_PATTERNS = (
    re.compile(r"""request\.args\.get\(\s*["']([\w.-]+)"""),
    re.compile(r"""request\.values\.get\(\s*["']([\w.-]+)"""),
    re.compile(r"""request\.form\.get\(\s*["']([\w.-]+)"""),
    re.compile(r"""\$_GET\[\s*["']([\w.-]+)"""),
    re.compile(r"""\$_REQUEST\[\s*["']([\w.-]+)"""),
    re.compile(r"""req\.query\.([\w.-]+)"""),
    re.compile(r"""req\.query\[\s*["']([\w.-]+)"""),
    re.compile(r"""req\.params\.([\w.-]+)"""),
    re.compile(r"""c\.Query\(\s*"([\w.-]+)"""),
    re.compile(r"""c\.Param\(\s*"([\w.-]+)"""),
    re.compile(r"""URL\.Query\(\)\.Get\(\s*"([\w.-]+)"""),
    re.compile(r"""r\.URL\.Query\(\)\.Get\(\s*"([\w.-]+)"""),
    re.compile(r"""getParameter\(\s*"([\w.-]+)"""),
    re.compile(r"""params\[:([\w.-]+)\]"""),
    re.compile(r"""args\[([\w.-]+)\]"""),
    # stdlib-стили: parse_qs + собственный хелпер, searchParams, query.get
    re.compile(r"""\.query\.get\(\s*["']([\w.-]+)"""),
    re.compile(r"""searchParams\.get\(\s*["']([\w.-]+)"""),
    re.compile(r"""\bone\(\s*["']([\w.-]+)"""),
    re.compile(r"""\.get\(\s*["']([\w.-]+)["']\s*,\s*["']"""),
    re.compile(r"""\bparams\.get\(\s*["']([\w.-]+)"""),
)

PATH_TEMPLATE = re.compile(r"<(?:\w+:)?(\w+)>|:(\w+)|\{(\w+)(?::[^}]*)?\}")


class ProbeError(RuntimeError):
    """Raised when a probe cannot run at all (bad base, blocked path)."""


class BudgetExhausted(ProbeError):
    """Raised when the process-wide request budget is spent."""

    def __init__(self, retry_after: float) -> None:
        super().__init__(f"budget spent; retry in {retry_after:.0f}s")
        self.retry_after = retry_after


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        return None


def _opener():
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return urllib.request.build_opener(_NoRedirect, urllib.request.HTTPSHandler(context=context))


def _blocked(path: str) -> bool:
    lowered = path.lower()
    return any(marker in lowered for marker in BLOCKED)


def detect_param(context: list[str], fallback: str = "id", snippet: str = "") -> str:
    """Parameter name the handler reads, from the finding's context window.

    The sink line comes first: an app that reads several parameters declares
    them in one order and uses them in another. Whoever appears in the
    vulnerable expression is the one to hit.
    """
    candidates: list[str] = []
    for line in context or []:
        for pattern in PARAM_PATTERNS:
            for match in pattern.finditer(line):
                candidates.append(match.group(1))
    if not candidates:
        return fallback
    if snippet:
        for name in candidates:
            if name and name in snippet:
                return name
    return candidates[0]


def resolve_endpoint(endpoint: str) -> tuple[str, str | None]:
    """Return (path with a benign value substituted, template slot or None)."""
    path = endpoint or "/"
    match = PATH_TEMPLATE.search(path)
    if not match:
        return path, None
    token = match.group(0)
    return path.replace(token, "1", 1), token


def _fill(value: str, port: int) -> str:
    return value.replace("{port}", str(port))


def build_requests(finding: dict, endpoint: str, port: int = 80) -> list[dict]:
    """Materialize the request list for one finding. Pure: no network."""
    kind = finding.get("kind", "")
    path, slot = resolve_endpoint(endpoint)
    param = finding.get("param") or detect_param(
        finding.get("context", []), snippet=finding.get("snippet", "")
    )
    requests: list[dict] = []

    if kind == "IDOR / BOLA":
        match = re.search(r"(\d+)(?=\D*$)", path)
        if match:
            base_id = int(match.group(1))
            for offset in (1, -1, 2):
                candidate = base_id + offset
                if candidate <= 0:
                    continue
                requests.append({
                    "label": f"id={candidate}",
                    "path": path[:match.start(1)] + str(candidate) + path[match.end(1):],
                    "marker": None,
                    "compare": True,
                    "note": "another object's id; a 200 with different body is the signal",
                })
        return requests

    if not is_probeable(kind):
        return []

    for payload in payloads_for(kind)[:5]:
        value = _fill(payload.value, port)
        if slot:
            candidate = path.replace("1", value, 1) if "1" in path else path + value
            requests.append({
                "label": payload.label,
                "path": candidate,
                "marker": payload.marker,
                "compare": payload.compare,
                "note": payload.note,
            })
        else:
            encoded = urllib.parse.quote(value, safe="")
            joiner = "&" if "?" in path else "?"
            requests.append({
                "label": payload.label,
                "path": f"{path}{joiner}{param}={encoded}",
                "marker": payload.marker,
                "compare": payload.compare,
                "note": payload.note,
            })
    return requests[:MAX_REQUESTS]


def _headers(cookie: str | None = None) -> dict[str, str]:
    headers = {"User-Agent": "ad-audit-probe/1.0"}
    if cookie:
        headers["Cookie"] = cookie
    return headers


def _fetch(opener, url: str, label: str = "probe", cookie: str | None = None) -> dict:
    started = time.time()
    request = urllib.request.Request(url, method="GET", headers=_headers(cookie))
    try:
        with opener.open(request, timeout=TIMEOUT) as response:
            body = response.read(MAX_BODY)
            status = response.status
            headers = dict(response.headers)
    except urllib.error.HTTPError as error:
        body = error.read(MAX_BODY) if error.fp else b""
        status = error.code
        headers = dict(error.headers or {})
    except Exception as error:  # noqa: BLE001 - surfaced as an error row
        JOURNAL.append({
            "at": round(started, 3), "url": url, "status": 0, "bytes": 0,
            "ms": int((time.time() - started) * 1000), "error": f"{type(error).__name__}",
            "label": label,
        })
        del JOURNAL[:-MAX_JOURNAL]
        return {"status": 0, "body": b"", "headers": {}, "ms": int((time.time() - started) * 1000),
                "error": f"{type(error).__name__}: {error}"}
    JOURNAL.append({
        "at": round(started, 3), "url": url, "status": status, "bytes": len(body),
        "ms": int((time.time() - started) * 1000), "error": None,
        "label": label,
    })
    del JOURNAL[:-MAX_JOURNAL]
    return {
        "status": status,
        "body": body,
        "headers": headers,
        "ms": int((time.time() - started) * 1000),
        "error": None,
    }


def auth_diff(base: str, path: str, opener, cookie: str | None = None,
              delay: float = DELAY) -> dict:
    """Один путь, два запроса: без сессии и с ней.

    Вопрос, на который отвечает пара: различает ли маршрут анонимного
    вызывающего и вошедшего. Если ответ дословно тот же — маршрут не смотрит
    на сессию, и это уже находка, без единой записи и без второго аккаунта.

    `cookie` необязателен: без него проверяется только «пускает ли без сессии»,
    с ним — «и отдаёт ли то же самое, что вошедшему».
    """
    row: dict = {"path": path, "anonymous": None, "authenticated": None,
                 "verdict": "unknown", "evidence": ""}

    anonymous = _fetch(opener, base + path, label="auth-anon")
    anon_body = anonymous.pop("body")
    anon_headers = anonymous.pop("headers")
    row["anonymous"] = {
        "status": anonymous["status"], "bytes": len(anon_body),
        "ms": anonymous["ms"], "sha": hashlib.sha256(anon_body).hexdigest()[:10],
        "error": anonymous["error"],
    }
    if anonymous["error"]:
        row["evidence"] = anonymous["error"]
        return row

    status = anonymous["status"]
    location = anon_headers.get("Location", "")
    text = anon_body.decode("utf-8", "replace")
    login_page = bool(LOGIN_MARKERS.search(text)) and len(anon_body) < 4096

    if 300 <= status < 400 and LOGIN_REDIRECT.search(location):
        row["verdict"] = "guarded"
        row["evidence"] = f"анонимного отправили на {location[:80]}"
        return row

    auth_body = None
    if cookie:
        time.sleep(delay)
        auth = _fetch(opener, base + path, label="auth-session", cookie=cookie)
        auth_body = auth.pop("body")
        row["authenticated"] = {
            "status": auth["status"], "bytes": len(auth_body),
            "ms": auth["ms"], "sha": hashlib.sha256(auth_body).hexdigest()[:10],
            "error": auth["error"],
        }

    same = auth_body is not None and hashlib.sha256(auth_body).hexdigest() == hashlib.sha256(anon_body).hexdigest()

    if status in (401, 403):
        row["verdict"] = "guarded"
        row["evidence"] = f"без сессии {status}"
    elif status == 200 and same:
        row["verdict"] = "open"
        row["evidence"] = f"200 и дословно тот же ответ, что с сессией ({len(anon_body)}Б)"
    elif status == 200 and login_page and not same:
        row["verdict"] = "guarded"
        row["evidence"] = "без сессии отдана страница входа"
    elif status == 200 and auth_body is None and not login_page and len(anon_body) >= 200:
        row["verdict"] = "open"
        row["evidence"] = f"200 без сессии, страницы входа нет ({len(anon_body)}Б)"
    elif status == 200:
        row["verdict"] = "unknown"
        row["evidence"] = "без сессии 200, но ответ похож на страницу входа или пуст"
    else:
        row["verdict"] = "guarded"
        row["evidence"] = f"без сессии {status}"

    if auth_body is None:
        row["note"] = "кука не задана: проверено только «пускает ли без сессии»"
    return row


def run(base: str, requests: list[dict], delay: float = DELAY,
        cookie: str | None = None, auth: bool = True) -> dict:
    """Execute the request list against one base URL."""
    base = (base or "").rstrip("/")
    if not base.startswith(("http://", "https://")):
        raise ProbeError("base must start with http:// or https://")
    if not requests:
        return {"base": base, "results": [], "summary": {"requests": 0, "signals": 0, "diffs": 0, "errors": 0}}

    delay = max(MIN_DELAY, float(delay))
    auth_requests = (1 + (1 if cookie else 0)) if auth else 0
    planned = min(len(requests), MAX_REQUESTS) + 1 + auth_requests  # +1 for the baseline request
    allowed, retry_after = BUDGET.take(planned)
    if not allowed:
        raise BudgetExhausted(retry_after)

    opener = _opener()
    results: list[dict] = []

    allowed = [item for item in requests[:MAX_REQUESTS] if not _blocked(item["path"])]
    if not allowed:
        return {
            "base": base,
            "endpoint": requests[0]["path"],
            "results": [{
                "label": item["label"], "path": item["path"], "status": 0, "ms": 0, "bytes": 0,
                "verdict": "blocked", "evidence": "path mentions the checker; not sent",
            } for item in requests[:MAX_REQUESTS]],
            "summary": {"requests": len(results), "signals": 0, "diffs": 0, "errors": 0,
                        "blocked": len(requests[:MAX_REQUESTS]), "verdict": "blocked"},
        }

    baseline = _fetch(opener, base + allowed[0]["path"])
    time.sleep(delay)

    auth_row = None
    if auth:
        auth_row = auth_diff(base, allowed[0]["path"], opener, cookie=cookie, delay=delay)
        time.sleep(delay)

    for item in requests[:MAX_REQUESTS]:
        path = item["path"]
        if _blocked(path):
            results.append({
                "label": item["label"], "path": path, "status": 0, "ms": 0, "bytes": 0,
                "verdict": "blocked", "evidence": "path mentions the checker; not sent",
            })
            continue
        response = _fetch(opener, base + path)
        body = response.pop("body")
        headers = response.pop("headers")
        text = body.decode("utf-8", "replace")
        haystack = text + "\n" + "\n".join(f"{key}: {value}" for key, value in headers.items())
        evidence = ""
        verdict = "clean"

        if response["error"]:
            verdict = "error"
            evidence = response["error"]
        else:
            marker = item.get("marker")
            if marker and re.search(marker, haystack) is not None:
                verdict = "signal"
                match = re.search(marker, haystack)
                evidence = f"matched {match.group(0)[:60]!r}"
            elif item.get("compare"):
                same_status = response["status"] == baseline["status"]
                delta = abs(len(body) - len(baseline["body"]))
                ratio = delta / max(1, len(baseline["body"]))
                if response["status"] == 200 and (not same_status or ratio > 0.2):
                    verdict = "diff"
                    evidence = f"baseline {baseline['status']}/{len(baseline['body'])}B vs {response['status']}/{len(body)}B"
                else:
                    evidence = "same shape as baseline"
            else:
                location = headers.get("Location", "")
                if location:
                    evidence = f"Location: {location[:80]}"
                else:
                    evidence = "marker absent"

        results.append({
            "label": item["label"],
            "path": path,
            "status": response["status"],
            "ms": response["ms"],
            "bytes": len(body),
            "sha": hashlib.sha256(body).hexdigest()[:10],
            "verdict": verdict,
            "evidence": evidence,
            "note": item.get("note", ""),
            "flag": (FLAG_RE.search(haystack).group(0)[:120] if FLAG_RE.search(haystack) else None),
        })
        time.sleep(delay)

    signals = sum(1 for row in results if row["verdict"] == "signal")
    diffs = sum(1 for row in results if row["verdict"] == "diff")
    errors = sum(1 for row in results if row["verdict"] == "error")
    blocked = sum(1 for row in results if row["verdict"] == "blocked")
    flags = [row["flag"] for row in results if row.get("flag")]
    return {
        "base": base,
        "endpoint": requests[0]["path"],
        "auth": auth_row,
        "results": results,
        "summary": {
            "requests": len(results) + (auth_requests if auth_row else 0),
            "signals": signals,
            "diffs": diffs,
            "errors": errors,
            "blocked": blocked,
            "flags": len(flags),
            "flag": flags[0] if flags else None,
            "auth": (auth_row or {}).get("verdict"),
            "verdict": "confirmed" if signals else ("candidate" if diffs else "no signal"),
        },
    }


def run_for(finding: dict, endpoint: str, base: str, port: int = 80,
            cookie: str | None = None) -> dict:
    """Build and execute in one call."""
    requests = build_requests(finding, endpoint, port)
    if not requests:
        return {
            "base": base,
            "endpoint": endpoint,
            "auth": None,
            "results": [],
            "summary": {"requests": 0, "signals": 0, "diffs": 0, "errors": 0, "blocked": 0,
                        "verdict": "manual"},
            "reason": "this kind cannot be tested with a single GET",
        }
    return run(base, requests, cookie=cookie)
