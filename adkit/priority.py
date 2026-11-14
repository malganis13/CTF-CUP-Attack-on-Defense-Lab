"""Порядок разбора находок.

На A/D очки теряются не на сложных дырах, а на тех, которые соседняя команда
щёлкает шаблонным скриптом в первом раунде. Поэтому находки сортируются не по
одной важности, а по цене закрытия и вероятности, что её уже пробуют:

1. шаблонная дыра (SQLi, traversal, cmd, eval, JWT без подписи) — её найдёт любой
   сканер, значит она первой и закрывается;
2. минутная правка раньше структурной;
3. важность;
4. файл и строка, чтобы разбор шёл сверху вниз по одному файлу.
"""
from __future__ import annotations

from . import ru

DEFAULT_EFFORT = 2

# 1 — одна строка, 2 — правка с пониманием контекста, 3 — структурная.
EFFORT = {
    "sql-fstring": 1,
    "sql-format": 1,
    "sql-exec-var": 2,
    "php-sql-request": 1,
    "php-sql-concat": 1,
    "js-sql-template": 1,
    "go-sql-sprintf": 1,
    "rust-sql-format": 1,
    "java-sql-concat": 1,
    "cs-sql-concat": 1,
    "rb-sql-interp": 1,
    "jwt-none": 1,
    "js-jwt-noverify": 1,
    "js-eval": 1,
    "php-eval": 1,
    "rb-eval": 1,
    "lua-loadstring": 1,
    "debug-on": 1,
    "open-redirect": 1,
    "autoescape-off": 1,
    "rust-unwrap-input": 1,
    "path-join": 2,
    "path-sink": 2,
    "js-path": 2,
    "go-path-sink": 2,
    "java-path": 2,
    "rust-path": 2,
    "cmd-shell": 2,
    "php-shell": 2,
    "js-exec-request": 2,
    "go-exec-user": 2,
    "rust-command-format": 2,
    "rust-command-user": 2,
    "rb-shell": 2,
    "cs-process": 2,
    "c-shell": 2,
    "c-unsafe-copy": 2,
    "c-memcpy-length": 2,
    "php-include": 2,
    "hardcoded-secret": 2,
    "xxe": 2,
    "flag-literal": 2,
    "idor-id-only": 2,
    "ssti": 3,
    "deserialization": 3,
    "php-unserialize": 3,
    "mass-assign": 3,
    "upload": 3,
    "php-upload": 3,
    "ssrf": 3,
    "js-xss": 2,
    "go-template-html": 2,
    "debug-path": 3,
    "checker-ref": 3,
    "lua-exec": 2,
}

# Дыры, под которые есть готовый публичный запрос: их пробуют в первом раунде.
TEMPLATE = {
    "sql-fstring",
    "sql-format",
    "sql-exec-var",
    "php-sql-request",
    "php-sql-concat",
    "js-sql-template",
    "go-sql-sprintf",
    "rust-sql-format",
    "java-sql-concat",
    "cs-sql-concat",
    "rb-sql-interp",
    "path-join",
    "path-sink",
    "js-path",
    "go-path-sink",
    "java-path",
    "rust-path",
    "cmd-shell",
    "php-shell",
    "js-exec-request",
    "go-exec-user",
    "rust-command-format",
    "rust-command-user",
    "rb-shell",
    "cs-process",
    "c-shell",
    "lua-exec",
    "php-eval",
    "js-eval",
    "rb-eval",
    "lua-loadstring",
    "php-include",
    "jwt-none",
    "js-jwt-noverify",
    "idor-id-only",
    "ssrf",
    "open-redirect",
    "upload",
    "php-upload",
    "deserialization",
    "php-unserialize",
}

SEVERITY_RANK = {"high": 0, "medium": 1, "low": 2, "info": 3}


def effort_of(rule: str) -> int:
    return EFFORT.get(rule, DEFAULT_EFFORT)


def is_template(rule: str) -> bool:
    return rule in TEMPLATE


def rank(finding: dict) -> int:
    """Меньше — раньше. Шаблонная и дешёвая находка идёт первой."""
    effort = effort_of(finding.get("rule", ""))
    templ = 0 if is_template(finding.get("rule", "")) else 1
    severity = SEVERITY_RANK.get(finding.get("severity", ""), 3)
    return templ * 100 + effort * 10 + severity


def enrich(finding: dict) -> dict:
    rule = finding.get("rule", "")
    effort = effort_of(rule)
    finding["effort"] = effort
    finding["effort_ru"] = ru.EFFORT_RU.get(effort, "")
    finding["template"] = is_template(rule)
    finding["rank"] = rank(finding)
    return finding


def sort_key(finding: dict) -> tuple:
    return (
        finding.get("rank", rank(finding)),
        finding.get("file", ""),
        finding.get("line", 0),
    )
