"""Осмотр собранных бинарников, когда исходников нет или их мало.

Читается только то, что бинарник сам о себе рассказывает: строки. Это не
дизассемблер — это ответ на вопрос «есть ли тут вызов оболочки, опасная
строковая функция и не лежит ли флаг в открытом виде».
"""
from __future__ import annotations

import re

from . import probe

ELF_COMMAND = (
    "for f in $(find {roots} -maxdepth 6 -type f -size -40M 2>/dev/null | head -800); do "
    "  [ \"$(head -c 4 \"$f\" 2>/dev/null | od -An -tx1 | tr -d ' \\n')\" = \"7f454c46\" ] && echo \"$f\"; "
    "done | head -{limit}"
)

# strings есть не везде (в голом kali binutils может не стоять): без него те же
# строки вытаскивает tr по печатному диапазону.
STRINGS_COMMAND = (
    "if command -v strings >/dev/null 2>&1; then strings -n 8 -- {path} 2>/dev/null; "
    "else tr -c '[:print:]' '\\n' < {path} 2>/dev/null | awk 'length($0) >= 5'; fi "
    "| head -c 300000"
)

SINK_PATTERNS = (
    (re.compile(r"^/bin/(?:sh|bash)$"), "Binary: shell path", "high",
     "В бинарнике есть путь к оболочке: вероятен вызов команды из данных запроса.",
     "Убрать оболочку; вызывать конкретный бинарник с массивом аргументов."),
    (re.compile(r"^(?:system|popen|execve|execl|execvp)$"), "Binary: shell call", "high",
     "Импорт или вызов запуска процесса: входные данные могут стать командой.",
     "Не передавать ввод в запуск процессов; сверять аргументы со списком."),
    (re.compile(r"^(?:strcpy|strcat|gets|sprintf)$"), "Binary: unsafe string", "medium",
     "Небезопасная строковая функция: переполнение буфера на длинном вводе.",
     "snprintf с размером буфера; strlcpy/strlcat где доступны."),
    (re.compile(r"^-----BEGIN [A-Z ]*PRIVATE KEY-----$"), "Hardcoded secret", "high",
     "В бинарнике лежит приватный ключ.",
     "Убрать ключ из сборки; читать из файла с правами 0600."),
)

INTERESTING = re.compile(r"^(?:%s|select .* from|/bin/(?:sh|bash))", re.I)


def scan_strings(text: str, path: str) -> list[dict]:
    """Строки бинарника → находки. Одна находка на класс, чтобы не заливать список."""
    found: list[dict] = []
    seen: set[str] = set()
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        for pattern, kind, severity, why, patch in SINK_PATTERNS:
            if kind in seen:
                continue
            if pattern.search(line):
                seen.add(kind)
                found.append({
                    "rule": "binary-" + kind.split(": ")[-1].replace(" ", "-"),
                    "kind": kind,
                    "severity": severity,
                    "file": path,
                    "line": 0,
                    "snippet": line[:200],
                    "context": [],
                    "why": why,
                    "patch": patch,
                    "checker_risk": "low",
                    "language": "binary",
                    "binary": True,
                })
        match = probe.FLAG_RE.search(line)
        if match and "Flag literal" not in seen:
            seen.add("Flag literal")
            found.append({
                "rule": "binary-flag",
                "kind": "Flag literal",
                "severity": "info",
                "file": path,
                "line": 0,
                "snippet": line[:200],
                "context": [],
                "why": "В бинарнике лежит строка, похожая на флаг.",
                "patch": "Флаг не должен попадать в сборку: он приходит из чекера.",
                "checker_risk": "low",
                "language": "binary",
                "binary": True,
            })
    return found
