"""Находка плюс рецепт лечения → unified diff.

Лечение в `fixes.py` — это «как должно выглядеть». Здесь оно превращается в
строки, которые принимает `patch` или `git apply`: контекст берётся из того
же чтения файла, которым нашлась строка, поэтому номера совпадают с файлом
на машине, а не с пересказом.

Патч не применяется инструментом. Он скачивается, читается глазами и
накладывается человеком — аудит остаётся read-only, а решение остаётся за
тем, кто держит чекер.
"""
from __future__ import annotations


def _relative(path: str, root: str) -> str:
    if not path:
        return "unknown"
    normalised = path.replace("\\", "/")
    if root:
        prefix = root.replace("\\", "/").rstrip("/") + "/"
        if normalised.startswith(prefix):
            return normalised[len(prefix):]
    return normalised.lstrip("/")


def _hunk(finding: dict, after: list[str]) -> tuple[int, list[str], list[str], int] | None:
    """Старая версия участка, новая версия и смещение находки внутри него."""
    line = int(finding.get("line") or 0)
    snippet = (finding.get("snippet") or "").strip("\n")
    if not snippet:
        return None

    context = [str(item).rstrip("\r") for item in (finding.get("context") or [])]
    start = int(finding.get("context_start") or line or 1)
    index = line - start

    if not context or not (0 <= index < len(context)):
        # Контекст не пришёл или сместился: патч всё равно собирается, просто
        # с одной строкой вместо окна. Врать про номера нельзя.
        context = [snippet]
        start = line or 1
        index = 0

    old = list(context)
    new = old[:index] + after + old[index + 1:]
    if new == old:
        return None
    return start, old, new, index


def unified(finding: dict, fix: dict | None, root: str = "") -> str:
    """Собрать diff для одной находки. Пустая строка — если рецепта нет."""
    fix = fix or {}
    if fix.get("exact") is False:
        # Рецепт написан на другом языке. Патч из него не собирается:
        # применить такой diff — значит вставить python в go-файл.
        return ""
    after = [str(item).rstrip("\r\n") for item in (fix.get("after") or [])]
    if not after:
        return ""
    built = _hunk(finding, after)
    if built is None:
        return ""
    start, old, new, index = built

    path = _relative(finding.get("file") or "", root)
    lines = [
        f"diff --git a/{path} b/{path}",
        f"--- a/{path}",
        f"+++ b/{path}",
        f"@@ -{start},{len(old)} +{start},{len(new)} @@",
    ]

    for item in old[:index]:
        lines.append(" " + item)
    lines.append("-" + old[index])
    for item in after:
        lines.append("+" + item)
    for item in old[index + 1:]:
        lines.append(" " + item)
    return "\n".join(lines) + "\n"


def stamp(finding: dict) -> str:
    """Имя файла патча: правило и строка, из которой он вырос."""
    rule = (finding.get("rule") or "finding").replace("/", "-")
    return f"{rule}-{finding.get('line') or 0}"
