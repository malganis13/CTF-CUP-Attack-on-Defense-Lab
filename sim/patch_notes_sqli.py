#!/usr/bin/env python3
"""Правит SQLi в notes и возвращает всё назад — доказательство «лечение не ломает сервис».

    python3 patch_notes_sqli.py apply
    python3 patch_notes_sqli.py restore
    python3 patch_notes_sqli.py check

Скрипт живёт в репозитории, чтобы правку можно было повторить на защите:
он показывает ровно тот диф, который печатает вкладка «Как закрыть».
"""
from __future__ import annotations

import pathlib
import sys

TARGET = pathlib.Path("/srv/notes/app.py")
BACKUP = pathlib.Path("/tmp/adlab-notes-app.py.bak")

OLD = '        cursor = conn.execute(f"SELECT id, title, body FROM notes WHERE title LIKE \'%{q}%\'")'
NEW = (
    '        cursor = conn.execute(\n'
    '            "SELECT id, title, body FROM notes WHERE title LIKE ?",\n'
    '            ("%" + q + "%",),\n'
    '        )'
)


def apply() -> int:
    text = TARGET.read_text(encoding="utf-8")
    if OLD not in text:
        print("уже пропатчено или строка изменилась — сверь файл вручную")
        return 1
    BACKUP.write_text(text, encoding="utf-8")
    TARGET.write_text(text.replace(OLD, NEW), encoding="utf-8")
    print("патч применён: склейка -> параметр")
    return 0


def restore() -> int:
    if not BACKUP.exists():
        print("бэкапа нет")
        return 1
    TARGET.write_text(BACKUP.read_text(encoding="utf-8"), encoding="utf-8")
    print("исходник восстановлен")
    return 0


def check() -> int:
    text = TARGET.read_text(encoding="utf-8")
    vulnerable = OLD in text
    print("sql-fstring в файле:", "есть" if vulnerable else "нет")
    return 0 if vulnerable else 2


if __name__ == "__main__":
    action = sys.argv[1] if len(sys.argv) > 1 else "check"
    sys.exit({"apply": apply, "restore": restore, "check": check}.get(action, check)())
