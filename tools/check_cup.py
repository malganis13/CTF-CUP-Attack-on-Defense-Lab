"""Прогон сканера по исходникам прошлых Кубков CTF (A/D).

Сканирует services/<имя> локально, без SSH, и сверяет находки с тем, что
авторы сервисов заложили (файл exploits/ в том же репозитории).

    python tools/check_cup.py D:/cup2019/2019-attack-defense
    python tools/check_cup.py <путь> --json out.json
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from adkit import patterns  # noqa: E402

# Что заложено авторами CUP 2019 (exploits/<сервис>/README.md).
EXPECTED = {
    "2019": {
        "medlink": {"Path traversal", "Weak session token"},
        "planner": {"SQL injection"},
        "qdb": {"Crypto: weak key", "Crypto: static IV", "Crypto: repeating-key XOR"},
    },
}

SKIP_DIRS = {"node_modules", ".git", "bin", "obj", "dist", "build", "__pycache__", ".idea"}


def collect(root: Path) -> dict[str, dict[str, list[dict]]]:
    """{сервис: {файл: находки}} по всем services/* репозитория."""
    services: dict[str, dict[str, list[dict]]] = {}
    for service in (root / "services").iterdir() if (root / "services").is_dir() else []:
        if not service.is_dir():
            continue
        found: dict[str, list[dict]] = {}
        for path in service.rglob("*"):
            if not path.is_file() or any(part in SKIP_DIRS for part in path.parts):
                continue
            if path.suffix.lower() not in {
                ".py", ".js", ".ts", ".mjs", ".cjs", ".php", ".rb", ".go", ".rs",
                ".java", ".kt", ".cs", ".c", ".h", ".cc", ".cpp", ".hpp", ".lua",
                ".fs", ".fsx", ".pas", ".dpr", ".lpr",
                ".json", ".toml", ".mod", ".xml", ".lock", ".txt", ".yml", ".yaml",
            }:
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            items = patterns.scan_text(str(path), text)
            if items:
                found[str(path.relative_to(root))] = items
        services[service.name] = found
    return services


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: python tools/check_cup.py <путь к репозиторию CUP>")
        return 2
    root = Path(sys.argv[1])
    if not (root / "services").is_dir():
        print(f"нет каталога services в {root}")
        return 2

    year = next((key for key in EXPECTED if key in root.name), "")
    expected = EXPECTED.get(year, {})
    services = collect(root)

    total = 0
    for service, files in sorted(services.items()):
        kinds = {item["kind"] for items in files.values() for item in items}
        count = sum(len(items) for items in files.values())
        total += count
        print(f"{service}: {count} находок, классы: {', '.join(sorted(kinds)) or '—'}")
        for path, items in sorted(files.items()):
            for item in items:
                print(f"    {item['rule']:<20} {item['file'] if 'file' in item else path}:{item['line']}")

    if expected:
        print("--- сверка с замыслом авторов")
        ok = True
        for service, kinds in expected.items():
            got = {item["kind"] for items in services.get(service, {}).values() for item in items}
            hit = sorted(kinds & got)
            miss = sorted(kinds - got)
            state = "покрыто" if not miss else "пропущено"
            print(f"  {service:<10} {state:<10} найдено: {', '.join(hit) or '—'}"
                  + (f"; нет: {', '.join(miss)}" if miss else ""))
            ok = ok and not miss
        print("итог:", "полное покрытие" if ok else "есть пропуски")
        return 0 if ok else 1

    print(f"всего находок: {total}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
