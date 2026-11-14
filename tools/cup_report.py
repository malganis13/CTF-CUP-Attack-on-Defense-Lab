"""Сводка по нескольким репозиториям Кубков: сколько сервисов, находок, классов."""
from __future__ import annotations

import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from check_cup import collect  # noqa: E402


def main() -> int:
    roots = [Path(arg) for arg in sys.argv[1:]]
    if not roots:
        print("usage: python tools/cup_report.py <repo> [<repo> ...]")
        return 2
    for root in roots:
        services = collect(root)
        total = sum(len(items) for files in services.values() for items in files.values())
        empty = [name for name, files in services.items() if not any(files.values())]
        print(f"{root.name}: сервисов {len(services)}, находок {total}, пусто: {', '.join(empty) or '—'}")
        for name, files in sorted(services.items()):
            count = sum(len(items) for items in files.values())
            kinds = sorted({item["kind"] for items in files.values() for item in items})
            print(f"   {name:<22} {count:>3}  {', '.join(kinds) or '—'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
