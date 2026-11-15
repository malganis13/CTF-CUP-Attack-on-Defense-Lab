"""Регрессия по корпусам Кубка 2019–2026.

Проверяет не «сколько нашлось», а «заложенное найдено»: для каждого сервиса
из `EXPECTED` в `check_cup.py` класс уязвимости должен присутствовать в
результате. Наборы пропусков печатаются построчно, чтобы новая правка правила
не осталась незамеченной.

    python tools/test_cup_years.py
    python tools/test_cup_years.py D:\\aciso D:\\cup2019

Корпуса, которых нет на диске, пропускаются: отсутствие чужого репозитория —
не провал теста.
"""
from __future__ import annotations

import sys
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))
sys.path.insert(0, str(BASE / "tools"))

from check_cup import EXPECTED, collect  # noqa: E402

DEFAULT_ROOTS = (
    Path(r"D:\cup2019\2018-attack-defense"),
    Path(r"D:\cup2019\training-27-10-19"),
    Path(r"D:\cup2019\2019-attack-defense"),
    Path(r"D:\aciso\ctfcup-2020-ad"),
    Path(r"D:\aciso\ctfcup-2020-ad-finals"),
    Path(r"D:\aciso\ctfcup21_battle"),
    Path(r"D:\aciso\ctfcup24-school-ad"),
    Path(r"D:\aciso\LetoCTF24-AD"),
    Path(r"D:\aciso\ctfcup2025-ad"),
    Path(r"D:\aciso\GoCTF-2026-AD"),
    Path(r"D:\aciso\letoctf26-ad"),
)

FAILED = 0


def check(title: str, ok: bool, detail: str = "") -> None:
    global FAILED
    if not ok:
        FAILED += 1
    print(f"{'ok' if ok else 'FAIL':>4} {title}{(' — ' + detail) if detail else ''}")


def expected_for(root: Path) -> dict[str, set[str]]:
    name = root.name
    key = next((item for item in sorted(EXPECTED, key=len, reverse=True) if item in name), "")
    return EXPECTED.get(key, {})


def main() -> int:
    roots = [Path(arg) for arg in sys.argv[1:]] or list(DEFAULT_ROOTS)
    seen = 0
    for root in roots:
        if not root.is_dir():
            print(f"skip {root} — нет каталога")
            continue
        expected = expected_for(root)
        if not expected:
            print(f"skip {root} — нет ожиданий в EXPECTED")
            continue
        seen += 1
        services = collect(root)
        missing: list[str] = []
        for service, kinds in expected.items():
            got = {item["kind"] for items in services.get(service, {}).values() for item in items}
            gap = sorted(kinds - got)
            if gap:
                missing.append(f"{service}: {', '.join(gap)}")
        total = sum(len(items) for files in services.values() for items in files.values())
        check(f"{root.name}: {len(services)} сервисов, {total} находок",
              not missing, "; ".join(missing))

    check("корпуса проверены", seen > 0, f"{seen}")
    print(f"\n{'пройдено' if FAILED == 0 else 'провалено'}: {seen - FAILED}/{seen} корпусов")
    return 0 if FAILED == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
