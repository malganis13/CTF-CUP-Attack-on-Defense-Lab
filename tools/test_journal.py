"""Журнал: снимок аудита, закрытие, возврат, ручной статус, разница прогонов.

Проверяется на настоящей SQLite во временном каталоге: тот же код, что в
приложении, но без сервера и без цели.
"""
import os
import sys
import tempfile
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from adkit.journal import Journal, fingerprint

FAILED = 0


def check(title: str, ok: bool, detail: str = "") -> None:
    global FAILED
    if not ok:
        FAILED += 1
    print(f"{'ok' if ok else 'FAIL':>4} {title}{(' — ' + detail) if detail else ''}")


def make_audit(items: list[dict]) -> dict:
    return {
        "target": "10.0.0.5:22",
        "host": "10.0.0.5",
        "findings": items,
        "offline": True,
    }


def item(rule: str, file: str, line: int, snippet: str, severity: str = "high",
         conf: str = "likely") -> dict:
    return {
        "id": f"{rule}-{line}",
        "rule": rule,
        "kind": "SQL injection" if "sql" in rule else "IDOR / BOLA",
        "severity": severity,
        "file": file,
        "line": line,
        "snippet": snippet,
        "confidence": {"level": conf},
    }


def main() -> int:
    workdir = tempfile.mkdtemp(prefix="ad-journal-")
    os.environ["AD_STATE_DIR"] = workdir
    journal = Journal(Path(workdir))

    first = make_audit([
        item("sql-fstring", "/srv/app/db.py", 41, "cursor.execute(f\"SELECT {q}\")"),
        item("idor-id-only", "/srv/app/view.py", 12, "WHERE id = ?", "medium", "unsure"),
    ])
    result = journal.record(first)
    check("первый прогон записан", result["run_id"] == 1, str(result))
    check("две находки открыты", journal.summary()["open"] == 2, str(journal.summary()))
    check("новых две", result["new"] == 2, str(result["new"]))
    check("неуверенных одна", result["unsure"] == 1, str(result["unsure"]))

    # Патч по SQL: строка сдвинулась, текст тот же — находка должна считаться той же.
    second = make_audit([
        item("sql-fstring", "/srv/app/db.py", 47, "cursor.execute(f\"SELECT {q}\")"),
        item("idor-id-only", "/srv/app/view.py", 12, "WHERE id = ?", "medium", "unsure"),
    ])
    result = journal.record(second)
    check("сдвиг строки не создаёт новую находку", result["new"] == 0, str(result["new"]))
    check("по-прежнему две открыты", journal.summary()["open"] == 2, str(journal.summary()))

    # Патч закрыл SQL: находка исчезла из прогона.
    third = make_audit([
        item("idor-id-only", "/srv/app/view.py", 12, "WHERE id = ?", "medium", "unsure"),
    ])
    result = journal.record(third)
    check("исчезнувшая находка закрыта", result["fixed"] == 1, str(result["fixed"]))
    check("сводка считает закрытые", journal.summary()["resolved"] == 1, str(journal.summary()))

    # Патч откатили: находка вернулась.
    result = journal.record(make_audit([
        item("sql-fstring", "/srv/app/db.py", 41, "cursor.execute(f\"SELECT {q}\")"),
        item("idor-id-only", "/srv/app/view.py", 12, "WHERE id = ?", "medium", "unsure"),
    ]))
    check("возврат отмечен", result["regressed"] == 1, str(result["regressed"]))
    check("возврат виден в сводке", journal.summary()["by_status"].get("regressed") == 1,
          str(journal.summary()))

    diff = journal.diff()
    check("разница доступна", diff["available"], str(diff))
    check("в разнице есть появившееся", len(diff["appeared"]) == 1, str(diff["appeared"]))
    check("в разнице есть исчезнувшее", len(diff["closed"]) == 0, str(diff["closed"]))

    mark = fingerprint(item("idor-id-only", "/srv/app/view.py", 12, "WHERE id = ?"))
    answer = journal.set_status(mark, "ignored", "объект публичный по замыслу")
    check("ручной статус применяется", answer.get("ok"), str(answer))
    check("игнор в сводке", journal.summary()["ignored"] == 1, str(journal.summary()))

    bad = journal.set_status("нет-такого", "ignored")
    check("неизвестный отпечаток отвергнут", bad.get("ok") is False, str(bad))
    try:
        journal.set_status(mark, "не-статус")
        check("неизвестный статус отвергнут", False)
    except ValueError:
        check("неизвестный статус отвергнут", True)

    events = journal.events()
    check("события пишутся", len(events) >= 4, str(len(events)))
    check("отпечаток устойчив", mark == fingerprint(item("idor-id-only", "/srv/app/view.py", 99, "WHERE   id = ?")),
          "пробелы и номер строки не влияют")

    runs = journal.runs()
    check("прогоны перечислены", len(runs) == 4, str(len(runs)))
    journal.close()

    total = 18
    print(f"\n{'пройдено' if FAILED == 0 else 'провалено'}: {total - FAILED}/{total}")
    return 0 if FAILED == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
