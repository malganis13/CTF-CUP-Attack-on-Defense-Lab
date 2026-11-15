"""Проверка уверенности: один и тот же вход — один и тот же ответ.

Три свойства, которые нужны на игре:
  1. уверенность детерминированная и не зависит от порядка вызовов;
  2. у каждой находки есть план проверки и список того, что её закроет;
  3. эвристика не называется «уверен», а прямой sink не называется «не уверен»
     без причины.
"""
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from adkit import confidence

FAILED = 0


def check(title: str, ok: bool, detail: str = "") -> None:
    global FAILED
    if not ok:
        FAILED += 1
    print(f"{'ok' if ok else 'FAIL':>4} {title}{(' — ' + detail) if detail else ''}")


def finding(**kwargs) -> dict:
    base = {
        "id": "x", "rule": "sql-fstring", "kind": "SQL injection",
        "severity": "high", "file": "/srv/app/db.py", "line": 41,
        "snippet": "cursor.execute(f\"SELECT * FROM notes WHERE id = {note_id}\")",
        "context": ['note_id = request.args.get("id")', "cursor.execute(...)"],
    }
    base.update(kwargs)
    return base


def main() -> int:
    sql = confidence.assess(finding())
    check("прямой sink с видимым входом — уверен", sql["level"] == "certain", sql["level"])
    check("уверенность числовая", 0 <= sql["score"] <= 100, str(sql["score"]))
    check("план не пустой", len(sql["plan"]) >= 3, str(len(sql["plan"])))
    check("есть чем закрыть", len(sql["disproof"]) >= 2, str(len(sql["disproof"])))

    idor = confidence.assess(finding(
        rule="idor-id-only", kind="IDOR / BOLA",
        snippet="WHERE id = ?", context=["rows = db.query(sql)"],
    ))
    check("эвристика не бывает «уверен»", idor["level"] in {"likely", "unsure"}, idor["level"])

    binary = confidence.assess(finding(
        rule="binary-shell-call", kind="Binary: shell call", binary=True, file="/srv/bin/app",
        snippet="импорт system", context=[],
    ))
    check("бинарь без исходников — не уверен", binary["level"] == "unsure", binary["level"])

    sanitized = confidence.assess(finding(
        rule="sql-fstring", snippet='q = secure_filename(request.args["q"])',
        context=['name = secure_filename(raw_name)', "open(os.path.join(root, name))"],
    ))
    check("проверка рядом снижает уверенность", sanitized["score"] < sql["score"],
          f"{sanitized['score']} < {sql['score']}")

    repeat = [confidence.assess(finding())["score"] for _ in range(5)]
    check("оценка детерминированная", len(set(repeat)) == 1, str(repeat))

    mixed = [finding(), finding(rule="idor-id-only", kind="IDOR / BOLA", snippet="WHERE id = ?")]
    summary = confidence.assess_many(mixed)
    check("assess_many заполняет находки", all(item.get("confidence") for item in mixed))
    check("сводка считает уровни", sum(summary["counts"].values()) == 2, str(summary["counts"]))

    plan_words = " ".join(sql["plan"]).lower()
    check("план про SQL говорит про кавычку", "%27" in plan_words or "1=1" in plan_words, plan_words[:80])

    total = 9
    print(f"\n{'пройдено' if FAILED == 0 else 'провалено'}: {total - FAILED}/{total}")
    return 0 if FAILED == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
