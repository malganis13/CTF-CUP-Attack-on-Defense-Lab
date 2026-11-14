#!/usr/bin/env python3
"""Тесты проб: доказывают, что детектор детектит.

Поднимает tools/lab_server.py на свободном порту, гоняет пробы по пяти
уязвимым ручкам и одной чистой, проверяет экспортированный скрипт как
отдельный процесс и проверяет оба режима линтера.

    python tools/test_probe.py
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

from adkit import generate, probe, ratelimit  # noqa: E402
from adkit.lint import lint_code  # noqa: E402
from adkit.payloads import PAYLOADS  # noqa: E402

import lab_server  # noqa: E402  (лежит рядом)

# Тесты не должны упираться в продуктовый бюджет; отдельная секция проверяет
# сам бюджет на маленьком значении.
probe.BUDGET = ratelimit.Budget(capacity=100_000, window=60.0)

failures: list[str] = []
checks = 0


def check(name: str, condition: bool, detail: str = "") -> None:
    global checks
    checks += 1
    if condition:
        print(f"  ok    {name}")
    else:
        print(f"  FAIL  {name} {detail}")
        failures.append(name)


def finding(kind: str, param: str, file: str = "/srv/app.py") -> dict:
    return {
        "id": kind.lower(),
        "kind": kind,
        "file": file,
        "line": 10,
        "severity": "high",
        "context": [f'value = request.args.get("{param}")'],
    }


def main() -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    server = lab_server.start(0)
    port = server.server_address[1]
    base = f"http://127.0.0.1:{port}"
    lab_server.HITS.clear()

    print("детект")
    cases = (
        ("SQL injection", "id", "/sqli"),
        ("Path traversal", "name", "/file"),
        ("Command injection", "host", "/ping"),
        ("Server-side template injection", "name", "/render"),
        ("Open redirect", "next", "/go"),
    )
    for kind, param, endpoint in cases:
        result = probe.run_for(finding(kind, param), endpoint, base, port)
        verdict = result["summary"]["verdict"]
        check(f"{kind}: сигнал", verdict == "confirmed", json.dumps(result["summary"], ensure_ascii=False))
        check(f"{kind}: запросов <= 14", result["summary"]["requests"] <= 14)

    print("ложные срабатывания")
    for kind, param, _ in cases:
        result = probe.run_for(finding(kind, param), "/clean", base, port)
        check(f"{kind} на чистой ручке молчит", result["summary"]["verdict"] == "no signal",
              json.dumps(result["summary"], ensure_ascii=False))

    print("защита")
    blocked = probe.run(base, [{"label": "checker", "path": "/_checker/putflag", "marker": None}])
    check("чекер заблокирован", blocked["results"][0]["verdict"] == "blocked")
    check("чекер не запрошен", not any("/_checker" in hit for hit in lab_server.HITS),
          str([hit for hit in lab_server.HITS if "/_checker" in hit]))

    print("нагрузка")
    limits = {kind: len(requests) for kind, requests in
              ((kind, probe.build_requests(finding(kind, "id"), "/x", port)) for kind in PAYLOADS)}
    check("ни один класс не превышает потолок", all(count <= probe.MAX_REQUESTS for count in limits.values()),
          str(limits))
    check("потолок запросов на пробу", probe.MAX_REQUESTS <= 14, str(probe.MAX_REQUESTS))

    lab_server.STAMPS.clear()
    paced = probe.run_for(finding("Path traversal", "name"), "/file", base, port)
    gaps = [round(b - a, 3) for a, b in zip(lab_server.STAMPS, lab_server.STAMPS[1:])]
    check("пауза между запросами", all(gap >= probe.MIN_DELAY * 0.8 for gap in gaps), str(gaps))
    check("запросов = базовый + пара авторизации + полезные нагрузки",
          len(lab_server.STAMPS) == len(paced["results"]) + 2,
          f"{len(lab_server.STAMPS)} на сервере, {len(paced['results'])} в отчёте")

    lab_server.STAMPS.clear()
    probe.run(base, [{"label": "a", "path": "/clean?q=1", "marker": None},
                     {"label": "b", "path": "/clean?q=2", "marker": None},
                     {"label": "c", "path": "/clean?q=3", "marker": None}], delay=0.0)
    gaps = [round(b - a, 3) for a, b in zip(lab_server.STAMPS, lab_server.STAMPS[1:])]
    check("нулевая пауза поднимается до минимума",
          all(gap >= probe.MIN_DELAY * 0.8 for gap in gaps), str(gaps))

    print("бюджет")
    probe.BUDGET = ratelimit.Budget(capacity=6, window=60.0)
    first, _ = probe.BUDGET.take(5)
    second, retry = probe.BUDGET.take(5)
    check("первая проба проходит", first is True)
    check("вторая отклонена", second is False, str(second))
    check("назван срок повтора", retry > 0, str(retry))
    refused = False
    try:
        probe.run_for(finding("SQL injection", "id"), "/sqli", base, port)
    except probe.BudgetExhausted:
        refused = True
    check("проба не начинается без бюджета", refused)
    probe.BUDGET = ratelimit.Budget(capacity=100_000, window=60.0)

    print("экспорт")
    export = generate.generate_probe(finding("SQL injection", "id"), "lab", "/sqli", port)
    check("проба не ручная", export["manual"] is False)
    check("линтер: чисто", export["lint"]["ok"] is True, str(export["lint"]["errors"])[:300])
    check("запросы в экспорте", len(export["requests"]) >= 3)

    with tempfile.TemporaryDirectory() as directory:
        script = Path(directory) / "probe.py"
        script.write_text(export["code"], encoding="utf-8")
        completed = subprocess.run(
            [sys.executable, str(script), "--base", base, "--json"],
            capture_output=True, text=True, timeout=60,
        )
        check("скрипт запускается", completed.returncode == 0, completed.stderr[-300:])
        rows = json.loads(completed.stdout) if completed.stdout.strip() else []
        check("скрипт нашёл сигнал", any(row["verdict"] == "signal" for row in rows), str(rows)[:300])
        check("скрипт не ходил в чекер", not any("/_checker" in row["path"] for row in rows))

    print("флаг")
    good = probe.FLAG_RE.search("note=CTF{8f3a1c9e2b} rest")
    check("метка флага распознаётся", bool(good), str(good))
    check("метка флага целиком", good is not None and good.group(0) == "CTF{8f3a1c9e2b}")
    check("чужая форма не метка", probe.FLAG_RE.search("BRACE{nope") is None)
    check("проба отдаёт поле флага", "flag" in result["results"][0], str(result["results"][0].keys()))

    print("заготовка")
    scaffold = generate.generate_probe(finding("Mass assignment", "role"), "lab", "/register", port)
    check("заготовка помечена ручной", scaffold["manual"] is True)
    check("заготовка проходит scaffold-линт", scaffold["lint"]["ok"] is True, str(scaffold["lint"]["errors"])[:300])
    check("в заготовке есть предупреждения", len(scaffold["lint"]["warnings"]) > 0)
    strict = lint_code(scaffold["code"], "probe")
    check("строгий линт режет заготовку", strict["ok"] is False, str(strict["errors"])[:200])

    jwt = generate.generate_probe(finding("JWT verification bypass", "token"), "lab", "/me", port)
    check("jwt-заготовка содержит alg none", "alg" in jwt["code"] and "none" in jwt["code"])
    check("jwt-заготовка проходит линт", jwt["lint"]["ok"] is True, str(jwt["lint"]["errors"])[:200])

    server.shutdown()

    print()
    if failures:
        print(f"{len(failures)} провалено из {checks}: {', '.join(failures)}")
        return 1
    print(f"{checks}/{checks} пройдено")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
