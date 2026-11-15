"""Стенд: модель, импорт из аудита, привязка находок, сохранение.

Проверки идут на настоящем каталоге состояния во временном каталоге: тот же
код, что в приложении, но без сервера и без цели.
"""
import os
import sys
import tempfile
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from adkit import topology

FAILED = 0


def check(title: str, ok: bool, detail: str = "") -> None:
    global FAILED
    if not ok:
        FAILED += 1
    print(f"{'ok' if ok else 'FAIL':>4} {title}{(' — ' + detail) if detail else ''}")


def audit() -> dict:
    return {
        "host": "10.0.0.5",
        "services": [
            {"port": 8081, "service": "python3", "language": "python", "root": "/srv/notes"},
            {"port": 8082, "service": "node", "language": "node", "root": "/srv/archive"},
            {"port": 8083, "service": "php", "language": "php", "root": "/srv/warehouse"},
        ],
        "findings": [
            {"id": "a1", "rule": "py-sql-concat", "kind": "SQL injection",
             "severity": "high", "file": "/srv/notes/app.py", "line": 41,
             "snippet": "SELECT ...", "confidence": {"level": "certain", "level_ru": "уверен"},
             "status": "open"},
            {"id": "a2", "rule": "path-join", "kind": "Path traversal",
             "severity": "medium", "file": "/srv/notes/files.py", "line": 12,
             "snippet": "open(...)", "confidence": {"level": "likely", "level_ru": "скорее да"},
             "status": "open"},
            {"id": "a3", "rule": "idor-id-only", "kind": "IDOR / BOLA",
             "severity": "medium", "file": "/srv/archive/api.js", "line": 7,
             "snippet": "WHERE id = ?", "confidence": {"level": "unsure", "level_ru": "не уверен"},
             "status": "fixed"},
            {"id": "a4", "rule": "dep-cve", "kind": "Уязвимая зависимость",
             "severity": "low", "file": "/opt/misc/package.json", "line": 3,
             "snippet": "lodash", "confidence": {"level": "unsure", "level_ru": "не уверен"},
             "status": "open"},
        ],
    }


def main() -> int:
    workdir = tempfile.mkdtemp(prefix="ad-topology-")
    os.environ["AD_STATE_DIR"] = workdir

    model = topology.empty_model()
    check("пустая модель — один сервер и ноль сервисов",
          model["services"] == [] and model["server"]["name"], str(model["server"]))
    check("раунд по умолчанию 5 минут", model["round_minutes"] == 5)

    many = {"teams_total": 99999, "round_minutes": 0, "members": ["a", "A", " ", "b"],
            "services": [{"name": f"s{i}", "port": i} for i in range(40)]}
    clean, notes = topology.normalise(many)
    check("команд не больше предела", clean["teams_total"] == topology.MAX_TEAMS, str(clean["teams_total"]))
    check("раунд не обнуляется", clean["round_minutes"] >= 1, str(clean["round_minutes"]))
    check("состав без дублей и пустых", clean["members"] == ["a", "b"], str(clean["members"]))
    check("сервисов не больше предела", len(clean["services"]) == topology.MAX_SERVICES,
          str(len(clean["services"])))
    check("о пределах сказано в замечаниях", any("сервисов" in note for note in notes), str(notes))

    bad_port, _ = topology.normalise({"services": [{"name": "x", "port": "не порт"}]})
    check("кривой порт не ломает модель", bad_port["services"][0]["port"] == 0,
          str(bad_port["services"][0]["port"]))

    board = {
        "event": "X Кубок CTF России",
        "team": "наша",
        "teams_total": 10,
        "members": ["23:59", "второй"],
        "services": [{"name": "мое имя", "port": 8081, "notes": "ручная заметка"}],
    }
    clean, _ = topology.normalise(board)
    saved = topology.save(clean)
    check("сохранение вернуло время", saved["updated_at"] > 0)
    loaded = topology.load()
    check("чтение после записи", loaded["team"] == "наша", loaded["team"])
    check("ручная заметка пережила запись",
          loaded["services"][0]["notes"] == "ручная заметка", loaded["services"][0]["notes"])
    check("файл лежит в state/", (Path(workdir) / "topology.json").is_file())

    merged, info = topology.merge_audit(loaded, audit())
    check("импорт добавил два сервиса", info["added"] == 2, str(info))
    check("совпадение по порту не дублируется", len(merged["services"]) == 3,
          str([s["name"] for s in merged["services"]]))
    check("ручное имя сохранено", merged["services"][0]["name"] == "мое имя",
          merged["services"][0]["name"])
    check("язык подтянут из аудита", merged["services"][0]["language"] == "python",
          merged["services"][0]["language"])
    check("каталог подтянут из аудита", merged["services"][0]["cwd"] == "/srv/notes",
          merged["services"][0]["cwd"])
    check("хост сервера из аудита", merged["server"]["host"] == "10.0.0.5", merged["server"]["host"])

    again, info2 = topology.merge_audit(merged, audit())
    check("повторный импорт ничего не добавляет", info2["added"] == 0 and len(again["services"]) == 3,
          str(info2))

    liveness = {"rows": [{"port": 8081, "state": "up"}, {"port": 8082, "state": "down"}]}
    view = topology.build_view(merged, audit(), liveness)
    by_port = {service["port"]: service for service in view["services"]}
    notes_svc = by_port[8081]
    check("находки привязались по каталогу", len(notes_svc["findings"]) == 2,
          str(len(notes_svc["findings"])))
    check("высокая посчитана", notes_svc["counts"]["high"] == 1, str(notes_svc["counts"]))
    check("худшая важность — high", notes_svc["worst"] == "high", notes_svc["worst"])
    check("риск по важности", notes_svc["risk"] == 14, str(notes_svc["risk"]))
    check("живость подтянута", notes_svc["health"] == "up", notes_svc["health"])
    check("лежащий сервис виден", by_port[8082]["health"] == "down", by_port[8082]["health"])
    check("неуверенных считает", by_port[8082]["confidence"]["unsure"] == 1,
          str(by_port[8082]["confidence"]))
    check("чужая находка осталась вне сервисов", len(view["loose"]) == 1, str(len(view["loose"])))
    check("сводка сходится по числу",
          view["summary"]["findings"] == 4, str(view["summary"]))
    check("сводка считает открытые",
          view["summary"]["open"] == 3, str(view["summary"]["open"]))
    check("поле и раунд на месте",
          view["field"]["teams_total"] == 10 and view["round"]["minutes"] == 5,
          str(view["field"]))
    check("сервер отдан отдельно", view["server"]["host"] == "10.0.0.5", str(view["server"]))

    empty_view = topology.build_view(topology.empty_model(), audit(), None)
    check("без сервисов все находки вне стенда", len(empty_view["loose"]) == 4,
          str(len(empty_view["loose"])))
    check("пустой стенд не падает", empty_view["summary"]["services"] == 0)

    check("id сервиса устойчив",
          topology.service_id("notes", 8081) == topology.service_id(" Notes ", 8081),
          topology.service_id("notes", 8081))

    total = 34
    print(f"\n{'пройдено' if FAILED == 0 else 'провалено'}: {total - FAILED}/{total}")
    return 0 if FAILED == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
