#!/usr/bin/env python3
"""checker — чекер полигона A/D.

Раз в раунд кладёт по флагу в каждый сервис и проверяет, что сервис отдаёт
флаг через свою легальную ручку. Пишет scoreboard и status.json.

  python3 checker.py --interval 45
  python3 checker.py --once

Флаги лежат в /srv/_checker/flags.json. Аудит эту директорию не читает и
пробы в неё не ходят — это проверяется отдельно.
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import sqlite3
import time
import urllib.error
import urllib.request

CHECKER_DIR = "/srv/_checker"
FLAGS_PATH = os.path.join(CHECKER_DIR, "flags.json")
STATUS_PATH = os.path.join(CHECKER_DIR, "status.json")
SCOREBOARD = os.path.join(CHECKER_DIR, "scoreboard.log")

NOTES_DB = "/srv/notes/notes.db"
ARCHIVE_ROOT = "/srv/archive"
ARCHIVE_DATA = os.path.join(ARCHIVE_ROOT, "data")
ARCHIVE_INDEX = os.path.join(ARCHIVE_ROOT, "index.json")
WAREHOUSE_DB = "/srv/warehouse/warehouse.db"

ENDPOINTS = {
    "notes": "http://127.0.0.1:8081/api/note?id={id}",
    "archive": "http://127.0.0.1:8082/api/file?name={id}",
    "warehouse": "http://127.0.0.1:8083/api/item?id={id}",
}


def flag(service: str, round_no: int) -> str:
    return f"ctfcup{{{service}_r{round_no}_{secrets.token_hex(6)}}}"


def http_get(url: str, timeout: float = 3.0) -> tuple[int, str]:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:  # noqa: S310 — адрес локальный и фиксированный
            return response.status, response.read(64 * 1024).decode("utf-8", "replace")
    except urllib.error.HTTPError as error:
        return error.code, error.read(4096).decode("utf-8", "replace")
    except Exception as error:  # noqa: BLE001
        return 0, f"{type(error).__name__}: {error}"


def plant_notes(value: str) -> str:
    conn = sqlite3.connect(NOTES_DB, timeout=5)
    cursor = conn.execute("INSERT INTO notes (title, body) VALUES (?, ?)", ("round", value))
    conn.commit()
    row_id = cursor.lastrowid
    conn.close()
    return str(row_id)


def plant_archive(value: str) -> str:
    name = f"round-{secrets.token_hex(4)}.txt"
    os.makedirs(ARCHIVE_DATA, exist_ok=True)
    with open(os.path.join(ARCHIVE_DATA, name), "w", encoding="utf-8") as handle:
        handle.write(value + "\n")
    index = {"files": []}
    if os.path.exists(ARCHIVE_INDEX):
        with open(ARCHIVE_INDEX, "r", encoding="utf-8") as handle:
            index = json.load(handle)
    index.setdefault("files", []).append({"id": len(index["files"]) + 1, "title": name, "name": name})
    with open(ARCHIVE_INDEX, "w", encoding="utf-8") as handle:
        json.dump(index, handle, indent=2)
    return name


def plant_warehouse(value: str) -> str:
    conn = sqlite3.connect(WAREHOUSE_DB, timeout=5)
    cursor = conn.execute("INSERT INTO items (name, price) VALUES (?, ?)", (value, 0))
    conn.commit()
    row_id = cursor.lastrowid
    conn.close()
    return str(row_id)


PLANT = {"notes": plant_notes, "archive": plant_archive, "warehouse": plant_warehouse}


def load_state() -> dict:
    if os.path.exists(FLAGS_PATH):
        try:
            with open(FLAGS_PATH, "r", encoding="utf-8") as handle:
                return json.load(handle)
        except Exception:  # noqa: BLE001
            pass
    return {"round": 0, "plants": []}


def save_state(state: dict) -> None:
    os.makedirs(CHECKER_DIR, exist_ok=True)
    with open(FLAGS_PATH, "w", encoding="utf-8") as handle:
        json.dump(state, handle, indent=2)


def check_once(service: str, handle_id: str) -> tuple[bool, str, float]:
    """Один заход в сервис. Возвращает (ok, note, ms)."""
    started = time.monotonic()
    status, body = http_get(ENDPOINTS[service].format(id=handle_id))
    ok = status == 200 and body_has_flag(body)
    note = "flag returned" if ok else f"planted={handle_id} status={status} body={body[:120]}"
    return ok, note, round((time.monotonic() - started) * 1000, 1)


def body_has_flag(body: str) -> bool:
    return "ctfcup{" in body


def run_round(state: dict) -> dict:
    state["round"] += 1
    round_no = state["round"]
    results = {}
    for service, plant in PLANT.items():
        started = time.monotonic()
        try:
            handle_id = plant(value := flag(service, round_no))
            ok, note, _ = check_once(service, handle_id)
            if not ok:
                # Перезапуск сервиса в AD — обычное дело. Один повтор, как у
                # настоящего чекера: раунд не должен падать из-за рестарта.
                time.sleep(0.3)
                retried_ok, retried_note, _ = check_once(service, handle_id)
                ok = retried_ok
                note = retried_note if retried_ok else f"{note}; retry: {retried_note}"
            if ok and value not in note:
                note = "flag returned"
        except Exception as error:  # noqa: BLE001
            ok = False
            note = f"{type(error).__name__}: {error}"
        results[service] = {
            "ok": ok,
            "ms": round((time.monotonic() - started) * 1000, 1),
            "note": note,
        }

    state["plants"].append({"round": round_no, "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "results": results})
    state["plants"] = state["plants"][-200:]
    save_state(state)

    line = f"round={round_no} " + " ".join(
        f"{service}={'OK' if data['ok'] else 'FAIL'}({data['ms']}ms)" for service, data in results.items()
    )
    with open(SCOREBOARD, "a", encoding="utf-8") as handle:
        handle.write(line + "\n")

    status = {
        "round": round_no,
        "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "services": results,
        "up": sum(1 for data in results.values() if data["ok"]),
        "total": len(results),
    }
    with open(STATUS_PATH, "w", encoding="utf-8") as handle:
        json.dump(status, handle, indent=2)

    print(line, flush=True)
    return status


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--interval", type=int, default=45)
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()

    os.makedirs(CHECKER_DIR, exist_ok=True)
    state = load_state()
    while True:
        try:
            run_round(state)
        except Exception as error:  # noqa: BLE001
            print(f"checker error: {type(error).__name__}: {error}", flush=True)
        if args.once:
            return
        time.sleep(max(5, args.interval))


if __name__ == "__main__":
    main()
