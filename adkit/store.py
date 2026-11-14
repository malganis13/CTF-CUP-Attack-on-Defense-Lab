"""Локальное состояние: история аудитов и журнал действий.

Всё, что инструмент помнит между запусками, лежит в одном каталоге:

- `history.jsonl` — по строке на аудит: время, счётчики, id находок. По ней
  работает «что изменилось после патча» даже после перезапуска.
- `ops.jsonl` — журнал действий: что и когда запускали. Это ответ на вопрос
  «когда я это правил» и материал для разбора спорного раунда.

Каталог переопределяется `AD_STATE_DIR` — тесты и упаковка не пишут в репозиторий.
Запись атомарная по строке: недописанная строка при чтении отбрасывается.
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path

MAX_HISTORY = 20
MAX_OPS = 500


def state_dir(base: Path | None = None) -> Path:
    override = (os.environ.get("AD_STATE_DIR") or "").strip()
    root = Path(override) if override else (Path(base) if base else Path.cwd()) / "state"
    root.mkdir(parents=True, exist_ok=True)
    return root


def _append(path: Path, payload: dict, cap: int) -> None:
    line = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    with path.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(line + "\n")
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return
    if len(lines) > cap:
        path.write_text("\n".join(lines[-cap:]) + "\n", encoding="utf-8", newline="\n")


def _read(path: Path) -> list[dict]:
    if not path.is_file():
        return []
    entries: list[dict] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except ValueError:
            # недописанная строка после аварийного выхода: она не история
            continue
        if isinstance(item, dict):
            entries.append(item)
    return entries


class Store:
    def __init__(self, base: Path | None = None) -> None:
        self.dir = state_dir(base)
        self.history_path = self.dir / "history.jsonl"
        self.ops_path = self.dir / "ops.jsonl"

    def remember_audit(self, audit: dict) -> dict:
        findings = {}
        for item in audit.get("findings") or []:
            if item.get("id"):
                findings[item["id"]] = {
                    "rule": item.get("rule"),
                    "kind": item.get("kind"),
                    "severity": item.get("severity"),
                    "file": item.get("file"),
                    "line": item.get("line"),
                }
        entry = {
            "at": time.time(),
            "host": audit.get("host"),
            "count": len(findings),
            "findings": findings,
            "services": len(audit.get("services") or []),
            "files": len(audit.get("files") or []),
        }
        _append(self.history_path, entry, MAX_HISTORY)
        return entry

    def history(self) -> list[dict]:
        return _read(self.history_path)[-MAX_HISTORY:]

    def log(self, event: str, **fields) -> None:
        payload = {"at": round(time.time(), 3), "event": event}
        payload.update({key: value for key, value in fields.items() if value is not None})
        _append(self.ops_path, payload, MAX_OPS)

    def ops(self, limit: int = 100) -> list[dict]:
        return _read(self.ops_path)[-max(1, min(limit, MAX_OPS)):]
