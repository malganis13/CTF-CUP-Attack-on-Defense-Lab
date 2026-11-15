"""Журнал находок: что было до патча, что после, что закрыли.

Это база, а не список в памяти. Каждый прогон аудита кладёт снимок находок;
одинаковые находки узнаются по отпечатку `правило + файл + текст строки`, а не
по номеру строки — патч сдвигает строки, но не меняет смысл.

Статусы:

- `open` — есть в последнем прогоне;
- `fixed` — была в прошлом и исчезла (закрыли или переписали код);
- `regressed` — была закрыта, а потом вернулась: патч откатили или он не тот;
- `ignored` — человек решил не трогать (публичный объект, ложное срабатывание).

SQLite, файл `state/journal.db`. Каталог переопределяется `AD_STATE_DIR`, как и
у остального состояния. БД нужна для ответа на вопрос «что мы исправили и что
ещё нет», поэтому она переживает перезапуск приложения.
"""
from __future__ import annotations

import hashlib
import re
import sqlite3
import threading
import time
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    at REAL NOT NULL,
    target TEXT,
    host TEXT,
    source TEXT,
    total INTEGER NOT NULL DEFAULT 0,
    high INTEGER NOT NULL DEFAULT 0,
    medium INTEGER NOT NULL DEFAULT 0,
    low INTEGER NOT NULL DEFAULT 0,
    unsure INTEGER NOT NULL DEFAULT 0,
    note TEXT
);
CREATE TABLE IF NOT EXISTS findings (
    fingerprint TEXT PRIMARY KEY,
    rule TEXT NOT NULL,
    kind TEXT,
    severity TEXT,
    confidence TEXT,
    file TEXT,
    line INTEGER,
    snippet TEXT,
    first_at REAL,
    last_at REAL,
    status TEXT NOT NULL DEFAULT 'open',
    note TEXT
);
CREATE TABLE IF NOT EXISTS run_findings (
    run_id INTEGER NOT NULL,
    fingerprint TEXT NOT NULL,
    PRIMARY KEY (run_id, fingerprint)
);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    at REAL NOT NULL,
    fingerprint TEXT NOT NULL,
    status TEXT NOT NULL,
    note TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_fp ON events(fingerprint);
"""

STATUSES = ("open", "fixed", "regressed", "ignored")
STATUS_RU = {
    "open": "открыта",
    "fixed": "закрыта",
    "regressed": "вернулась",
    "ignored": "игнор",
}


def _norm(text: str) -> str:
    return re.sub(r"\s+", " ", (text or "").strip())[:240]


def fingerprint(finding: dict) -> str:
    """Устойчивый идентификатор: правило + файл + смысл строки, без номера строки."""
    rule = str(finding.get("rule") or "")
    file = str(finding.get("file") or "").replace("\\", "/")
    snippet = _norm(str(finding.get("snippet") or ""))
    digest = hashlib.sha1(f"{rule}|{file}|{snippet}".encode("utf-8")).hexdigest()
    return digest[:20]


def _state_dir(base: Path | None) -> Path:
    import os

    override = (os.environ.get("AD_STATE_DIR") or "").strip()
    root = Path(override) if override else (Path(base) if base else Path.cwd()) / "state"
    root.mkdir(parents=True, exist_ok=True)
    return root


class Journal:
    def __init__(self, base: Path | None = None) -> None:
        self.path = _state_dir(base) / "journal.db"
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(str(self.path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.executescript(SCHEMA)
            self._conn.commit()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # --- запись -----------------------------------------------------------

    def record(self, audit: dict, note: str = "") -> dict:
        """Снимок аудита. Возвращает, что появилось, что закрылось, что вернулось."""
        findings = audit.get("findings") or []
        now = time.time()
        counts = {"high": 0, "medium": 0, "low": 0, "unsure": 0}
        for item in findings:
            severity = str(item.get("severity") or "")
            if severity in counts:
                counts[severity] += 1
            level = (item.get("confidence") or {}).get("level")
            if level == "unsure":
                counts["unsure"] += 1

        with self._lock:
            cursor = self._conn.cursor()
            cursor.execute(
                "INSERT INTO runs (at, target, host, source, total, high, medium, low, unsure, note)"
                " VALUES (?,?,?,?,?,?,?,?,?,?)",
                (now, audit.get("target") or audit.get("source") or "",
                 audit.get("host") or "", "offline" if audit.get("offline") else "ssh",
                 len(findings), counts["high"], counts["medium"], counts["low"],
                 counts["unsure"], note),
            )
            run_id = int(cursor.lastrowid)

            present: set[str] = set()
            known = {row["fingerprint"]: row for row in cursor.execute("SELECT * FROM findings")}
            new: list[str] = []
            regressed: list[str] = []

            for item in findings:
                mark = fingerprint(item)
                present.add(mark)
                level = (item.get("confidence") or {}).get("level") or ""
                row = known.get(mark)
                if row is None:
                    cursor.execute(
                        "INSERT INTO findings (fingerprint, rule, kind, severity, confidence,"
                        " file, line, snippet, first_at, last_at, status)"
                        " VALUES (?,?,?,?,?,?,?,?,?,?, 'open')",
                        (mark, item.get("rule") or "", item.get("kind") or "",
                         item.get("severity") or "", level, item.get("file") or "",
                         int(item.get("line") or 0), _norm(item.get("snippet") or ""),
                         now, now),
                    )
                    new.append(mark)
                    cursor.execute(
                        "INSERT INTO events (at, fingerprint, status, note) VALUES (?,?,?,?)",
                        (now, mark, "open", "находка появилась впервые"),
                    )
                else:
                    status = row["status"]
                    if status == "fixed":
                        status = "regressed"
                        regressed.append(mark)
                        cursor.execute(
                            "INSERT INTO events (at, fingerprint, status, note) VALUES (?,?,?,?)",
                            (now, mark, "regressed", "находка вернулась после закрытия"),
                        )
                    elif status == "ignored":
                        status = "ignored"
                    else:
                        status = "open"
                    cursor.execute(
                        "UPDATE findings SET last_at=?, line=?, severity=?, confidence=?, status=?"
                        " WHERE fingerprint=?",
                        (now, int(item.get("line") or 0), item.get("severity") or "",
                         level, status, mark),
                    )
                cursor.execute(
                    "INSERT INTO run_findings (run_id, fingerprint) VALUES (?,?)",
                    (run_id, mark),
                )

            closed: list[str] = []
            for mark, row in known.items():
                if mark in present:
                    continue
                if row["status"] in ("open", "regressed"):
                    cursor.execute("UPDATE findings SET status='fixed', last_at=? WHERE fingerprint=?",
                                   (now, mark))
                    cursor.execute(
                        "INSERT INTO events (at, fingerprint, status, note) VALUES (?,?,?,?)",
                        (now, mark, "fixed", "исчезла из следующего аудита"),
                    )
                    closed.append(mark)

            self._conn.commit()

        return {
            "run_id": run_id,
            "at": now,
            "total": len(findings),
            "new": len(new),
            "fixed": len(closed),
            "regressed": len(regressed),
            "unsure": counts["unsure"],
        }

    def set_status(self, mark: str, status: str, note: str = "") -> dict:
        if status not in STATUSES:
            raise ValueError(f"unknown status: {status}")
        now = time.time()
        with self._lock:
            cursor = self._conn.cursor()
            row = cursor.execute("SELECT fingerprint FROM findings WHERE fingerprint=?", (mark,)).fetchone()
            if row is None:
                return {"ok": False, "reason": "находка не найдена"}
            cursor.execute("UPDATE findings SET status=?, note=? WHERE fingerprint=?",
                           (status, note, mark))
            cursor.execute("INSERT INTO events (at, fingerprint, status, note) VALUES (?,?,?,?)",
                           (now, mark, status, note))
            self._conn.commit()
        return {"ok": True, "fingerprint": mark, "status": status, "status_ru": STATUS_RU[status]}

    # --- чтение -----------------------------------------------------------

    def runs(self, limit: int = 20) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM runs ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
            result = []
            for row in rows:
                closed = self._conn.execute(
                    "SELECT COUNT(*) AS n FROM events WHERE status='fixed' AND at>=? AND at<=?",
                    (row["at"] - 0.001, row["at"] + 0.001),
                ).fetchone()["n"]
                result.append({
                    "id": row["id"], "at": row["at"], "target": row["target"],
                    "host": row["host"], "source": row["source"], "total": row["total"],
                    "high": row["high"], "medium": row["medium"], "low": row["low"],
                    "unsure": row["unsure"], "note": row["note"],
                    "closed_in_run": closed,
                })
            return result

    def findings(self, status: str | None = None, limit: int = 500) -> list[dict]:
        with self._lock:
            if status:
                rows = self._conn.execute(
                    "SELECT * FROM findings WHERE status=? ORDER BY last_at DESC LIMIT ?",
                    (status, limit),
                ).fetchall()
            else:
                rows = self._conn.execute(
                    "SELECT * FROM findings ORDER BY last_at DESC LIMIT ?", (limit,)
                ).fetchall()
        return [dict(row) for row in rows]

    def summary(self) -> dict:
        with self._lock:
            rows = self._conn.execute(
                "SELECT status, COUNT(*) AS n FROM findings GROUP BY status"
            ).fetchall()
            by_status = {row["status"]: row["n"] for row in rows}
            runs = self._conn.execute("SELECT COUNT(*) AS n FROM runs").fetchone()["n"]
        total = sum(by_status.values())
        resolved = by_status.get("fixed", 0)
        return {
            "total": total,
            "by_status": by_status,
            "resolved": resolved,
            "open": by_status.get("open", 0) + by_status.get("regressed", 0),
            "ignored": by_status.get("ignored", 0),
            "runs": runs,
            "share_closed": round(100 * resolved / total) if total else 0,
        }

    def diff(self, before_id: int | None = None, after_id: int | None = None) -> dict:
        with self._lock:
            run_rows = self._conn.execute(
                "SELECT id, at, total FROM runs ORDER BY id DESC LIMIT 2"
            ).fetchall()
            if not run_rows:
                return {"available": False, "reason": "журнал пуст: нужен хотя бы один аудит"}
            if before_id is None or after_id is None:
                if len(run_rows) < 2:
                    return {"available": False, "reason": "нужен второй аудит, чтобы увидеть разницу"}
                after_id, before_id = run_rows[0]["id"], run_rows[1]["id"]

            def marks(run_id: int) -> set[str]:
                return {row["fingerprint"] for row in self._conn.execute(
                    "SELECT fingerprint FROM run_findings WHERE run_id=?", (run_id,))}

            def info(run_id: int) -> dict:
                row = self._conn.execute("SELECT id, at, total FROM runs WHERE id=?", (run_id,)).fetchone()
                return dict(row) if row else {"id": run_id, "at": 0, "total": 0}

            old, new = marks(int(before_id)), marks(int(after_id))
            details = {row["fingerprint"]: dict(row) for row in self._conn.execute("SELECT * FROM findings")}

        def brief(mark: str) -> dict:
            row = details.get(mark, {})
            return {
                "fingerprint": mark,
                "rule": row.get("rule"), "kind": row.get("kind"),
                "severity": row.get("severity"), "file": row.get("file"),
                "line": row.get("line"), "status": row.get("status"),
                "confidence": row.get("confidence"),
            }

        appeared = [brief(mark) for mark in sorted(new - old)]
        closed = [brief(mark) for mark in sorted(old - new)]
        return {
            "available": True,
            "before": info(int(before_id)),
            "after": info(int(after_id)),
            "appeared": appeared,
            "closed": closed,
            "persisting": len(old & new),
        }

    def events(self, limit: int = 100) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT e.*, f.rule, f.kind, f.file FROM events e"
                " LEFT JOIN findings f ON f.fingerprint = e.fingerprint"
                " ORDER BY e.id DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(row) for row in rows]
