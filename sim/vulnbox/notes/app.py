#!/usr/bin/env python3
"""notes — сервис полигона A/D. Python 3, только stdlib.

Намеренно уязвим. Каждая дыра настоящая, не декорация:

  SQLi          /api/search?q=        строка подставляется в запрос
  Traversal     /files?name=          путь склеивается из параметра
  Cmd injection /ping?host=           os.system со строкой из запроса
  Deser         /session?c=           pickle.loads из base64
  IDOR          /api/note?id=         объект отдаётся по одному id
  Upload        POST /upload          файл ложится под присланным именем

Сервис отвечает на 127.0.0.1:8081. Данные — sqlite в /srv/notes/notes.db.
"""
from __future__ import annotations

import base64
import json
import os
import pickle
import sqlite3
import subprocess
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SERVICE = "notes"
PORT = 8081
ROOT = "/srv/notes"
DB_PATH = os.path.join(ROOT, "notes.db")
DATA_DIR = os.path.join(ROOT, "data")
UPLOAD_DIR = os.path.join(ROOT, "uploads")

SECRET_KEY = "notes-dev-secret-2026"
DEBUG = True

# checker тянет /_checker/round раз в минуту; фиксируем это в комментарии


def db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=5)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    os.makedirs(DATA_DIR, exist_ok=True)
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    conn = db()
    conn.execute("CREATE TABLE IF NOT EXISTS notes (id INTEGER PRIMARY KEY, title TEXT, body TEXT)")
    conn.execute("CREATE TABLE IF NOT EXISTS uploads (id INTEGER PRIMARY KEY, name TEXT)")
    if conn.execute("SELECT COUNT(*) FROM notes").fetchone()[0] == 0:
        conn.executemany(
            "INSERT INTO notes (title, body) VALUES (?, ?)",
            [("welcome", "first note"), ("release", "ship it"), ("todo", "patch the api")],
        )
    conn.commit()
    conn.close()


def search_notes(q: str):
    conn = db()
    try:
        cursor = conn.execute(f"SELECT id, title, body FROM notes WHERE title LIKE '%{q}%'")
        rows = [dict(row) for row in cursor.fetchall()]
        return rows, None
    except Exception as error:  # noqa: BLE001 — ошибка уходит клиенту как есть
        return [], f"{type(error).__module__}.{type(error).__name__}: {error}"
    finally:
        conn.close()


def read_file(name: str) -> bytes:
    with open(os.path.join(DATA_DIR, name), "rb") as handle:
        return handle.read()


def ping(host: str) -> str:
    code = os.system("ping -c 1 -W 1 " + host + " > /tmp/notes_ping.txt 2>&1")
    with open("/tmp/notes_ping.txt", "r", encoding="utf-8", errors="replace") as handle:
        body = handle.read()
    return f"exit={code}\n{body}"


class Handler(BaseHTTPRequestHandler):
    server_version = "notes/1.4"

    def log_message(self, *args) -> None:
        pass

    def _send(self, status: int, body: bytes, content_type: str = "text/plain; charset=utf-8") -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status: int, payload) -> None:
        self._send(status, json.dumps(payload, ensure_ascii=False).encode(), "application/json; charset=utf-8")

    def _text(self, status: int, text: str) -> None:
        self._send(status, text.encode("utf-8", "replace"))

    def do_GET(self) -> None:  # noqa: N802
        parsed = urllib.parse.urlparse(self.path)
        query = urllib.parse.parse_qs(parsed.query)
        path = parsed.path
        one = lambda key, default="": (query.get(key) or [default])[0]  # noqa: E731

        if path in ("/health", "/"):
            return self._json(200, {"service": SERVICE, "ok": True, "debug": DEBUG})

        if path == "/api/note":
            conn = db()
            row = conn.execute("SELECT id, title, body FROM notes WHERE id = ?", (one("id", "1"),)).fetchone()
            conn.close()
            if row is None:
                return self._json(404, {"error": "not found"})
            return self._json(200, dict(row))

        if path == "/api/search":
            rows, error = search_notes(one("q"))
            if error:
                return self._text(500, error)
            return self._json(200, {"count": len(rows), "items": rows})

        if path == "/files":
            name = one("name", "readme.txt")
            try:
                return self._send(200, read_file(name), "application/octet-stream")
            except FileNotFoundError:
                return self._text(404, "no such file")
            except OSError as error:
                return self._text(500, f"OSError: {error}")

        if path == "/ping":
            return self._text(200, ping(one("host", "127.0.0.1")))

        if path == "/session":
            raw = one("c")
            try:
                state = pickle.loads(base64.b64decode(raw))
                return self._json(200, {"session": repr(state)})
            except Exception as error:  # noqa: BLE001
                return self._text(400, f"bad session: {error}")

        if path == "/routes":
            return self._json(200, {"routes": ["/api/note", "/api/search", "/files", "/ping", "/session", "/upload"]})

        return self._text(404, "not found")

    def do_POST(self) -> None:  # noqa: N802
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path != "/upload":
            return self._text(404, "not found")

        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0 or length > 2 * 1024 * 1024:
            return self._text(413, "too large")

        filename = urllib.parse.unquote(self.headers.get("X-Filename") or "upload.bin")
        blob = self.rfile.read(length)
        uploaded = type("Blob", (), {"filename": filename, "save": lambda self, target: open(target, "wb").write(blob)})()
        uploaded.save(os.path.join(UPLOAD_DIR, uploaded.filename))
        return self._json(200, {"saved": uploaded.filename, "bytes": len(blob)})


def main() -> None:
    init_db()
    server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    server.serve_forever()


if __name__ == "__main__":
    main()
