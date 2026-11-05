#!/usr/bin/env python3
"""Three intentionally vulnerable, isolated A/D training services.

Never bind this lab to a public interface unless you have deliberately
firewalled it and understand the exposure. Defaults are loopback-only.
"""
from __future__ import annotations

import json
import os
import sqlite3
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

SERVICE = os.environ.get("SERVICE", "notes")
TEAM_ID = os.environ.get("TEAM_ID", "blue")
CHECKER_TOKEN = os.environ.get("CHECKER_TOKEN", "CHANGE-ME-LOCAL-ONLY")
PATCHED = os.environ.get("PATCHED", "0").lower() in {"1", "true", "yes", "on"}
PORT = int(os.environ.get("PORT", "8081"))
DB_PATH = Path(os.environ.get("DB_PATH", f"/data/{SERVICE}.sqlite3"))
DB_PATH.parent.mkdir(parents=True, exist_ok=True)


def connect() -> sqlite3.Connection:
    db = sqlite3.connect(DB_PATH, timeout=3)
    db.row_factory = sqlite3.Row
    return db


def init_db() -> None:
    with connect() as db:
        if SERVICE == "notes":
            db.execute("CREATE TABLE IF NOT EXISTS notes (id INTEGER PRIMARY KEY AUTOINCREMENT, owner TEXT NOT NULL, title TEXT NOT NULL, body TEXT NOT NULL)")
            if not db.execute("SELECT 1 FROM notes WHERE owner='alice' AND title='design-note'").fetchone():
                db.execute("INSERT INTO notes(owner,title,body) VALUES('alice','design-note','Training note: ordinary private content.')")
        elif SERVICE == "workflow":
            db.execute("CREATE TABLE IF NOT EXISTS orders (id INTEGER PRIMARY KEY AUTOINCREMENT, owner TEXT NOT NULL, item TEXT NOT NULL, paid INTEGER NOT NULL DEFAULT 0, shipped INTEGER NOT NULL DEFAULT 0, delivery TEXT NOT NULL)")
            if not db.execute("SELECT 1 FROM orders WHERE owner='alice' AND item='training-box'").fetchone():
                db.execute("INSERT INTO orders(owner,item,paid,shipped,delivery) VALUES('alice','training-box',0,0,'demo-delivery-code')")
        elif SERVICE == "search":
            db.execute("CREATE TABLE IF NOT EXISTS articles (title TEXT NOT NULL, body TEXT NOT NULL)")
            db.execute("CREATE TABLE IF NOT EXISTS flags (slot TEXT PRIMARY KEY, flag_id TEXT NOT NULL, flag TEXT NOT NULL)")
            if not db.execute("SELECT 1 FROM articles LIMIT 1").fetchone():
                db.execute("INSERT INTO articles VALUES('welcome','Search the training knowledge base.')")
        else:
            raise RuntimeError(f"Unknown SERVICE={SERVICE!r}")


init_db()


class Handler(BaseHTTPRequestHandler):
    server_version = "ADLab/1.0"

    def log_message(self, fmt: str, *args: object) -> None:
        print(f"[{SERVICE}/{TEAM_ID}] {self.address_string()} {fmt % args}")

    def send_json(self, status: int, body: object) -> None:
        payload = json.dumps(body, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(payload)

    def body_json(self) -> dict:
        try:
            length = min(int(self.headers.get("Content-Length", "0")), 8192)
            data = json.loads(self.rfile.read(length) or b"{}")
            return data if isinstance(data, dict) else {}
        except (ValueError, json.JSONDecodeError):
            return {}

    def user(self) -> str:
        # Deliberately simple training identity, not real authentication.
        return self.headers.get("X-User", "guest")[:64]

    def checker_ok(self) -> bool:
        return bool(CHECKER_TOKEN) and self.headers.get("X-Checker-Token", "") == CHECKER_TOKEN

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        if path == "/health":
            self.send_json(200, {"status": "ok", "service": SERVICE, "team": TEAM_ID, "patched": PATCHED})
            return
        if path == "/api/notes" and SERVICE == "notes":
            with connect() as db:
                rows = db.execute("SELECT id,title FROM notes ORDER BY id").fetchall()
            self.send_json(200, {"notes": [dict(r) for r in rows]})
            return
        if path.startswith("/api/notes/") and SERVICE == "notes":
            try:
                note_id = int(path.rsplit("/", 1)[1])
            except ValueError:
                self.send_json(400, {"error": "invalid id"}); return
            with connect() as db:
                if PATCHED:
                    row = db.execute("SELECT id,owner,title,body FROM notes WHERE id=? AND owner=?", (note_id, self.user())).fetchone()
                else:
                    # INTENTIONAL IDOR: object ID is checked but ownership is not.
                    row = db.execute("SELECT id,owner,title,body FROM notes WHERE id=?", (note_id,)).fetchone()
            if not row:
                self.send_json(404, {"error": "not found"}); return
            self.send_json(200, dict(row)); return
        if path == "/api/orders" and SERVICE == "workflow":
            with connect() as db:
                rows = db.execute("SELECT id,item,paid,shipped FROM orders ORDER BY id").fetchall()
            self.send_json(200, {"orders": [dict(r) for r in rows]}); return
        if path.startswith("/api/orders/") and SERVICE == "workflow":
            try:
                order_id = int(path.rsplit("/", 1)[1])
            except ValueError:
                self.send_json(400, {"error": "invalid id"}); return
            with connect() as db:
                row = db.execute("SELECT id,owner,item,paid,shipped,delivery FROM orders WHERE id=?", (order_id,)).fetchone()
            if not row:
                self.send_json(404, {"error": "not found"}); return
            result = dict(row)
            if result["owner"] != self.user() or not result["shipped"]:
                result.pop("delivery", None)
            self.send_json(200, result); return
        if path == "/api/search" and SERVICE == "search":
            q = parse_qs(parsed.query, keep_blank_values=True).get("q", [""])[0][:256]
            with connect() as db:
                if PATCHED:
                    rows = db.execute("SELECT title,body FROM articles WHERE title LIKE ?", (f"%{q}%",)).fetchall()
                else:
                    # INTENTIONAL SQL INJECTION: q is interpolated into SQL.
                    sql = f"SELECT title,body FROM articles WHERE title LIKE '%{q}%'"
                    try:
                        rows = db.execute(sql).fetchall()
                    except sqlite3.Error:
                        self.send_json(400, {"error": "query rejected"}); return
            self.send_json(200, {"results": [dict(r) for r in rows]}); return
        if path == "/" or path == "/api":
            self.send_json(200, {"service": SERVICE, "team": TEAM_ID, "patched": PATCHED,
                                 "message": "Isolated training target. See the lab README for the scope."}); return
        self.send_json(404, {"error": "not found"})

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        if path.startswith("/_checker/"):
            if not self.checker_ok():
                self.send_json(403, {"error": "checker authentication required"}); return
            if path.startswith("/_checker/pay/") and SERVICE == "workflow":
                order_id = path.rsplit("/", 1)[1]
                with connect() as db:
                    db.execute("UPDATE orders SET paid=1 WHERE id=? AND owner=? AND item='checker-package'", (order_id, TEAM_ID))
                self.send_json(200, {"status": "paid"}); return
            data = self.body_json()
            flag = str(data.get("flag", ""))[:256]
            flag_id = str(data.get("flag_id", ""))[:128]
            if not flag or not flag_id:
                self.send_json(400, {"error": "flag and flag_id required"}); return
            if SERVICE == "notes" and path == "/_checker/putflag":
                with connect() as db:
                    db.execute("DELETE FROM notes WHERE owner=? AND title='checker-flag'", (TEAM_ID,))
                    db.execute("INSERT INTO notes(owner,title,body) VALUES(?,?,?)", (TEAM_ID, "checker-flag", f"flag_id={flag_id};flag={flag}"))
                self.send_json(200, {"status": "stored"}); return
            if SERVICE == "workflow" and path == "/_checker/putflag":
                with connect() as db:
                    db.execute("DELETE FROM orders WHERE owner=? AND item='checker-package'", (TEAM_ID,))
                    db.execute("INSERT INTO orders(owner,item,paid,shipped,delivery) VALUES(?,?,0,0,?)", (TEAM_ID, "checker-package", f"flag_id={flag_id};flag={flag}"))
                self.send_json(200, {"status": "stored"}); return
            if SERVICE == "workflow" and path.startswith("/_checker/pay/"):
                order_id = path.rsplit("/", 1)[1]
                with connect() as db:
                    db.execute("UPDATE orders SET paid=1 WHERE id=? AND owner=? AND item='checker-package'", (order_id, TEAM_ID))
                self.send_json(200, {"status": "paid"}); return
            if SERVICE == "search" and path == "/_checker/putflag":
                with connect() as db:
                    db.execute("INSERT INTO flags(slot,flag_id,flag) VALUES('current',?,?) ON CONFLICT(slot) DO UPDATE SET flag_id=excluded.flag_id,flag=excluded.flag", (flag_id, flag))
                self.send_json(200, {"status": "stored"}); return
            self.send_json(404, {"error": "checker route not found"}); return
        if path.startswith("/api/orders/") and path.endswith("/ship") and SERVICE == "workflow":
            try:
                order_id = int(path.split("/")[3])
            except (ValueError, IndexError):
                self.send_json(400, {"error": "invalid id"}); return
            with connect() as db:
                order = db.execute("SELECT * FROM orders WHERE id=?", (order_id,)).fetchone()
                if not order:
                    self.send_json(404, {"error": "not found"}); return
                if PATCHED and order["owner"] != self.user():
                    self.send_json(403, {"error": "not your order"}); return
                if PATCHED and not order["paid"]:
                    self.send_json(409, {"error": "payment required"}); return
                # INTENTIONAL WORKFLOW BUG when unpatched: allows shipping before payment.
                db.execute("UPDATE orders SET shipped=1 WHERE id=?", (order_id,))
                updated = db.execute("SELECT delivery FROM orders WHERE id=?", (order_id,)).fetchone()
            self.send_json(200, {"status": "shipped", "delivery": updated["delivery"]}); return
        self.send_json(404, {"error": "not found"})

    def do_PUT(self) -> None:
        path = urlparse(self.path).path
        if path.startswith("/_checker/"):
            if not self.checker_ok():
                self.send_json(403, {"error": "checker authentication required"}); return
            data = self.body_json()
            flag = str(data.get("flag", ""))[:256]
            flag_id = str(data.get("flag_id", ""))[:128]
            if not flag or not flag_id:
                self.send_json(400, {"error": "flag and flag_id required"}); return
            with connect() as db:
                if SERVICE == "notes" and path.startswith("/_checker/notes/"):
                    note_id = path.rsplit("/", 1)[1]
                    db.execute("UPDATE notes SET body=? WHERE owner=? AND title='checker-flag' AND id=?", (f"flag_id={flag_id};flag={flag}", TEAM_ID, note_id))
                    self.send_json(200, {"status": "checked"}); return
                if SERVICE == "workflow" and path.startswith("/_checker/orders/"):
                    order_id = path.rsplit("/", 1)[1]
                    row = db.execute("SELECT delivery FROM orders WHERE id=? AND owner=? AND item='checker-package'", (order_id, TEAM_ID)).fetchone()
                    result = row is not None and row["delivery"] == f"flag_id={flag_id};flag={flag}"
                    self.send_json(200 if result else 409, {"status": "ok" if result else "corrupt"}); return
                if SERVICE == "search" and path == "/_checker/checkflag":
                    row = db.execute("SELECT flag_id,flag FROM flags WHERE slot='current'").fetchone()
                    result = row is not None and row["flag_id"] == flag_id and row["flag"] == flag
                    self.send_json(200 if result else 409, {"status": "ok" if result else "corrupt"}); return
            self.send_json(404, {"error": "checker route not found"}); return
        self.send_json(404, {"error": "not found"})


if __name__ == "__main__":
    host = os.environ.get("HOST", "127.0.0.1")
    print(f"Starting {SERVICE} for team {TEAM_ID} on {host}:{PORT}; patched={PATCHED}; db={DB_PATH}")
    ThreadingHTTPServer((host, PORT), Handler).serve_forever()
