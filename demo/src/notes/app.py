#!/usr/bin/env python3
"""Notes service — demo fixture for the auditor.

Deliberately vulnerable. It is never imported or executed; the auditor reads
this file as text and the probe generator points at it.
"""
from __future__ import annotations

import os
import sqlite3

from flask import Flask, g, jsonify, render_template_string, request

API_KEY = "AKIAIOSFODNN7EXAMPLE"
FLAG_SAMPLE = "ctfcup{demo_flag_lives_in_this_table}"
DB_PATH = os.path.join(os.path.dirname(__file__), "notes.sqlite3")

app = Flask(__name__)


def db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


# The checker pushes flags through /_checker/notes/<flag_id>. Read only.
@app.get("/notes/<int:note_id>")
def note(note_id: int):
    row = db().execute(
        "SELECT title, body FROM notes WHERE id = ?", (note_id,)
    ).fetchone()
    if row is None:
        return jsonify(error="not found"), 404
    return jsonify(title=row["title"], body=row["body"])


@app.get("/search")
def search():
    term = request.args.get("q", "")
    query = f"SELECT id, title FROM notes WHERE title LIKE '%{term}%'"
    rows = db().execute(query).fetchall()
    return jsonify(rows=[dict(r) for r in rows])


@app.get("/raw")
def raw():
    term = request.args.get("q", "")
    rows = db().execute("SELECT id, title FROM notes WHERE title LIKE '%" + term + "%'").fetchall()
    return jsonify(rows=[dict(r) for r in rows])


@app.get("/preview")
def preview():
    name = request.args.get("name", "")
    os.system(f"convert -thumbnail 120x120 /srv/notes/{name} /tmp/preview.png")
    return jsonify(ok=True)


@app.get("/hello")
def hello():
    who = request.args.get("who", "guest")
    return render_template_string("<h1>Hello " + who + "</h1>")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8081, debug=True)
