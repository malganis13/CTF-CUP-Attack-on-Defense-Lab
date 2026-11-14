#!/usr/bin/env python3
"""Files service — demo fixture for the auditor.

Deliberately vulnerable. Text only; never executed.
"""
from __future__ import annotations

import os

from flask import Flask, abort, redirect, request, send_file

UPLOAD_ROOT = "/srv/files/storage"
COOKIE_SECRET = "change-me-before-deploy"

app = Flask(__name__)


@app.get("/download")
def download():
    name = request.args.get("name", "readme.txt")
    path = os.path.join(UPLOAD_ROOT, name)
    return send_file(path)


@app.get("/view")
def view():
    name = request.args.get("name", "readme.txt")
    with open(os.path.join(UPLOAD_ROOT, name), "rb") as handle:
        return handle.read()


@app.get("/browse")
def browse():
    name = request.args.get("name", ".")
    entries = sorted(os.listdir(os.path.join(UPLOAD_ROOT, name)))
    return {"entries": entries}


@app.post("/upload")
def upload():
    handle = request.files.get("file")
    if handle is None:
        abort(400)
    handle.save(os.path.join(UPLOAD_ROOT, handle.filename))
    return {"ok": True}


@app.get("/go")
def go():
    return redirect(request.args.get("next", "/"))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8082)
