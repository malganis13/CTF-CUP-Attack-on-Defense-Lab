#!/usr/bin/env python3
"""Profile service — demo fixture for the auditor.

Deliberately vulnerable. Text only; never executed.
"""
from __future__ import annotations

import pickle
import sqlite3

import jwt
import requests
from flask import Flask, jsonify, request

JWT_SECRET = "dev-secret-replace-me"
DB_PATH = "/srv/profile/profiles.sqlite3"

app = Flask(__name__)


@app.post("/register")
def register():
    payload = request.get_json(force=True, silent=True) or {}
    profile = {
        "name": payload.get("name", "anonymous"),
        "bio": payload.get("bio", ""),
        "role": payload.get("role", "user"),
    }
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "INSERT INTO profiles (name, bio, role) VALUES (?, ?, ?)",
        (profile["name"], profile["bio"], profile["role"]),
    )
    conn.commit()
    conn.close()
    return jsonify(ok=True, profile=profile)


@app.post("/import")
def import_profile():
    blob = request.get_data()
    profile = pickle.loads(blob)
    return jsonify(profile=profile)


@app.get("/me")
def me():
    token = request.headers.get("Authorization", "").removeprefix("Bearer ")
    claims = jwt.decode(token, JWT_SECRET, verify=False)
    return jsonify(claims=claims)


@app.get("/avatar")
def avatar():
    url = request.args.get("url", "http://127.0.0.1/static/avatar.png")
    response = requests.get(url, timeout=3)
    return jsonify(status=response.status_code, length=len(response.content))


@app.get("/profile/<int:profile_id>")
def profile(profile_id: int):
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute(
        "SELECT name, bio, role FROM profiles WHERE id = ?", (profile_id,)
    ).fetchone()
    conn.close()
    if row is None:
        return jsonify(error="not found"), 404
    return jsonify(name=row[0], bio=row[1], role=row[2])


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8083)
