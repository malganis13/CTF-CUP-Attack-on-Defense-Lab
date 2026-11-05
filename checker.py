#!/usr/bin/env python3
"""Small functional checker for local training instances.

This simulates checker's putflag -> later getflag workflow. Run it only against
lab URLs supplied on the command line.
"""
from __future__ import annotations
import argparse
import secrets
import string
import sys
import urllib.error
import urllib.request
import json


def request(base: str, path: str, method: str = "GET", body: dict | None = None, token: str = "", user: str = "guest") -> tuple[int, dict]:
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Content-Type": "application/json", "X-Checker-Token": token, "X-User": user}
    req = urllib.request.Request(base.rstrip("/") + path, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=3) as res:
            payload = res.read(16384)
            return res.status, json.loads(payload) if payload else {}
    except urllib.error.HTTPError as exc:
        payload = exc.read(16384)
        try: parsed = json.loads(payload) if payload else {}
        except ValueError: parsed = {}
        return exc.code, parsed


def random_flag() -> tuple[str, str]:
    alphabet = string.ascii_letters + string.digits
    flag = "TRAINING{" + "".join(secrets.choice(alphabet) for _ in range(24)) + "}"
    flag_id = "lab-" + secrets.token_hex(8)
    return flag_id, flag


def check_one(name: str, base: str, token: str, team_user: str) -> bool:
    flag_id, flag = random_flag()
    payload = {"flag_id": flag_id, "flag": flag}
    try:
        code, _ = request(base, "/health")
        if code != 200:
            raise RuntimeError(f"health returned {code}")
        code, stored = request(base, "/_checker/putflag", "POST", payload, token)
        if code != 200:
            raise RuntimeError(f"putflag returned {code}: {stored}")

        if name == "notes":
            code, listing = request(base, "/api/notes")
            if code != 200:
                raise RuntimeError(f"listing returned {code}")
            row = next((r for r in listing.get("notes", []) if r.get("title") == "checker-flag"), None)
            if row is None:
                raise RuntimeError("checker note not found")
            code, read = request(base, f"/api/notes/{row['id']}", user=team_user)
            if code != 200 or flag not in str(read.get("body", "")):
                raise RuntimeError(f"note readback failed: {read}")
        elif name == "workflow":
            code, listing = request(base, "/api/orders")
            if code != 200:
                raise RuntimeError(f"listing returned {code}")
            row = next((r for r in listing.get("orders", []) if r.get("item") == "checker-package"), None)
            if row is None:
                raise RuntimeError("checker order not found")
            code, _ = request(base, f"/_checker/pay/{row['id']}", "POST", {}, token=token)
            if code != 200:
                raise RuntimeError(f"checker pay returned {code}")
            code, read = request(base, f"/api/orders/{row['id']}/ship", "POST", {}, user=team_user)
            if code != 200 or read.get("delivery") != f"flag_id={flag_id};flag={flag}":
                raise RuntimeError(f"workflow readback failed: {read}")
        else:
            code, read = request(base, "/_checker/checkflag", "PUT", payload, token)
            if code != 200:
                raise RuntimeError(f"checkflag returned {code}: {read}")

        print(f"[{name}] UP: putflag → readback; flag_id={flag_id}")
        return True
    except Exception as exc:
        print(f"[{name}] FAIL: {exc}")
        return False


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--notes", default="http://127.0.0.1:18081")
    parser.add_argument("--workflow", default="http://127.0.0.1:18082")
    parser.add_argument("--search", default="http://127.0.0.1:18083")
    parser.add_argument("--token", required=True)
    parser.add_argument("--team-user", default="blue", help="owner identity for checker readback")
    args = parser.parse_args()
    ok = True
    for name, url in [("notes", args.notes), ("workflow", args.workflow), ("search", args.search)]:
        ok = check_one(name, url, args.token, args.team_user) and ok
    return 0 if ok else 1

if __name__ == "__main__":
    raise SystemExit(main())
