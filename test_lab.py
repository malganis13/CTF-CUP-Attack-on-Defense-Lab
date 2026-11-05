#!/usr/bin/env python3
"""Smoke/integration tests; launches only localhost lab processes."""
from __future__ import annotations
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parent
TOKEN = "integration-test-only-token"


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def request(base: str, path: str, method: str = "GET", data: dict | None = None, user: str = "guest", token: str = "") -> tuple[int, dict]:
    body = json.dumps(data).encode() if data is not None else None
    req = urllib.request.Request(base + path, data=body, method=method, headers={"Content-Type":"application/json", "X-User":user, "X-Checker-Token":token})
    try:
        with urllib.request.urlopen(req, timeout=2) as response:
            return response.status, json.loads(response.read() or b"{}")
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read() or b"{}")


def run_service(service: str, patched: bool, tests) -> None:
    port = free_port()
    with tempfile.TemporaryDirectory(prefix="adlab-test-") as directory:
        env = os.environ.copy()
        env.update({"SERVICE":service,"TEAM_ID":"blue","CHECKER_TOKEN":TOKEN,"PATCHED":"1" if patched else "0","PORT":str(port),"HOST":"127.0.0.1","DB_PATH":str(Path(directory)/f"{service}.sqlite3")})
        proc = subprocess.Popen([sys.executable,str(ROOT/"app.py")],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        base=f"http://127.0.0.1:{port}"
        try:
            for _ in range(40):
                if proc.poll() is not None: raise AssertionError(f"{service} exited with {proc.returncode}")
                try:
                    if request(base,"/health")[0]==200: break
                except Exception: pass
                time.sleep(0.1)
            else: raise AssertionError(f"{service} did not start")
            tests(base)
        finally:
            proc.terminate()
            try: proc.wait(timeout=3)
            except subprocess.TimeoutExpired: proc.kill(); proc.wait()


def notes_test(patched: bool) -> None:
    def tests(base: str) -> None:
        code, listing=request(base,"/api/notes")
        note_id=next(r["id"] for r in listing["notes"] if r["title"]=="design-note")
        code, _=request(base,f"/api/notes/{note_id}",user="mallory")
        assert code==(404 if patched else 200),f"IDOR expected patched={patched}, got {code}"
        flag={"flag_id":"unit-note","flag":"TRAINING{note-check}"}
        assert request(base,"/_checker/putflag","POST",flag,token=TOKEN)[0]==200
        code, listing=request(base,"/api/notes")
        row=next(r for r in listing["notes"] if r["title"]=="checker-flag")
        code, result=request(base,f"/_checker/notes/{row['id']}","PUT",flag,token=TOKEN)
        assert code==200
        code, value=request(base,f"/api/notes/{row['id']}",user="blue")
        assert code==200 and flag["flag"] in value["body"]
    run_service("notes",patched,tests)


def workflow_test(patched: bool) -> None:
    def tests(base: str) -> None:
        _, listing=request(base,"/api/orders")
        order_id=next(r["id"] for r in listing["orders"] if r["item"]=="training-box")
        code,_=request(base,f"/api/orders/{order_id}/ship","POST",{},user="alice")
        assert code==(409 if patched else 200),f"workflow expected patched={patched}, got {code}"
    run_service("workflow",patched,tests)


def search_test(patched: bool) -> None:
    def tests(base: str) -> None:
        flag={"flag_id":"unit-search","flag":"TRAINING{search-check}"}
        assert request(base,"/_checker/putflag","POST",flag,token=TOKEN)[0]==200
        query="%' UNION SELECT flag_id,flag FROM flags -- "
        encoded=urllib.parse.quote(query,safe="")
        code,result=request(base,"/api/search?q="+encoded)
        assert code==200
        rendered=json.dumps(result)
        leaked=flag["flag"] in rendered
        assert leaked is (not patched),f"SQLi expected patched={patched}, leaked={leaked}: {rendered}"
        code,result=request(base,"/_checker/checkflag","PUT",flag,token=TOKEN)
        assert code==200
    run_service("search",patched,tests)


if __name__ == "__main__":
    checks=0
    for service_test in (notes_test,workflow_test,search_test):
        for patched in (False,True):
            service_test(patched); checks+=1
            print(f"PASS {service_test.__name__} patched={patched}")
    print(f"All {checks} integration checks passed; only 127.0.0.1 was used.")
