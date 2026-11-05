#!/usr/bin/env python3
"""Local smoke tests for Go and Rust services when their toolchains exist."""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parent
TOKEN = "native-service-test-token"


def request(base: str, path: str, method: str = "GET", body: dict | None = None, token: str = "") -> tuple[int, dict]:
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Content-Type": "application/json", "X-Checker-Token": token}
    request = urllib.request.Request(base + path, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=2) as response:
            return response.status, json.loads(response.read() or b"{}")
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read() or b"{}")


def wait_health(base: str, process: subprocess.Popen) -> None:
    for _ in range(50):
        if process.poll() is not None:
            raise AssertionError(f"service exited with {process.returncode}")
        try:
            if request(base, "/health")[0] == 200:
                return
        except OSError:
            pass
        time.sleep(0.1)
    raise AssertionError("service did not start")


def run_go() -> None:
    if shutil.which("go") is None:
        print("SKIP go-files native test: Go toolchain is not installed")
        return
    with tempfile.TemporaryDirectory(prefix="adlab-go-") as data_dir:
        for patched in (False, True):
            env = os.environ.copy()
            env.update({"TEAM_ID": "blue", "CHECKER_TOKEN": TOKEN, "PATCHED": "1" if patched else "0", "PORT": "28084", "HOST": "127.0.0.1", "DATA_ROOT": data_dir})
            process = subprocess.Popen(["go", "run", "."], cwd=ROOT / "go-files", env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                base = "http://127.0.0.1:28084"
                wait_health(base, process)
                flag = {"flag_id": "go-test", "flag": "TRAINING{go-test}"}
                assert request(base, "/_checker/putflag", "POST", flag, TOKEN)[0] == 200
                code, result = request(base, "/api/files/download?name=../private/blue/flag.txt")
                assert code == (403 if patched else 200)
                if not patched:
                    assert flag["flag"] in result["contents"]
            finally:
                process.terminate()
                process.wait(timeout=3)


def run_rust() -> None:
    if shutil.which("cargo") is None:
        print("SKIP rust-profile native test: Cargo is not installed")
        return
    with tempfile.TemporaryDirectory(prefix="adlab-rust-") as data_dir:
        for patched in (False, True):
            env = os.environ.copy()
            env.update({"TEAM_ID": "blue", "CHECKER_TOKEN": TOKEN, "PATCHED": "1" if patched else "0", "PORT": "28085", "DATA_ROOT": data_dir})
            process = subprocess.Popen(["cargo", "run", "--quiet"], cwd=ROOT / "rust-profile", env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                base = "http://127.0.0.1:28085"
                wait_health(base, process)
                flag = {"flag_id": "rust-test", "flag": "TRAINING{rust-test}"}
                assert request(base, "/_checker/putflag", "POST", flag, TOKEN)[0] == 200
                assert request(base, "/api/profile", "PUT", {"role": "admin"})[0] == 200
                code, result = request(base, "/api/admin/secret")
                assert code == (403 if patched else 200)
                if not patched:
                    assert result["flag"] == flag["flag"]
            finally:
                process.terminate()
                process.wait(timeout=3)


if __name__ == "__main__":
    run_go()
    run_rust()
    print("Native service smoke tests completed")
