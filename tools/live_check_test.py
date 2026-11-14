"""Живой прогон проверки живости: полигон, остановка сервиса, возврат.

    python tools/live_check_test.py

Требует поднятого приложения на 127.0.0.1:8765 и развёрнутого полигона.
"""
from __future__ import annotations

import json
import subprocess
import sys
import time
import urllib.request

BASE = "http://127.0.0.1:8765"


def call(path: str, payload: dict | None = None) -> dict:
    data = json.dumps(payload).encode() if payload is not None else None
    request = urllib.request.Request(BASE + path, data=data, method="POST" if data else "GET")
    if data:
        request.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(request, timeout=60) as response:
        return json.loads(response.read().decode("utf-8"))


def wsl(command: str) -> str:
    result = subprocess.run(
        ["wsl", "-d", "kali-linux", "-u", "root", "--", "bash", "-lc", command],
        capture_output=True, text=True, timeout=120,
    )
    return (result.stdout or "").strip()


def host() -> str:
    out = subprocess.run(
        ["wsl", "-d", "kali-linux", "--", "hostname", "-I"],
        capture_output=True, text=True, timeout=60,
    ).stdout.strip()
    return out.split()[0] if out else ""


def audit(ip: str) -> dict:
    call("/api/config", {"target": {
        "host": ip, "port": 2222, "user": "root", "auth": "key",
        "key_path": r"C:\Users\RYZEN_USER\Downloads\III_Exploit\ad-audit\sim\keys\ad_lab",
    }})
    started = call("/api/audit", {})
    for _ in range(240):
        time.sleep(0.4)
        job = call(f"/api/job?id={started['job']}")
        if job.get("status") != "running":
            return job
    raise SystemExit("audit timeout")


def main() -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

    ip = host()
    print(f"host: {ip}")
    job = audit(ip)
    print(f"audit: status={job.get('status')} findings={len((job.get('result') or {}).get('findings') or [])}")

    t0 = time.time()
    live = call("/api/liveness?force=1")
    print(f"liveness: {time.time() - t0:.2f}s summary={live.get('summary')} avg={live.get('avg_ms')}ms")
    for row in live.get("rows") or []:
        print(f"  {row['port']:<5} {row['service'][:10]:<10} {row['state']:<7} {row.get('ms')}ms  {row['note']}")

    print("stop ad-archive")
    print(" ", wsl("systemctl stop ad-archive; sleep 1; systemctl is-active ad-archive"))
    down = call("/api/liveness?force=1")
    row = next((item for item in down["rows"] if item["port"] == 8082), {})
    print(f"  8082: {row.get('state')} — {row.get('note')}  (down={down['summary'].get('down')})")

    print("start ad-archive")
    print(" ", wsl("systemctl start ad-archive; sleep 2; systemctl is-active ad-archive"))
    back = call("/api/liveness?force=1")
    row = next((item for item in back["rows"] if item["port"] == 8082), {})
    print(f"  8082: {row.get('state')} — {row.get('note')}")

    traffic = call("/api/traffic")
    print(f"traffic: total={traffic['summary']['total']} minute={traffic['summary']['last_minute']} "
          f"labels={sorted({event.get('label') for event in traffic['events']})}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
