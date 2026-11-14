"""Проверка оффлайн-входа через API: архив -> находки -> diff по находке."""
import io
import json
import sys
import time
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")

BASE = "http://127.0.0.1:8765"
ARCHIVE = Path(r"D:\ad-audit-dist\veladora.zip")
SOURCE = Path(r"D:\aciso\ctfcup2025-ad\services\veladora")


def call(path: str, body: dict | None = None) -> dict:
    data = json.dumps(body or {}).encode()
    request = urllib.request.Request(f"{BASE}{path}", data=data if body is not None else None,
                                     headers={"Content-Type": "application/json"},
                                     method="POST" if body is not None else "GET")
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.loads(response.read().decode())


def main() -> int:
    if not ARCHIVE.exists():
        with zipfile.ZipFile(ARCHIVE, "w", zipfile.ZIP_DEFLATED) as handle:
            for item in SOURCE.rglob("*"):
                if item.is_file():
                    handle.write(item, item.relative_to(SOURCE))
        print(f"архив собран: {ARCHIVE} ({ARCHIVE.stat().st_size // 1024} КБ)")

    started = call("/api/audit", {"path": str(ARCHIVE)})
    job = started["job"]
    for _ in range(60):
        time.sleep(0.5)
        state = call(f"/api/job?id={job}")
        if state.get("status") != "running":
            break
    result = state.get("result") or {}
    findings = result.get("findings") or []
    print(f"job: {state.get('status')} · находок {len(findings)} · файлов {len(result.get('files') or [])}")

    if not findings:
        print("FAIL: находок нет")
        return 1

    target = next((item for item in findings if item.get("line")), findings[0])
    detail = call(f"/api/fix?id={target['id']}")
    diff = detail.get("diff") or ""
    print(f"правило: {target['rule']} · строка {target['line']} · diff: {len(diff.splitlines())} строк")
    print((diff.splitlines() or ["<пусто>"])[0])

    ok = bool(diff) and diff.startswith("diff --git")
    print("ok" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
