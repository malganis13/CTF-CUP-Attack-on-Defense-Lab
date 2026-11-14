#!/usr/bin/env python3
"""Build demo/audit.json from demo/src.

The fixture tree is scanned with the same engine a live audit uses, so the demo
exercise every rule that the shipped scanner ships. Run it after editing the
fixtures or a rule:

    python tools/build_demo.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

from adkit.audit import analyze_sources  # noqa: E402

SRC = BASE / "demo" / "src"
OUT = BASE / "demo" / "audit.json"

SERVICES = [
    {
        "port": 8081,
        "proto": "tcp",
        "state": "LISTEN",
        "address": "0.0.0.0:8081",
        "process": "python3",
        "pid": 1412,
        "cwd": "/srv/notes",
        "cmdline": "/usr/bin/python3 /srv/notes/app.py",
        "service": "notes",
        "language": "python",
    },
    {
        "port": 8082,
        "proto": "tcp",
        "state": "LISTEN",
        "address": "0.0.0.0:8082",
        "process": "python3",
        "pid": 1418,
        "cwd": "/srv/files",
        "cmdline": "/usr/bin/python3 /srv/files/app.py",
        "service": "files",
        "language": "python",
    },
    {
        "port": 8083,
        "proto": "tcp",
        "state": "LISTEN",
        "address": "0.0.0.0:8083",
        "process": "python3",
        "pid": 1423,
        "cwd": "/srv/profile",
        "cmdline": "/usr/bin/python3 /srv/profile/app.py",
        "service": "profile",
        "language": "python",
    },
    {
        "port": 8084,
        "proto": "tcp",
        "state": "LISTEN",
        "address": "0.0.0.0:8084",
        "process": "gateway",
        "pid": 1451,
        "cwd": "/srv/gateway",
        "cmdline": "/srv/gateway/gateway",
        "service": "gateway",
        "language": "go",
    },
    {
        "port": 8085,
        "proto": "tcp",
        "state": "LISTEN",
        "address": "0.0.0.0:8085",
        "process": "php-fpm",
        "pid": 1467,
        "cwd": "/srv/portal",
        "cmdline": "php-fpm: pool www",
        "service": "portal",
        "language": "php",
    },
    {
        "port": 8086,
        "proto": "tcp",
        "state": "LISTEN",
        "address": "0.0.0.0:8086",
        "process": "node",
        "pid": 1489,
        "cwd": "/srv/api",
        "cmdline": "node /srv/api/server.js",
        "service": "api",
        "language": "javascript",
    },
    {
        "port": 8087,
        "proto": "tcp",
        "state": "LISTEN",
        "address": "0.0.0.0:8087",
        "process": "legacy",
        "pid": 1502,
        "cwd": "/srv/legacy",
        "cmdline": "/srv/legacy/legacy 8087",
        "service": "legacy",
        "language": "c",
    },
    {
        "port": 8088,
        "proto": "tcp",
        "state": "LISTEN",
        "address": "0.0.0.0:8088",
        "process": "ruby",
        "pid": 1518,
        "cwd": "/srv/lookup",
        "cmdline": "ruby /srv/lookup/app.rb",
        "service": "lookup",
        "language": "ruby",
    },
    {
        "port": 8089,
        "proto": "tcp",
        "state": "LISTEN",
        "address": "0.0.0.0:8089",
        "process": "rustapp",
        "pid": 1533,
        "cwd": "/srv/rustapp",
        "cmdline": "/srv/rustapp/rustapp",
        "service": "rustapp",
        "language": "rust",
    },
    {
        "port": 8090,
        "proto": "tcp",
        "state": "LISTEN",
        "address": "0.0.0.0:8090",
        "process": "java",
        "pid": 1544,
        "cwd": "/srv/billing",
        "cmdline": "java -jar /srv/billing/billing.jar",
        "service": "billing",
        "language": "java",
    },
    {
        "port": 8091,
        "proto": "tcp",
        "state": "LISTEN",
        "address": "0.0.0.0:8091",
        "process": "dotnet",
        "pid": 1556,
        "cwd": "/srv/support",
        "cmdline": "dotnet /srv/support/support.dll",
        "service": "support",
        "language": "csharp",
    },
    {
        "port": 8092,
        "proto": "tcp",
        "state": "LISTEN",
        "address": "0.0.0.0:8092",
        "process": "lua",
        "pid": 1568,
        "cwd": "/srv/luaapp",
        "cmdline": "lua /srv/luaapp/handler.lua",
        "service": "luaapp",
        "language": "lua",
    },
]

# Audit paths are the paths a target would show, not the fixture paths.
PREFIX = {}


def load_sources() -> dict[str, str]:
    sources: dict[str, str] = {}
    for file in sorted(SRC.rglob("*")):
        if not file.is_file():
            continue
        relative = file.relative_to(SRC)
        if "__pycache__" in relative.parts:
            continue
        sources[f"/srv/{relative.as_posix()}"] = file.read_text(encoding="utf-8", errors="replace")
    return sources


def main() -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    if not SRC.is_dir():
        print(f"missing fixture tree: {SRC}")
        return 1
    sources = load_sources()
    if not sources:
        print("no sources under demo/src")
        return 1
    audit = analyze_sources(sources, SERVICES, "demo@vulnbox:22 (fixture)")
    audit["os"] = ["Arch Linux", "Linux vulnbox 6.11.5-arch1-1 x86_64 GNU/Linux"]
    audit["meta"].update(
        {
            "duration_ms": 812,
            "roots": ["/srv/notes", "/srv/files", "/srv/profile"],
            "commands": ["fixture", "no ssh"],
            "findings_total": len(audit["findings"]),
            "demo": True,
        }
    )
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(audit, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    counts = audit["counts"]
    print(
        f"wrote {OUT.relative_to(BASE)}  files={len(audit['files'])} "
        f"endpoints={len(audit['endpoints'])} "
        f"findings={len(audit['findings'])} "
        f"(high {counts['high']}, medium {counts['medium']}, low {counts['low']}, info {counts['info']})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
