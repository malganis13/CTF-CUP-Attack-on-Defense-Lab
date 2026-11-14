#!/usr/bin/env python3
"""Проверка платформы: что есть, чего нет, что сломается при переносе.

    python tools/check_platform.py

Проверяет то, что реально ломалось при переносе между Windows и Arch:
право запуска у run.sh, переводы строк, наличие ssh, paramiko, версию Python.
"""
from __future__ import annotations

import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
problems: list[str] = []


def row(name: str, value: str, ok: bool = True) -> None:
    mark = "ok  " if ok else "ПЛОХО"
    print(f"  {mark} {name:<22} {value}")
    if not ok:
        problems.append(name)


def main() -> int:
    print("Система")
    row("os", f"{platform.system()} {platform.release()}")
    row("python", f"{platform.python_version()} ({sys.executable})",
        sys.version_info >= (3, 10))

    print("SSH")
    ssh = shutil.which("ssh")
    if ssh:
        try:
            version = subprocess.run([ssh, "-V"], capture_output=True, text=True, timeout=10)
            text = (version.stderr or version.stdout).strip().splitlines()[0]
        except Exception as error:  # noqa: BLE001
            text = f"{type(error).__name__}: {error}"
        row("ssh client", text)
    else:
        row("ssh client", "не найден в PATH", False)

    try:
        import paramiko  # noqa: F401
        row("paramiko", "есть (вход по паролю доступен)")
    except Exception:
        row("paramiko", "нет — только ключ/агент через системный ssh")

    print("Файлы")
    run_sh = BASE / "run.sh"
    run_ps1 = BASE / "run.ps1"
    for path in (run_sh, run_ps1):
        if not path.is_file():
            row(path.name, "отсутствует", False)
            continue
        data = path.read_bytes()
        crlf = data.count(b"\r\n")
        lf = data.count(b"\n")
        if path.name.endswith(".sh"):
            row("run.sh", f"LF {lf}, CRLF {crlf}", crlf == 0)
            if os.name != "nt":
                mode = path.stat().st_mode
                row("run.sh +x", oct(mode)[-3:], bool(mode & 0o111))
        else:
            row("run.ps1", f"LF {lf}, CRLF {crlf}")
            has_bom = data.startswith(b"\xef\xbb\xbf")
            row("run.ps1 BOM", "есть" if has_bom else "нет — PowerShell 5.1 сломает кириллицу", has_bom)

    if (BASE / ".git").is_dir():
        try:
            listing = subprocess.run(
                ["git", "ls-files", "-s", "run.sh"],
                cwd=BASE, capture_output=True, text=True, timeout=10,
            ).stdout.strip()
            mode = listing.split()[0] if listing else "?"
            row("git mode run.sh", mode, mode == "100755")
        except Exception as error:  # noqa: BLE001
            row("git mode run.sh", f"{type(error).__name__}", False)

    print("Данные")
    demo = BASE / "demo" / "audit.json"
    row("demo/audit.json", "есть" if demo.is_file() else "нет; python tools/build_demo.py",
        demo.is_file())
    knowledge = BASE / "knowledge"
    notes = len(list(knowledge.glob("*.md"))) if knowledge.is_dir() else 0
    row("knowledge/*.md", str(notes), notes > 0)

    print()
    if problems:
        print(f"проблем: {len(problems)} — {', '.join(problems)}")
        return 1
    print("проблем нет")
    return 0


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    raise SystemExit(main())
