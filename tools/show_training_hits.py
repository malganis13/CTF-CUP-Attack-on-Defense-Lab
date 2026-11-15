"""Что именно нашлось в корпусе training-27-10-19, по файлам и строкам."""
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from adkit import patterns

ROOT = Path(r"D:\cup2019\training-27-10-19\services")
SUFFIXES = {".cs", ".fs", ".pas", ".dpr", ".lpr", ".py", ".go", ".js", ".db", ".txt"}

for service in ("chocowrappers", "icecreams", "rushmallow", "kozipipe"):
    print(f"== {service}")
    for path in sorted((ROOT / service).rglob("*")):
        if not path.is_file() or any(part in {"bin", "obj", "Migrations"} for part in path.parts):
            continue
        if path.suffix.lower() not in SUFFIXES:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for finding in patterns.scan_text(str(path), text):
            print(f"   {finding['rule']:<22} line {finding['line']:<4} {finding['snippet'][:78]}")
