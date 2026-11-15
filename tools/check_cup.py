"""Прогон сканера по исходникам прошлых Кубков CTF (A/D).

Сканирует services/<имя> локально, без SSH, и сверяет находки с тем, что
авторы сервисов заложили (файл exploits/ в том же репозитории).

    python tools/check_cup.py D:/cup2019/2019-attack-defense
    python tools/check_cup.py <путь> --json out.json
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from adkit import flow, patterns  # noqa: E402

# Что заложено авторами CUP 2019 (exploits/<сервис>/README.md).
EXPECTED = {
    # Замысел авторов восстановлен по каталогу `sploits/` рядом с сервисами:
    # в нём лежит готовый эксплойт и его описание. Сверяемся не с догадкой, а
    # с тем, что сервис действительно должен был отдавать.
    "training-27-10-19": {
        "chocowrappers": {"Mass assignment"},
        "icecreams": {"Weak session token"},
        "rushmallow": {"Business logic: comparison oracle"},
        "kozipipe": {"SSRF"},
    },
    "2019-attack-defense": {
        "medlink": {"Path traversal", "Weak session token"},
        "planner": {"SQL injection"},
        "qdb": {"Crypto: weak key"},
    },
    "2018-attack-defense": {
        "black_exchange": {"IDOR / BOLA"},
        "arlington": {"Path traversal"},
        "vaultpass": {"Unsafe C string function"},
    },
    "ctfcup-2020-ad-finals": {
        "barker": {"Business logic: object owner", "Weak session token",
                   "Business logic: auto-approved relation"},
        "VaporService": {"Debug mode", "Business logic: dead branch"},
    },
    "ctfcup-2020-ad": {
        "ChessBase": {"Unsafe deserialization"},
        "QExecute": {"SSRF"},
        # cubic — криптографическая задача на умножение кубика Рубика:
        # проверяется руками, регуляркой не берётся.
        "cubic": set(),
    },
    "ctfcup21_battle": {
        "web": {"Hardcoded secret", "Debug mode"},
        "data-saver": {"Infrastructure: privileged container"},
    },
    "ctfcup24-school-ad": {
        "filtranator": {"SQL injection"},
        "flysim": {"NoSQL injection", "Unsafe dynamic call"},
    },
    "LetoCTF24-AD": {
        "crud": {"Auth: prefix compare", "Out of bounds", "Command injection"},
    },
    "ctfcup2025-ad": {
        "archive": {"Unsafe deserialization"},
        "warehouse": {"SSRF", "IDOR / BOLA"},
        "prototype": {"SQL injection"},
    },
    "GoCTF-2026-AD": {
        "starpost": {"Mass assignment", "SQL injection", "Business logic: balance update"},
        "lighthouse": {"Command injection"},
        "greenhouse": {"IDOR / BOLA"},
    },
    "letoctf26-ad": {
        "smc": {"Debug mode", "SQL injection"},
        "tuzemun": {"SQL injection"},
        "skychat": {"Command injection", "IDOR / BOLA"},
    },
}

SKIP_DIRS = {"node_modules", ".git", "bin", "obj", "dist", "build", "__pycache__", ".idea"}
NOT_SERVICES = {
    "services", "checkers", "sploits", "writeups", "scoreboard", "ansible",
    "terraform", "packer_images", "db_backup", "teams", "docs", ".github",
}


def service_dirs(root: Path) -> list[Path]:
    """Каталоги сервисов. Обычно `services/*`, но у 2021-го — сервисы в корне."""
    base = root / "services"
    if base.is_dir():
        return sorted(item for item in base.iterdir() if item.is_dir())
    return sorted(
        item for item in root.iterdir()
        if item.is_dir() and not item.name.startswith(".") and item.name.lower() not in NOT_SERVICES
    )


def collect(root: Path) -> dict[str, dict[str, list[dict]]]:
    """{сервис: {файл: находки}} по всем сервисам репозитория."""
    services: dict[str, dict[str, list[dict]]] = {}
    for service in service_dirs(root):
        if not service.is_dir():
            continue
        found: dict[str, list[dict]] = {}
        for path in service.rglob("*"):
            if not path.is_file() or any(part in SKIP_DIRS for part in path.parts):
                continue
            if path.suffix.lower() not in {
                ".py", ".js", ".ts", ".mjs", ".cjs", ".php", ".rb", ".go", ".rs",
                ".java", ".kt", ".cs", ".c", ".h", ".cc", ".cpp", ".hpp", ".lua",
                ".fs", ".fsx", ".pas", ".dpr", ".lpr",
                ".json", ".toml", ".mod", ".xml", ".lock", ".txt", ".yml", ".yaml",
                ".conf", ".service", ".sql", ".proto", ".graphql", ".tf", ".gradle",
                ".ini", ".env", ".sh",
            } and not path.name.lower().startswith(("dockerfile", "nginx")):
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            items = patterns.scan_text(str(path), text)
            if not patterns.is_generated(str(path), text.splitlines()):
                taken = {(item.get("line"), item.get("kind")) for item in items}
                for item in flow.analyze(str(path), text, patterns.language_of(str(path), text)):
                    if (item.get("line"), item.get("kind")) in taken:
                        continue
                    items.append(item)
            if items:
                found[str(path.relative_to(root))] = items
        services[service.name] = found
    return services


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: python tools/check_cup.py <путь к репозиторию CUP>")
        return 2
    root = Path(sys.argv[1])
    if not (root / "services").is_dir() and not service_dirs(root):
        print(f"нет ни services, ни сервисных каталогов в {root}")
        return 2

    year = next((key for key in sorted(EXPECTED, key=len, reverse=True) if key in root.name), "")
    expected = EXPECTED.get(year, {})
    services = collect(root)

    total = 0
    for service, files in sorted(services.items()):
        kinds = {item["kind"] for items in files.values() for item in items}
        count = sum(len(items) for items in files.values())
        total += count
        print(f"{service}: {count} находок, классы: {', '.join(sorted(kinds)) or '—'}")
        for path, items in sorted(files.items()):
            for item in items:
                print(f"    {item['rule']:<20} {item['file'] if 'file' in item else path}:{item['line']}")

    if expected:
        print("--- сверка с замыслом авторов")
        ok = True
        for service, kinds in expected.items():
            got = {item["kind"] for items in services.get(service, {}).values() for item in items}
            hit = sorted(kinds & got)
            miss = sorted(kinds - got)
            state = "покрыто" if not miss else "пропущено"
            print(f"  {service:<10} {state:<10} найдено: {', '.join(hit) or '—'}"
                  + (f"; нет: {', '.join(miss)}" if miss else ""))
            ok = ok and not miss
        print("итог:", "полное покрытие" if ok else "есть пропуски")
        return 0 if ok else 1

    print(f"всего находок: {total}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
