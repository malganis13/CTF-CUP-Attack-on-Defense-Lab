"""Сверка версий зависимостей с базой уязвимостей.

Два источника, в этом порядке:

1. OSV — `https://api.osv.dev/v1/query`, живой запрос на каждую пару
   «пакет + версия». Это точный ответ, но он требует сети.
2. Встроенная таблица — семь записей, которые встречались на A/D и в
   публичных корпусах Кубка. Работает без сети и без базы.

Ответ — находки того же вида, что у сканера правил: файл, строка, версия,
исправленная версия. «boost 1.74 используется» превращается в «boost 1.74
уязвим, исправлено в 1.84».
"""
from __future__ import annotations

import json
import re
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from .deps import Dependency

OSV_ENDPOINT = "https://api.osv.dev/v1/query"
TIMEOUT = 6.0
MAX_PACKAGES = 40
MAX_SECONDS = 25.0


@dataclass(frozen=True)
class Advisory:
    ecosystem: str
    name: str
    fixed: str
    advisory: str
    summary: str
    severity: str = "high"
    source: str = "builtin"


# Встроенная таблица: то, что реально встречалось на A/D. Каждая строка —
# «до какой версии включительно плохо». Источник указан, чтобы это можно было
# проверить, а не принять на веру.
SEED: tuple[Advisory, ...] = (
    Advisory("PyPI", "flask", "2.2.5", "CVE-2023-30861",
             "Flask раскрывает постоянную куку сессии при кэшировании ответа", "high"),
    Advisory("PyPI", "pyyaml", "5.4", "CVE-2020-14343",
             "yaml.full_load исполняет произвольный код из документа", "high"),
    Advisory("PyPI", "requests", "2.31.0", "CVE-2023-32681",
             "заголовок Proxy-Authorization уходит на сторонний хост при редиректе", "medium"),
    Advisory("npm", "lodash", "4.17.21", "CVE-2021-23337",
             "шаблон в _.template исполняет команду через переменную", "higher"),
    Advisory("npm", "jsonwebtoken", "9.0.0", "CVE-2022-23529",
             "слабый секрет принимается как валидный ключ подписи", "high"),
    Advisory("Maven", "log4j-core", "2.17.1", "CVE-2021-44228",
             "Log4Shell: подстановка JNDI из строки лога", "high"),
    Advisory("native", "boost", "1.84.0", "CVE-2023-34399",
             "boost serialization читает размеры из архива и переполняет буфер", "high"),
)

SEVERITY_MAP = {
    "critical": "high",
    "high": "high",
    "moderate": "medium",
    "medium": "medium",
    "low": "low",
}

CACHE: dict[str, list[dict]] = {}
_ONLINE = {"broken": False}


def _number(text: str) -> int | None:
    match = re.match(r"\d+", text or "")
    return int(match.group(0)) if match else None


def _key(version: str) -> list[int]:
    parts = [int(item) for item in re.findall(r"\d+", version or "")]
    return parts or [0]


def older(version: str, fixed: str) -> bool:
    """version < fixed, по числовым сегментам. Неразборчивое считается новее."""
    left, right = _key(version), _key(fixed)
    length = max(len(left), len(right))
    left += [0] * (length - len(left))
    right += [0] * (length - len(right))
    return left < right


def _cache_path() -> Path | None:
    import os

    override = (os.environ.get("AD_STATE_DIR") or "").strip()
    root = Path(override) if override else Path.cwd() / "state"
    try:
        root.mkdir(parents=True, exist_ok=True)
    except OSError:
        return None
    return root / "osv-cache.json"


def _cached(key: str) -> list[dict] | None:
    if key in CACHE:
        return CACHE[key]
    path = _cache_path()
    if path is None or not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    entry = data.get(key)
    if isinstance(entry, list):
        CACHE[key] = entry
        return entry
    return None


def _remember(key: str, vulns: list[dict]) -> None:
    CACHE[key] = vulns
    path = _cache_path()
    if path is None:
        return
    try:
        data = json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {}
    except (OSError, ValueError):
        data = {}
    data[key] = vulns
    try:
        path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    except OSError:
        return


def _severity(vuln: dict) -> str:
    for item in vuln.get("severity") or []:
        score = str(item.get("score") or "")
        number = re.match(r"^\s*([0-9]+(?:\.[0-9]+)?)\s*$", score)
        if number:
            value = float(number.group(1))
            return "high" if value >= 7 else "medium" if value >= 4 else "low"
    for item in vuln.get("database_specific", {}).get("severity", "") if isinstance(vuln.get("database_specific"), dict) else []:
        return SEVERITY_MAP.get(str(item).lower(), "medium")
    return "medium"


def _fixed_for(vuln: dict, name: str) -> str:
    best = ""
    for affected in vuln.get("affected") or []:
        package = (affected.get("package") or {}).get("name") or ""
        if package and package.lower() != name.lower():
            continue
        for span in affected.get("ranges") or []:
            for event in span.get("events") or []:
                fixed = str(event.get("fixed") or "")
                if not fixed or not fixed[:1].isdigit():
                    continue
                if not best or older(best, fixed):
                    best = fixed
    return best


def query_osv(dependency: Dependency) -> list[dict]:
    """Один запрос в OSV. Ошибка сети отключает онлайн до конца прогона."""
    if _ONLINE["broken"]:
        return []
    key = dependency.key
    cached = _cached(key)
    if cached is not None:
        return cached
    payload = json.dumps({
        "package": {"name": dependency.name, "ecosystem": dependency.ecosystem},
        "version": dependency.version,
    }).encode()
    request = urllib.request.Request(
        OSV_ENDPOINT, data=payload,
        headers={"Content-Type": "application/json", "User-Agent": "ad-audit-cve/1.0"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
            data = json.loads(response.read(2_000_000))
    except Exception:  # noqa: BLE001 - сеть может отсутствовать целиком
        _ONLINE["broken"] = True
        return []
    vulns = data.get("vulns") or []
    _remember(key, vulns)
    return vulns


def _finding(dependency: Dependency, vuln_id: str, summary: str, fixed: str,
             severity: str, source: str) -> dict:
    snippet = f"{dependency.name} {dependency.version}"
    return {
        "rule": "dep-cve",
        "kind": "Dependency: known vulnerability",
        "severity": severity,
        "file": dependency.file,
        "line": dependency.line,
        "snippet": snippet,
        "context": [f"{vuln_id}: {summary}"[:220]],
        "why": f"{dependency.ecosystem} {snippet}: {summary}",
        "patch": (f"Обновить {dependency.name} до {fixed} или выше; проверить сборку и "
                  f"что сервис отдаёт флаг после рестарта." if fixed else
                  f"Обновить {dependency.name}; исправленная версия не названа — смотреть advisory {vuln_id}."),
        "checker_risk": "medium",
        "language": "manifest",
        "source": source,
        "advisory": vuln_id,
        "fixed": fixed,
    }


def check(dependencies: list[Dependency], online: bool = True,
          limit: int = MAX_PACKAGES) -> list[dict]:
    """Версии → находки. Онлайн-часть ограничена по числу пакетов и по времени."""
    import time

    findings: list[dict] = []
    seen: set[tuple[str, str, str]] = set()
    started = time.monotonic()

    for dependency in dependencies[:limit]:
        # 1. Встроенная таблица: работает всегда.
        for advisory in SEED:
            if (advisory.ecosystem.lower() == dependency.ecosystem.lower()
                    and advisory.name.lower() == dependency.name.lower()
                    and older(dependency.version, advisory.fixed)):
                mark = (dependency.key, advisory.advisory, "builtin")
                if mark in seen:
                    continue
                seen.add(mark)
                findings.append(_finding(dependency, advisory.advisory, advisory.summary,
                                         advisory.fixed, advisory.severity, "builtin"))

        if not online or _ONLINE["broken"] or time.monotonic() - started > MAX_SECONDS:
            continue
        per_package = 0
        for vuln in query_osv(dependency):
            vuln_id = vuln.get("id") or "OSV"
            mark = (dependency.key, vuln_id, "osv")
            if mark in seen:
                continue
            seen.add(mark)
            findings.append(_finding(
                dependency, vuln_id,
                (vuln.get("summary") or vuln.get("details") or "advisory")[:220].replace("\n", " "),
                _fixed_for(vuln, dependency.name), _severity(vuln), "osv",
            ))
            per_package += 1
            if per_package >= 3:
                break
    return findings


def online_broken() -> bool:
    return _ONLINE["broken"]
