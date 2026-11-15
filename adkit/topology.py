"""Стенд турнира: сервер, сервисы, находки, команды.

Карта находок (`/api/map`) отвечает на вопрос «что чинить». Эта модель отвечает
на другой: «как выглядит наш вулнбокс и что на нём висит». Узлы задаёт человек —
сервисы, которые он видит в игре, — а находки, живость и уверенность
подтягиваются из последнего аудита.

Модель хранится в `state/topology.json`, правится из интерфейса и переживает
перезапуск. Аудит её не перезаписывает: импорт только добавляет недостающие
сервисы и заполняет пустые поля, ручные правки остаются.

Почему отдельный модуль, а не поле в аудите: аудит — снимок машины, стенд —
рабочая схема команды. Они живут разное время и меняются разными людьми.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path

SCHEMA = 1
MAX_SERVICES = 32
MAX_MEMBERS = 64
MAX_TEAMS = 4096

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}
HEALTH_RU = {
    "up": "не лежит",
    "down": "лежит",
    "sick": "ошибки",
    "open": "порт открыт",
    "local": "loopback",
    "unknown": "неизвестно",
    "": "неизвестно",
}


def state_dir(base: Path | None = None) -> Path:
    """Каталог состояния: `AD_STATE_DIR` или `state/` рядом с приложением."""
    override = (os.environ.get("AD_STATE_DIR") or "").strip()
    root = Path(override) if override else (Path(base) if base else Path.cwd()) / "state"
    root.mkdir(parents=True, exist_ok=True)
    return root


def empty_model() -> dict:
    return {
        "schema": SCHEMA,
        "event": "",
        "team": "",
        "teams_total": 0,
        "members": [],
        "round_minutes": 5,
        "server": {"name": "наш вулнбокс", "host": ""},
        "services": [],
        "updated_at": 0,
    }


def service_id(name: str, port: int) -> str:
    digest = hashlib.sha1(f"{(name or '').strip().lower()}:{int(port or 0)}".encode()).hexdigest()
    return digest[:8]


def _text(value, limit: int) -> str:
    if value is None:
        return ""
    return str(value).replace("\x00", "").strip()[:limit]


def _int(value, low: int, high: int, default: int = 0) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return default
    return max(low, min(high, number))


def normalise(raw: dict) -> tuple[dict, list[str]]:
    """Приводит модель к безопасному виду. Возвращает модель и замечания."""
    notes: list[str] = []
    if not isinstance(raw, dict):
        return empty_model(), ["модель должна быть объектом"]
    model = empty_model()
    model["event"] = _text(raw.get("event"), 80)
    model["team"] = _text(raw.get("team"), 48)
    model["teams_total"] = _int(raw.get("teams_total"), 0, MAX_TEAMS)
    model["round_minutes"] = _int(raw.get("round_minutes"), 1, 120, 5)
    if model["round_minutes"] <= 0:
        model["round_minutes"] = 5

    server = raw.get("server") or {}
    if isinstance(server, dict):
        model["server"] = {
            "name": _text(server.get("name"), 48) or "наш вулнбокс",
            "host": _text(server.get("host"), 64),
        }

    members = raw.get("members") or []
    if isinstance(members, str):
        members = members.splitlines()
    seen_members: set[str] = set()
    for entry in members:
        name = _text(entry, 40)
        if not name or name.lower() in seen_members:
            continue
        seen_members.add(name.lower())
        model["members"].append(name)
        if len(model["members"]) >= MAX_MEMBERS:
            notes.append(f"участников больше {MAX_MEMBERS}: лишние отброшены")
            break

    services = raw.get("services") or []
    if not isinstance(services, list):
        services = []
        notes.append("services должен быть списком")
    seen: set[str] = set()
    for entry in services:
        if not isinstance(entry, dict):
            continue
        name = _text(entry.get("name") or entry.get("service"), 48)
        port = _int(entry.get("port"), 0, 65535)
        if not name and not port:
            continue
        if not name:
            name = f"port {port}"
        mark = service_id(name, port)
        if mark in seen:
            continue
        seen.add(mark)
        model["services"].append({
            "id": mark,
            "name": name,
            "port": port,
            "language": _text(entry.get("language"), 24),
            "cwd": _text(entry.get("cwd") or entry.get("root"), 200),
            "url": _text(entry.get("url"), 200),
            "notes": _text(entry.get("notes"), 200),
        })
        if len(model["services"]) >= MAX_SERVICES:
            notes.append(f"сервисов больше {MAX_SERVICES}: лишние отброшены")
            break
    return model, notes


def load(base: Path | None = None) -> dict:
    path = state_dir(base) / "topology.json"
    if not path.is_file():
        return empty_model()
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return empty_model()
    model, _ = normalise(raw)
    return model


def save(model: dict, base: Path | None = None) -> dict:
    """Атомарная запись: сначала временный файл, потом переименование."""
    clean, _ = normalise(model)
    clean["updated_at"] = time.time()
    root = state_dir(base)
    path = root / "topology.json"
    tmp = root / "topology.json.tmp"
    tmp.write_text(json.dumps(clean, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(tmp, path)
    return clean


def merge_audit(model: dict, audit: dict | None) -> tuple[dict, dict]:
    """Добавляет сервисы из аудита, не трогая ручные поля.

    Совпадение — по порту, затем по имени. Имя, язык, каталог заполняются только
    там, где пусто: человек мог назвать сервис по-своему.
    """
    added = 0
    updated = 0
    if not audit:
        return model, {"added": 0, "updated": 0, "found": 0}

    clean, _ = normalise(model)
    if not clean["server"].get("host") and audit.get("host"):
        clean["server"]["host"] = _text(audit.get("host"), 64)

    by_port = {item["port"]: item for item in clean["services"] if item["port"]}
    by_name = {item["name"].lower(): item for item in clean["services"]}

    for entry in audit.get("services") or []:
        port = _int(entry.get("port"), 0, 65535)
        name = _text(entry.get("service") or entry.get("name"), 48) or f"port {port}"
        target = by_port.get(port) if port else None
        if target is None:
            target = by_name.get(name.lower())
        if target is None:
            target = {
                "id": service_id(name, port),
                "name": name,
                "port": port,
                "language": "",
                "cwd": "",
                "url": "",
                "notes": "",
            }
            clean["services"].append(target)
            added += 1
        else:
            updated += 1
        if not target.get("language"):
            target["language"] = _text(entry.get("language"), 24)
        if not target.get("cwd"):
            target["cwd"] = _text(entry.get("root") or entry.get("cwd"), 200)
        if not target.get("port") and port:
            target["port"] = port
        by_port[target["port"]] = target
        by_name[target["name"].lower()] = target

    return clean, {"added": added, "updated": updated, "found": len(audit.get("services") or [])}


def _prefix_match(path: str, service: dict) -> int:
    """Длина совпавшего префикса каталога. 0 — не этот сервис."""
    if not path:
        return 0
    best = 0
    for key in ("cwd", "root", "path"):
        prefix = (service.get(key) or "").rstrip("/")
        if len(prefix) < 2:
            continue
        if path == prefix or path.startswith(prefix + "/"):
            best = max(best, len(prefix))
    return best


def _health(liveness: dict | None, port: int) -> str:
    for row in (liveness or {}).get("rows") or []:
        if _int(row.get("port"), 0, 65535) == port:
            return str(row.get("state") or "unknown")
    return "unknown"


def _brief(finding: dict) -> dict:
    conf = finding.get("confidence") or {}
    return {
        "id": finding.get("id"),
        "fingerprint": finding.get("fingerprint"),
        "rule": finding.get("rule"),
        "kind": finding.get("kind"),
        "kind_ru": finding.get("kind_ru") or finding.get("kind"),
        "severity": finding.get("severity"),
        "line": finding.get("line"),
        "file": finding.get("file"),
        "snippet": (finding.get("snippet") or "")[:160],
        "confidence": conf.get("level", "unsure"),
        "confidence_ru": conf.get("level_ru", "не уверен"),
        "status": finding.get("status") or "open",
        "template": bool(finding.get("template")),
        "effort_ru": finding.get("effort_ru") or "",
    }


def build_view(model: dict, audit: dict | None = None,
               liveness: dict | None = None) -> dict:
    """Модель + находки + живость → плоская структура для отрисовки."""
    clean, notes = normalise(model)
    findings = list((audit or {}).get("findings") or [])

    buckets: dict[str, list[dict]] = {item["id"]: [] for item in clean["services"]}
    loose: list[dict] = []
    for finding in findings:
        best_id = ""
        best_len = 0
        for service in clean["services"]:
            score = _prefix_match(str(finding.get("file") or ""), service)
            if score > best_len:
                best_len = score
                best_id = service["id"]
        if best_id:
            buckets[best_id].append(finding)
        else:
            loose.append(finding)

    services = []
    totals = {"high": 0, "medium": 0, "low": 0, "info": 0}
    unsure = 0
    open_count = 0
    for service in clean["services"]:
        items = buckets.get(service["id"], [])
        counts = {"high": 0, "medium": 0, "low": 0, "info": 0}
        conf = {"certain": 0, "likely": 0, "unsure": 0}
        status = {"open": 0, "fixed": 0, "regressed": 0, "ignored": 0}
        worst = "info"
        for finding in items:
            severity = str(finding.get("severity") or "info")
            if severity not in counts:
                severity = "info"
            counts[severity] += 1
            totals[severity] += 1
            if SEVERITY_ORDER.get(severity, 3) < SEVERITY_ORDER.get(worst, 3):
                worst = severity
            level = ((finding.get("confidence") or {}).get("level")) or "unsure"
            conf[level] = conf.get(level, 0) + 1
            if level == "unsure":
                unsure += 1
            state = finding.get("status") or "open"
            status[state] = status.get(state, 0) + 1
            if state in ("open", "regressed"):
                open_count += 1
        # Риск — не «сколько нашлось», а «сколько стоит раунд»: high весит
        # десять, medium четыре, low один. 100 — потолок шкалы.
        risk = min(100, counts["high"] * 10 + counts["medium"] * 4 + counts["low"])
        services.append({
            **service,
            "health": _health(liveness, service["port"]),
            "health_ru": HEALTH_RU.get(_health(liveness, service["port"]), "неизвестно"),
            "worst": worst,
            "risk": risk,
            "counts": counts,
            "confidence": conf,
            "status": status,
            "findings": [_brief(finding) for finding in items],
        })

    loose_brief = [_brief(finding) for finding in loose]
    for finding in loose_brief:
        if finding["status"] in ("open", "regressed"):
            open_count += 1
        severity = finding["severity"] if finding["severity"] in totals else "info"
        totals[severity] += 1
        if finding["confidence"] == "unsure":
            unsure += 1

    field = {
        "teams_total": clean["teams_total"],
        "members": clean["members"],
        "ours": clean["team"],
    }

    return {
        "model": clean,
        "notes": notes,
        "server": clean["server"],
        "services": services,
        "loose": loose_brief,
        "field": field,
        "summary": {
            "services": len(services),
            "findings": sum(totals.values()),
            "high": totals["high"],
            "medium": totals["medium"],
            "low": totals["low"],
            "info": totals["info"],
            "unsure": unsure,
            "open": open_count,
            "teams_total": clean["teams_total"],
            "members": len(clean["members"]),
        },
        "round": {"minutes": clean["round_minutes"], "event": clean["event"]},
    }


def demo_model() -> dict:
    """Стенд для демо-режима: три сервиса полигона."""
    model = empty_model()
    model.update({
        "event": "тренировочный полигон",
        "team": "наша команда",
        "teams_total": 12,
        "members": ["23:59", "второй", "третий"],
        "server": {"name": "вулнбокс", "host": "127.0.0.1"},
        "services": [
            {"id": service_id("notes", 8081), "name": "notes", "port": 8081,
             "language": "python", "cwd": "/srv/notes", "url": "", "notes": ""},
            {"id": service_id("files", 8082), "name": "files", "port": 8082,
             "language": "node", "cwd": "/srv/files", "url": "", "notes": ""},
            {"id": service_id("profile", 8083), "name": "profile", "port": 8083,
             "language": "python", "cwd": "/srv/profile", "url": "", "notes": ""},
        ],
    })
    return model
