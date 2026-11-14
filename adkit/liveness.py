"""Живость сервисов: один GET на сервис, статус и время ответа.

Проверка идёт тем же движком и через тот же бюджет, что и пробы: запрос
попадает в журнал трафика, путь `/_checker` блокируется, метод только GET.
Отличие одно — здесь не ищется уязвимость, здесь выясняется, отвечает ли
сервис вообще. Во время игры это первый вопрос раунда.
"""
from __future__ import annotations

import re
import socket
import time

from . import probe
from .ratelimit import BUDGET

HEALTH_PATHS = ("/health", "/")
TIMEOUT = 1.5
MAX_SERVICES = 24
# Между проверками одного и того же порта — не чаще раза в две секунды:
# кнопку можно нажимать сколько угодно, сети это не стоит ничего лишнего.
COOLDOWN = 2.0
LAST: dict[int, dict] = {}


def _probe_url(host: str, port: int, path: str) -> str:
    return f"http://{host}:{port}{path}"


def _tcp_open(host: str, port: int) -> tuple[bool, int]:
    """Быстрый TCP-коннект: отличает «порт закрыт» от «порт открыт, но молчит»."""
    started = time.time()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(TIMEOUT)
        try:
            code = sock.connect_ex((host, port))
        except OSError:
            code = 1
    return code == 0, int((time.time() - started) * 1000)


BANNERS = (
    (re.compile(rb"^SSH-([\d.]+)"), "SSH"),
    (re.compile(rb"^HTTP/"), "HTTP"),
    (re.compile(rb"^-?(?:NOAUTH|ERR|WRONGTYPE)|\*1\r\n\$"), "Redis"),
    (re.compile(rb"^AMQP"), "AMQP"),
    (re.compile(rb"^(?:RTSP|SIP)/"), "RTSP/SIP"),
    (re.compile(rb"^220[ -].*(?:SMTP|Postfix|Exim)", re.I), "SMTP"),
    (re.compile(rb"^RFB \d"), "VNC"),
    (re.compile(rb"^\x00\x00\x00\x0a[\d.]+"), "MySQL"),
    (re.compile(rb"^220 .*FTP", re.I), "FTP"),
)


def _fingerprint(host: str, port: int) -> str:
    """Кто на порту: баннер читается один раз, без бюджета запросов.

    qdb и подобные протоколы молчат в ответ на POST — для них это
    «бинарный протокол», и это уже ответ, а не пустота.
    """
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
            sock.settimeout(0.7)
            try:
                data = sock.recv(96)
            except (socket.timeout, OSError):
                return ""
    except OSError:
        return ""
    if not data:
        return ""
    for pattern, label in BANNERS:
        if pattern.search(data):
            return label
    printable = sum(1 for byte in data[:16] if 32 <= byte < 127)
    return "текст без HTTP" if printable >= 12 else "бинарный протокол"


def _host_part(address: str) -> str:
    """`127.0.0.53:53` и `127.0.0.53%lo:53` → `127.0.0.53`."""
    text = (address or "").strip()
    if not text:
        return ""
    if text.count(":") == 1:
        head, _, tail = text.partition(":")
        if tail.isdigit():
            text = head
    text = text.split("%", 1)[0]
    return text.strip("[]")


def check_one(host: str, entry: dict) -> dict:
    """Один сервис: TCP-коннект, затем GET /health, затем GET /."""
    port = int(entry.get("port") or 0)
    name = entry.get("service") or entry.get("name") or f"port {port}"
    address = _host_part(entry.get("address") or "")
    proto = (entry.get("proto") or "tcp").lower()
    row = {
        "port": port,
        "service": name,
        "language": entry.get("language") or "",
        "state": "down",
        "status": 0,
        "ms": None,
        "path": None,
        "note": "",
        "checked_at": round(time.time(), 3),
    }
    if not port:
        row["note"] = "нет порта"
        return row
    if proto != "tcp":
        # UDP-сокет HTTP не отдаёт: стучаться некуда и незачем
        row["state"] = "local"
        row["note"] = f"{proto}, HTTP не проверяется"
        LAST[port] = row
        return row
    if address.startswith("127.") or address in {"::1", "localhost"}:
        # systemd-resolved, chronyd и прочие слушают только loopback:
        # снаружи такого порта нет, и «лежит» здесь было бы неправдой
        row["state"] = "local"
        row["note"] = f"только {address}"
        LAST[port] = row
        return row

    opened, handshake_ms = _tcp_open(host, port)
    if not opened:
        row["ms"] = handshake_ms
        row["note"] = "порт закрыт"
        LAST[port] = row
        return row

    allowed, retry_after = BUDGET.take(1)
    if not allowed:
        row["state"] = "unknown"
        row["ms"] = handshake_ms
        row["note"] = f"бюджет исчерпан, повтор через {retry_after:.0f} с"
        LAST[port] = row
        return row

    opener = probe._opener()  # noqa: SLF001 - один движок, один бюджет, один журнал
    best: dict | None = None
    for path in HEALTH_PATHS:
        allowed, retry_after = BUDGET.take(1) if path != HEALTH_PATHS[0] else (True, 0)
        if not allowed:
            break
        answer = probe._fetch(opener, _probe_url(host, port, path), label="liveness")  # noqa: SLF001
        answer["path"] = path
        if answer.get("status"):
            best = answer
            if answer["status"] < 400:
                break
        elif best is None:
            best = answer

    if best is None:
        row["state"] = "unknown"
        row["note"] = "нет ответа и нет бюджета"
        LAST[port] = row
        return row

    row["status"] = int(best.get("status") or 0)
    row["ms"] = best.get("ms")
    row["path"] = best.get("path")
    if best.get("error"):
        # порт открыт, но говорит не по HTTP (sshd, gRPC, что угодно):
        # для «лежит / не лежит» это живой сервис
        row["state"] = "open"
        guess = _fingerprint(host, port)
        row["protocol"] = guess
        row["note"] = f"порт открыт: {guess}" if guess else "порт открыт, ответ не HTTP"
    elif 200 <= row["status"] < 400:
        row["state"] = "up"
        row["note"] = f"{row['status']} за {row['ms']} мс"
    elif row["status"] >= 500:
        row["state"] = "sick"
        row["note"] = f"{row['status']} — сервис отвечает ошибкой"
    else:
        row["state"] = "up"
        row["note"] = f"{row['status']} — отвечает, ручки /health нет"
    LAST[port] = row
    return row


def check(host: str, services: list[dict], force: bool = False) -> dict:
    """Проверяет список сервисов. Возвращает строки и сводку.

    `force=False` уважает кулдаун: повторное нажатие кнопки в ту же секунду
    отдаёт прошлый результат, а не гонит новую пачку запросов.
    """
    host = (host or "").strip()
    if not host:
        return {"host": "", "rows": [], "summary": {"up": 0, "down": 0, "sick": 0, "open": 0, "local": 0, "unknown": 0},
                "error": "цель не задана"}
    rows: list[dict] = []
    services = [entry for entry in services if entry.get("port")][:MAX_SERVICES]
    for index, entry in enumerate(services):
        port = int(entry.get("port") or 0)
        cached = LAST.get(port)
        now = time.time()
        if not force and cached and now - cached.get("checked_at", 0) < COOLDOWN and cached.get("state") != "unknown":
            rows.append(dict(cached, cached=True))
            continue
        if index:
            time.sleep(probe.MIN_DELAY)
        rows.append(check_one(host, entry))

    summary = {"up": 0, "down": 0, "sick": 0, "open": 0, "local": 0, "unknown": 0}
    for row in rows:
        summary[row["state"]] = summary.get(row["state"], 0) + 1
    alive = [row["ms"] for row in rows if row.get("ms") is not None and row["state"] in {"up", "open"}]
    return {
        "host": host,
        "rows": rows,
        "summary": summary,
        "avg_ms": round(sum(alive) / len(alive)) if alive else None,
        "checked_at": round(time.time(), 3),
    }


def reset() -> None:
    LAST.clear()
