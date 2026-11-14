"""Проверка перед игрой: то, что ломает раунды раньше, чем уязвимости.

Одна SSH-сессия, один скрипт, набор проверок. Ничего не пишется и не
перезапускается: только чтение состояния машины. Каждая проверка возвращает
ok / warn / fail и подсказку, что делать руками.

Проверки выбраны по опыту A/D, а не по красоте:

- часы бокса против часов ноутбука — расхождение в минуты означает патчи
  «после раунда» и флаги, положенные в чужое окно;
- диск и загрузка — сервис, которому некуда писать, падает без ошибки в логе;
- упавшие юниты — самый частый красный раунд после неудачного патча;
- наличие чекер-юнита — чтобы знать его имя и не трогать его;
- бюджет запросов — должен быть пуст на старте;
- ключ и адрес цели — локальная проверка, до всякого SSH.
"""
from __future__ import annotations

import os
import re
import time
from pathlib import Path

from . import probe
from .ssh import BaseSSH

SCRIPT = r"""
echo __DATE__
date +%s
date -u +%Y-%m-%dT%H:%M:%SZ
echo __UNAME__
uname -sr 2>/dev/null
echo __ID__
id -u 2>/dev/null
id -un 2>/dev/null
echo __DF__
df -P / /srv 2>/dev/null | tail -n +2
echo __LOAD__
cat /proc/loadavg 2>/dev/null
echo __FAILED__
systemctl --failed --no-legend --plain 2>/dev/null | head -20
echo __UNITS__
systemctl list-units --type=service --state=running --no-legend --plain 2>/dev/null | head -40
echo __CHECKER__
systemctl list-units --type=service --all --no-legend --plain 2>/dev/null | grep -i -E 'check|flag' | head -10
echo __BINS__
for b in python3 node php ruby java go gcc sqlite3 curl; do
  printf '%s=' "$b"
  command -v "$b" >/dev/null 2>&1 && echo yes || echo no
done
echo __UPTIME__
uptime -p 2>/dev/null || uptime 2>/dev/null
echo __END__
"""

SECTION = re.compile(r"^__([A-Z]+)__$")

UNIT_RE = re.compile(r"^[A-Za-z0-9@._:-]{1,80}$")


def parse(raw: str) -> dict[str, str]:
    sections: dict[str, list[str]] = {}
    current: str | None = None
    for line in raw.splitlines():
        match = SECTION.match(line.strip())
        if match:
            current = match.group(1).lower()
            sections[current] = []
            continue
        if current is not None:
            sections[current].append(line)
    return {name: "\n".join(lines).strip() for name, lines in sections.items()}


def _row(check_id: str, title: str, status: str, value: str, hint: str = "") -> dict:
    return {"id": check_id, "title": title, "status": status, "value": value, "hint": hint}


def _disk_rows(text: str) -> list[tuple[str, float, str]]:
    rows: list[tuple[str, float, str]] = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 6:
            continue
        mount = parts[5]
        use = parts[4].rstrip("%")
        try:
            percent = float(use)
        except ValueError:
            continue
        rows.append((mount, percent, f"{parts[2]} занято из {parts[1]}"))
    return rows


def _failed_units(text: str) -> list[str]:
    units = []
    for line in text.splitlines():
        name = line.split()[0] if line.split() else ""
        if name.endswith(".service"):
            units.append(name)
    return units


def local_checks(target: dict) -> list[dict]:
    rows: list[dict] = []
    host = (target.get("host") or "").strip()
    if not host:
        rows.append(_row("target", "Адрес цели", "fail", "не задан",
                         "вкладка «Подключение»: адрес вулнбокса и порт SSH"))
    else:
        rows.append(_row("target", "Адрес цели", "ok", f"{host}:{target.get('port') or 22}"))
    if (target.get("auth") or "key") == "key":
        key_path = (target.get("key_path") or "").strip()
        if not key_path:
            rows.append(_row("key", "SSH-ключ", "fail", "путь не указан",
                             "укажите файл ключа или переключитесь на пароль (нужен paramiko)"))
        elif not Path(key_path).expanduser().is_file():
            rows.append(_row("key", "SSH-ключ", "fail", f"нет файла {key_path}",
                             "проверьте путь; на Linux ключ обычно ~/.ssh/id_ed25519"))
        else:
            mode = Path(key_path).expanduser().stat().st_mode & 0o777
            if os.name != "nt" and mode & 0o077:
                rows.append(_row("key", "SSH-ключ", "warn", f"{key_path} режим {mode:o}",
                                 f"chmod 600 {key_path}: ssh откажется работать с открытым ключом"))
            else:
                rows.append(_row("key", "SSH-ключ", "ok", key_path))
    budget = probe.BUDGET.peek()
    if budget["used"] == 0:
        rows.append(_row("budget", "Бюджет запросов", "ok", f"0/{budget['capacity']}"))
    else:
        rows.append(_row("budget", "Бюджет запросов", "warn",
                         f"{budget['used']}/{budget['capacity']}",
                         f"на старте лучше ноль: остаток вернётся через {budget['window']:.0f} с"))
    return rows


def check(ssh: BaseSSH | None, target: dict, services: list[dict] | None = None) -> dict:
    """Прогоняет проверки. Плохое соединение — это строки, а не исключение."""
    rows = local_checks(target)
    started = time.time()
    host = (target.get("host") or "").strip()
    if ssh is None:
        rows.append(_row("ssh", "SSH", "fail", "нет соединения", "нажмите «Проверить связь»"))
    else:
        try:
            code, raw, err = ssh.run(SCRIPT, timeout=40)
        except Exception as exc:  # noqa: BLE001 - связь есть, команда нет
            rows.append(_row("ssh", "SSH", "fail", f"{type(exc).__name__}: {exc}", "переподключитесь"))
            code, raw, err = 1, "", ""
        sections = parse(raw)
        rows.extend(_remote_rows(sections, host, services or []))
        if code != 0 and not sections:
            rows.append(_row("ssh", "SSH", "fail", err.strip()[:120] or f"exit {code}",
                             "проверьте ключ, порт и пользователя"))

    summary = {"ok": 0, "warn": 0, "fail": 0}
    for row in rows:
        summary[row["status"]] = summary.get(row["status"], 0) + 1
    return {
        "host": host,
        "checked_at": round(time.time(), 3),
        "duration_ms": int((time.time() - started) * 1000),
        "rows": rows,
        "summary": summary,
        "verdict": "fail" if summary["fail"] else ("warn" if summary["warn"] else "ok"),
    }


def _remote_rows(sections: dict[str, str], host: str, services: list[dict]) -> list[dict]:
    rows: list[dict] = []

    uname = sections.get("uname", "").strip()
    user = sections.get("id", "").splitlines()
    uid = user[0].strip() if user else ""
    name = user[1].strip() if len(user) > 1 else ""
    if uid == "0":
        rows.append(_row("ssh", "SSH и права", "ok", f"root@{host}, {uname}"))
    elif uid:
        rows.append(_row("ssh", "SSH и права", "warn", f"{name} (uid {uid}), {uname}",
                         "часть файлов сервисов читается только root — для аудита нужен root"))
    else:
        rows.append(_row("ssh", "SSH и права", "ok", f"{host}, {uname}"))

    date_lines = sections.get("date", "").splitlines()
    if date_lines:
        try:
            box_epoch = int(date_lines[0].strip())
            skew = box_epoch - int(time.time())
        except ValueError:
            skew = 0
        if abs(skew) <= 2:
            rows.append(_row("clock", "Часы бокса", "ok", f"расхождение {skew:+d} с"))
        elif abs(skew) <= 15:
            rows.append(_row("clock", "Часы бокса", "warn", f"расхождение {skew:+d} с",
                             "патч с временной меткой может уехать в чужой раунд: сверьте NTP"))
        else:
            rows.append(_row("clock", "Часы бокса", "fail", f"расхождение {skew:+d} с",
                             "сначала часы, потом патчи: chronyc makestep / timedatectl set-ntp true"))

    for mount, percent, detail in _disk_rows(sections.get("df", "")):
        if mount not in {"/", "/srv"}:
            continue
        if any(row["id"] == f"disk{mount}" for row in rows):
            # /srv на том же разделе, что /: вторая строка ничего не добавляет
            continue
        if percent < 80:
            rows.append(_row(f"disk{mount}", f"Диск {mount}", "ok", f"{percent:.0f}% · {detail}"))
        elif percent < 92:
            rows.append(_row(f"disk{mount}", f"Диск {mount}", "warn", f"{percent:.0f}% · {detail}",
                             "логи и бэкапы съедят остаток: почистите старые архивы"))
        else:
            rows.append(_row(f"disk{mount}", f"Диск {mount}", "fail", f"{percent:.0f}% · {detail}",
                             "сервис не сможет писать: освободите место до первого раунда"))

    load = sections.get("load", "").split()
    if load:
        try:
            one, five = float(load[0]), float(load[1])
        except ValueError:
            one = five = 0.0
        if five < 2:
            rows.append(_row("load", "Загрузка", "ok", f"{one:.2f} / {five:.2f} (1 / 5 мин)"))
        elif five < 6:
            rows.append(_row("load", "Загрузка", "warn", f"{one:.2f} / {five:.2f}",
                             "что-то уже греет машину: проверьте, не висит ли чужой сканер"))
        else:
            rows.append(_row("load", "Загрузка", "fail", f"{one:.2f} / {five:.2f}",
                             "при такой загрузке раунды будут плавать по времени ответа"))

    failed = _failed_units(sections.get("failed", ""))
    if failed:
        rows.append(_row("failed", "Упавшие юниты", "fail", ", ".join(failed[:4]),
                         "systemctl --failed; поднимайте до старта, иначе раунд красный сразу"))
    else:
        rows.append(_row("failed", "Упавшие юниты", "ok", "нет"))

    checker = [line for line in sections.get("checker", "").splitlines() if line.strip()]
    if checker:
        rows.append(_row("checker", "Чекер", "ok", checker[0].split()[0],
                         "имя юнита из systemd; каталог /_checker инструмент не читает"))
    else:
        rows.append(_row("checker", "Чекер", "warn", "юнит не найден",
                         "чекер может жить у организаторов; уточните, как узнавать счёт"))

    bins = dict(
        line.split("=", 1) for line in sections.get("bins", "").splitlines() if "=" in line
    )
    present = [f"{name}" for name, yes in bins.items() if yes == "yes"]
    missing = [f"{name}" for name, yes in bins.items() if yes != "yes"]
    detail = f"есть: {', '.join(present) or '—'}"
    if missing:
        detail += f"; нет: {', '.join(missing)}"
    rows.append(_row("bins", "Стеки на боксе", "ok" if present else "warn", detail,
                     "" if present else "не нашлось ни одного рантайма — проверьте, тот ли это хост"))

    if services:
        rows.append(_row("listeners", "Слушающие сервисы", "ok", f"{len(services)} портов",
                         "подробности во вкладке «Сервисы»"))
    else:
        rows.append(_row("listeners", "Слушающие сервисы", "warn", "аудит не запускался",
                         "запустите аудит: без него нет ни находок, ни живости"))

    uptime = sections.get("uptime", "").strip()
    if uptime:
        rows.append(_row("uptime", "Аптайм", "ok", uptime))
    return rows


def tail(ssh: BaseSSH, unit: str, lines: int = 120) -> dict:
    """Последние строки журнала юнита. Только чтение, только systemd."""
    if not UNIT_RE.match(unit or ""):
        raise ValueError("имя юнита: буквы, цифры, @ . _ - :")
    lines = max(10, min(int(lines or 120), 400))
    command = f"journalctl -u {unit} -n {lines} --no-pager 2>&1"
    code, out, err = ssh.run(command, timeout=25)
    text = out if out.strip() else err
    return {
        "unit": unit,
        "lines": lines,
        "exit": code,
        "text": text[-60000:],
        "empty": not text.strip(),
    }
