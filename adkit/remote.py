"""Что видно на цели по SSH: службы, порты, каталоги и смена пароля.

Аудит читает исходники; этот модуль читает саму машину. Он отвечает на вопрос
«что у меня висит и на каком порту» без сканера портов: `ss`, `systemctl`,
`docker ps` — всё локально на цели, один заход, никакого трафика наружу.

Смена пароля — единственная запись, которую инструмент делает на цели, и только
по явной кнопке. Она идёт через `chpasswd` со stdin: пароль не попадает ни в
аргументы процесса на цели, ни в журнал приложения, ни в config.json.
"""
from __future__ import annotations

import re
import secrets
import shlex
import time

USER_RE = re.compile(r"^[a-z_][a-z0-9_.-]{0,31}$")
MIN_PASSWORD = 4
MAX_PASSWORD = 128
MAX_ROWS = 64

ALPHABET = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789-_"


class RemoteError(RuntimeError):
    """Ошибка чтения цели или смены пароля."""


def generate_password(length: int = 20) -> str:
    return "".join(secrets.choice(ALPHABET) for _ in range(max(MIN_PASSWORD, length)))


# Один заход: порты, юниты, их рабочие каталоги, каталоги сервисов, докер.
# Маркеры разделяют блоки, чтобы разбор не зависел от порядка вывода.
SCRIPT = r"""
echo __SS__
ss -lntp 2>/dev/null || netstat -lntp 2>/dev/null || true
echo __UNITS__
systemctl list-units --type=service --state=running --no-pager --no-legend 2>/dev/null || true
echo __SHOW__
u=$(systemctl list-units --type=service --state=running --no-pager --no-legend 2>/dev/null | awk '{print $1}')
if [ -n "$u" ]; then systemctl show -p Id -p MainPID -p WorkingDirectory --no-pager $u 2>/dev/null; fi
echo __DIRS__
for b in /srv /opt /home; do [ -d "$b" ] && find "$b" -maxdepth 1 -mindepth 1 -type d -printf '%p\n' 2>/dev/null; done
true
echo __CWD__
for pid in $(ss -lntpH 2>/dev/null | grep -o 'pid=[0-9]*' | cut -d= -f2 | sort -u); do
  [ -d /proc/$pid ] || continue
  printf '%s\t%s\n' "$pid" "$(readlink /proc/$pid/cwd 2>/dev/null)"
done
echo __DOCKER__
docker ps --format '{{.Names}}	{{.Ports}}' 2>/dev/null || true
echo __SSHD__
sshd -T 2>/dev/null | grep -Ei '^(permitrootlogin|passwordauthentication|pubkeyauthentication) ' || true
"""


def _sections(text: str) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    current = ""
    for line in text.splitlines():
        stripped = line.strip()
        if re.fullmatch(r"__[A-Z]+__", stripped):
            current = stripped.strip("_")
            result.setdefault(current, [])
            continue
        if current:
            result[current].append(line)
    return result


def _split_local(value: str) -> tuple[str, int]:
    host, _, port = value.rpartition(":")
    if not host or not port.isdigit():
        return "", 0
    return host.strip("[]") or host, int(port)


def _parse_ss(lines: list[str]) -> list[dict]:
    rows: list[dict] = []
    for line in lines:
        parts = line.split()
        if len(parts) < 5 or parts[0] not in {"LISTEN", "UNCONN"}:
            # формат netstat: tcp 0 0 0.0.0.0:2222 0.0.0.0:* LISTEN 194/sshd
            match = re.match(r"^\s*(?:tcp6?|udp6?)\s+\d+\s+\d+\s+(\S+)\s+\S+\s+(?:LISTEN\s+)?(\d+)/(\S+)",
                             line)
            if not match:
                continue
            bind, port = _split_local(match.group(1))
            if port:
                rows.append({"port": port, "bind": bind, "process": match.group(3),
                             "pid": int(match.group(2))})
            continue
        bind, port = _split_local(parts[3])
        if not port:
            continue
        rest = " ".join(parts[5:])
        proc = re.search(r'\("([^"]+)",pid=(\d+)', rest)
        rows.append({
            "port": port,
            "bind": bind,
            "process": proc.group(1) if proc else "",
            "pid": int(proc.group(2)) if proc else 0,
        })
    return rows


def _parse_units(lines: list[str]) -> list[dict]:
    units: list[dict] = []
    for line in lines:
        parts = line.split()
        if not parts or not parts[0].endswith(".service"):
            continue
        units.append({"unit": parts[0], "description": " ".join(parts[4:])})
    return units


def _parse_show(lines: list[str]) -> dict[int, dict]:
    """MainPID -> {unit, cwd} из блоков systemctl show."""
    by_pid: dict[int, dict] = {}
    block: dict[str, str] = {}

    def flush() -> None:
        pid = block.get("MainPID", "").strip()
        unit = block.get("Id", "").strip()
        if unit and pid.isdigit() and int(pid) > 0:
            by_pid[int(pid)] = {"unit": unit, "cwd": block.get("WorkingDirectory", "").strip()}

    for line in lines + [""]:
        if not line.strip():
            flush()
            block = {}
            continue
        key, _, value = line.partition("=")
        if key in {"Id", "MainPID", "WorkingDirectory"}:
            block[key] = value
    return by_pid


def _friendly(unit: str) -> str:
    name = unit[:-8] if unit.endswith(".service") else unit
    if name.startswith("ad-"):
        name = name[3:]
    return name


def _parse_docker(lines: list[str]) -> list[dict]:
    rows: list[dict] = []
    for line in lines:
        line = line.rstrip("\r")
        if not line.strip():
            continue
        name, _, ports = line.partition("\t")
        ports = ports or line[len(name):].strip()
        match = re.search(r"(?:0\.0\.0\.0|\[::\]|[\d.]+):(\d+)->", ports)
        rows.append({
            "name": name.strip() or "container",
            "port": int(match.group(1)) if match else 0,
            "bind": "docker",
        })
    return rows


def _parse_policy(lines: list[str]) -> dict:
    policy: dict[str, str] = {}
    for line in lines:
        key, _, value = line.strip().partition(" ")
        if key:
            policy[key.lower()] = value.strip()
    return policy


def _parse_cwd(lines: list[str]) -> dict[int, str]:
    result: dict[int, str] = {}
    for line in lines:
        pid, _, cwd = line.partition("\t")
        if pid.strip().isdigit() and cwd.strip():
            result[int(pid)] = cwd.strip()
    return result


def services(ssh) -> dict:
    """Службы и порты на цели. Ничего не меняет, один SSH-заход.

    Процессы и `sshd -T` видны только root. Если подключились служебным
    пользователем, пробуем `sudo -n`; без него отдаём то, что видно, и честную
    пометку, почему строки беднее.
    """
    code, out, _ = ssh.run("id -u", timeout=8)
    privileged = out.strip() == "0"
    note = ""
    if privileged:
        code, out, err = ssh.run(SCRIPT, timeout=40)
    else:
        command = "sudo -n sh -c " + shlex.quote(SCRIPT)
        code, out, err = ssh.run(command, timeout=40)
        if "__SS__" not in out:
            code, out, err = ssh.run(SCRIPT, timeout=40)
            note = ("подключение не root: процессы, каталоги по pid и политика sshd "
                    "не видны; для полной картины нужен root или sudo без пароля")
    if code != 0 and not out.strip():
        raise RemoteError((err or out).strip() or f"ssh exited with {code}")
    parts = _sections(out)

    ports = _parse_ss(parts.get("SS", []))
    units = _parse_units(parts.get("UNITS", []))
    by_pid = _parse_show(parts.get("SHOW", []))
    cwd_by_pid = _parse_cwd(parts.get("CWD", []))
    dirs = [line.strip() for line in parts.get("DIRS", []) if line.strip()]
    docker = _parse_docker(parts.get("DOCKER", []))
    policy = _parse_policy(parts.get("SSHD", []))

    unit_by_cwd = {info["cwd"].rstrip("/"): info["unit"]
                   for info in by_pid.values() if info.get("cwd")}

    def describe(pid: int, process: str, port: int) -> dict:
        info = by_pid.get(pid, {})
        cwd = cwd_by_pid.get(pid, "") or info.get("cwd", "")
        unit = info.get("unit", "") or unit_by_cwd.get(cwd.rstrip("/"), "")
        if unit:
            name = _friendly(unit)
        elif cwd.startswith(("/srv/", "/opt/", "/home/")):
            name = cwd.rstrip("/").rsplit("/", 1)[-1]
        else:
            name = process or f"port {port}"
        return {"unit": unit, "cwd": cwd, "name": name}

    rows: dict[int, dict] = {}
    for item in ports:
        if item["bind"] == "10.255.255.254":
            continue  # DNS-прокси WSL, к вулнбоксу отношения не имеет
        info = describe(item["pid"], item["process"], item["port"])
        row = {
            "port": item["port"],
            "bind": item["bind"],
            "process": item["process"],
            "pid": item["pid"],
            "unit": info["unit"],
            "name": info["name"],
            "cwd": info["cwd"],
            "kind": "port",
        }
        existing = rows.get(item["port"])
        # один порт — одна строка: [::] и 0.0.0.0 — это один и тот же сокет
        if existing is None or (existing["bind"] == "::" and item["bind"] != "::"):
            rows[item["port"]] = row

    used_units = {row["unit"] for row in rows.values() if row["unit"]}
    used_pids = {row["pid"] for row in rows.values() if row["pid"]}
    for item in units:
        if item["unit"] in used_units:
            continue
        pid = next((pid for pid, info in by_pid.items() if info["unit"] == item["unit"]), 0)
        if pid and pid in used_pids:
            continue
        info = by_pid.get(pid, {})
        cwd = info.get("cwd", "") or cwd_by_pid.get(pid, "")
        if not (item["unit"].startswith("ad-") or cwd.startswith(("/srv/", "/opt/", "/home/"))):
            continue
        rows[-(len(rows) + 1)] = {
            "port": 0,
            "bind": "",
            "process": "",
            "pid": pid,
            "unit": item["unit"],
            "name": _friendly(item["unit"]),
            "cwd": cwd,
            "kind": "unit",
        }

    for item in docker:
        if not item["port"] or item["port"] in rows:
            continue
        rows[-1000 - item["port"]] = {
            "port": item["port"],
            "bind": "docker",
            "process": item["name"],
            "pid": 0,
            "unit": "",
            "name": item["name"],
            "cwd": "",
            "kind": "docker",
        }

    ordered = sorted(rows.values(), key=lambda row: (row["port"] == 0, row["port"], row["name"]))
    ordered = ordered[:MAX_ROWS]
    return {
        "ok": True,
        "label": ssh.label(),
        "host": getattr(ssh, "host", ""),
        "collected_at": time.time(),
        "dirs": dirs[:32],
        "policy": policy,
        "note": note,
        "count": len(ordered),
        "rows": ordered,
    }


def policy(ssh) -> dict:
    """Политика sshd для паролей: нужна, чтобы объяснить отказ входа по паролю."""
    code, out, _ = ssh.run("sshd -T 2>/dev/null | grep -Ei "
                           "'^(permitrootlogin|passwordauthentication|pubkeyauthentication) ' || true",
                           timeout=10)
    return _parse_policy(out.splitlines())


def _clean_password(password: str) -> str:
    clean = (password or "").replace("\r", "").replace("\n", "").replace("\x00", "")
    if len(clean) < MIN_PASSWORD:
        raise RemoteError(f"пароль короче {MIN_PASSWORD} символов")
    if len(clean) > MAX_PASSWORD:
        raise RemoteError(f"пароль длиннее {MAX_PASSWORD} символов")
    return clean


def rotate_password(ssh, user: str, password: str) -> dict:
    """Меняет пароль пользователя через chpasswd. Пароль идёт по stdin."""
    user = (user or "").strip()
    if not USER_RE.match(user):
        raise RemoteError("имя пользователя: строчные буквы, цифры, _ . -; до 32 символов")
    password = _clean_password(password)

    code, out, err = ssh.run(f"id -u {shlex.quote(user)}", timeout=10)
    if code != 0:
        raise RemoteError(f"на цели нет пользователя {user}")

    # Пароль не попадает в командную строку процесса: только в stdin chpasswd.
    code, out, err = ssh.run("chpasswd", timeout=15, stdin=f"{user}:{password}\n")
    if code != 0:
        message = (err or out).strip()
        if "permission" in message.lower() or "denied" in message.lower():
            # Не root: пробуем sudo без пароля — так работает служебный аккаунт.
            code, out, err = ssh.run("sudo -n chpasswd", timeout=15,
                                     stdin=f"{user}:{password}\n")
            if code == 0:
                return {"ok": True, "user": user}
            raise RemoteError("нет прав: нужен root или sudo без пароля")
        raise RemoteError(message or f"chpasswd exited with {code}")
    return {"ok": True, "user": user}


def demo_rows() -> dict:
    rows = [
        {"port": 8081, "bind": "0.0.0.0", "process": "python3", "pid": 147,
         "unit": "ad-notes.service", "name": "notes", "cwd": "/srv/notes", "kind": "port"},
        {"port": 8082, "bind": "0.0.0.0", "process": "node", "pid": 146,
         "unit": "ad-archive.service", "name": "archive", "cwd": "/srv/archive", "kind": "port"},
        {"port": 8083, "bind": "0.0.0.0", "process": "php", "pid": 150,
         "unit": "ad-warehouse.service", "name": "warehouse", "cwd": "/srv/warehouse", "kind": "port"},
        {"port": 2222, "bind": "0.0.0.0", "process": "sshd", "pid": 194,
         "unit": "ssh.service", "name": "ssh", "cwd": "", "kind": "port"},
        {"port": 0, "bind": "", "process": "", "pid": 152,
         "unit": "ad-checker.service", "name": "checker", "cwd": "/srv/_checker", "kind": "unit"},
    ]
    return {
        "ok": True, "demo": True, "label": "демо-цель", "host": "127.0.0.1",
        "collected_at": time.time(), "dirs": ["/srv/notes", "/srv/archive", "/srv/warehouse"],
        "policy": {"permitrootlogin": "prohibit-password", "passwordauthentication": "yes",
                   "pubkeyauthentication": "yes"},
        "count": len(rows), "rows": rows,
    }
