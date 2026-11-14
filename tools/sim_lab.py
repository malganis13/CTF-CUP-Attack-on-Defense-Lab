#!/usr/bin/env python3
"""sim_lab — поднимает и обслуживает полигон A/D внутри WSL.

    python tools/sim_lab.py up            # развернуть и проверить
    python tools/sim_lab.py status        # чекер, порты, здоровье
    python tools/sim_lab.py down          # остановить сервисы
    python tools/sim_lab.py ssh-config    # готовый блок для ~/.ssh/config
    python tools/sim_lab.py reset-flags   # обнулить счёт чекера

Полигон: Kali WSL, три сервиса (python/node/php), чекер по раундам,
sshd на 2222. Всё внутри дистрибутива, хост не трогается.
"""
from __future__ import annotations

import argparse
import io
import json
import os
import pathlib
import socket
import subprocess
import sys
import tarfile
import time
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
SIM = ROOT / "sim"
KEYS = SIM / "keys"
STATE = SIM / ".lab.json"
DISTRO = os.environ.get("AD_WSL_DISTRO", "kali-linux")
SSH_PORT = int(os.environ.get("AD_SSH_PORT", "2222"))
SERVICES = {"notes": 8081, "archive": 8082, "warehouse": 8083}
ENV = dict(os.environ, WSL_UTF8="1")


def wsl(*args: str, stdin: bytes | None = None, check: bool = False) -> subprocess.CompletedProcess:
    command = ["wsl", "-d", DISTRO, "-u", "root", "--", *args]
    return subprocess.run(command, input=stdin, capture_output=True, env=ENV, check=check)


def resolve_host() -> str:
    """Адрес дистрибутива.

    localhost-форвард WSL2 отваливается на длинных соединениях и на части
    сокетов, поэтому полигон адресуется по IP виртуальной сети. Он живёт до
    перезапуска WSL, поэтому читается каждый раз заново.
    """
    result = subprocess.run(
        ["wsl", "-d", DISTRO, "--", "hostname", "-I"], capture_output=True, env=ENV
    )
    text = result.stdout.decode("utf-8", "replace").strip()
    return text.split()[0] if text else "127.0.0.1"



def say(text: str) -> None:
    print(text, flush=True)


def ensure_key() -> pathlib.Path:
    KEYS.mkdir(parents=True, exist_ok=True)
    private = KEYS / "ad_lab"
    public = KEYS / "ad_lab.pub"
    if not private.exists():
        say("== ssh key: generating sim/keys/ad_lab")
        result = subprocess.run(
            ["ssh-keygen", "-t", "ed25519", "-N", "", "-C", "ad-lab", "-f", str(private)],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise SystemExit("ssh-keygen failed: " + (result.stderr or result.stdout))
    if not public.exists():
        raise SystemExit("public key missing: " + str(public))
    return public


def stage_tar(public_key: pathlib.Path) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        archive.add(SIM / "deploy.sh", arcname="deploy.sh")
        for path in sorted((SIM / "vulnbox").rglob("*")):
            if path.is_file():
                archive.add(path, arcname=str(path.relative_to(SIM)))
        data = public_key.read_bytes()
        info = tarfile.TarInfo("id_ed25519.pub")
        info.size = len(data)
        archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def health(host: str, port: int, timeout: float = 3.0) -> tuple[bool, str]:
    try:
        with urllib.request.urlopen(f"http://{host}:{port}/health", timeout=timeout) as response:  # noqa: S310
            return True, response.read(400).decode("utf-8", "replace")
    except Exception as error:  # noqa: BLE001
        return False, f"{type(error).__name__}: {error}"


def port_open(host: str, port: int, timeout: float = 1.5) -> bool:
    with socket.socket() as sock:
        sock.settimeout(timeout)
        return sock.connect_ex((host, port)) == 0


def cmd_up(args: argparse.Namespace) -> int:
    public_key = ensure_key()

    say("== WSL check")
    result = wsl("bash", "-lc", "uname -sr; id -u")
    if result.returncode != 0:
        say("WSL недоступен: " + result.stderr.decode("utf-8", "replace"))
        return 2
    say("  " + result.stdout.decode("utf-8", "replace").strip().replace("\n", " / "))

    say("== staging")
    payload = stage_tar(public_key)
    wsl("bash", "-lc", "rm -rf /tmp/adlab && mkdir -p /tmp/adlab")
    extract = wsl("tar", "-xf", "-", "-C", "/tmp/adlab", stdin=payload)
    if extract.returncode != 0:
        say("tar failed: " + extract.stderr.decode("utf-8", "replace"))
        return 3
    say(f"  {len(payload)} bytes -> /tmp/adlab")

    say("== deploy (это ~10 секунд)")
    env_prefix = f"AD_SSH_PORT={SSH_PORT} AD_KEY=/tmp/adlab/id_ed25519.pub AD_CHECKER_INTERVAL={args.interval}"
    deploy = wsl("bash", "-lc", f"{env_prefix} bash /tmp/adlab/deploy.sh")
    output = deploy.stdout.decode("utf-8", "replace")
    for line in output.splitlines():
        say("  " + line)
    if deploy.returncode != 0:
        say("deploy failed:")
        say(deploy.stderr.decode("utf-8", "replace"))
        return 4

    say("== health from windows")
    host = resolve_host()
    say(f"  адрес дистрибутива: {host}")
    all_ok = True
    for name, port in SERVICES.items():
        ok, body = health(host, port)
        all_ok &= ok
        say(f"  {name:<10} :{port}  {'ok' if ok else 'FAIL'}  {body[:80]}")

    ssh_ok = port_open(host, SSH_PORT)
    say(f"  ssh        :{SSH_PORT}  {'ok' if ssh_ok else 'FAIL'}")

    STATE.write_text(
        json.dumps(
            {
                "distro": DISTRO,
                "host": host,
                "ssh": {"host": host, "port": SSH_PORT, "user": "root", "key": str(KEYS / "ad_lab")},
                "services": {name: f"http://{host}:{port}" for name, port in SERVICES.items()},
                "checked_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return 0 if all_ok and ssh_ok else 5


def cmd_status(_: argparse.Namespace) -> int:
    host = resolve_host()
    for name, port in SERVICES.items():
        ok, body = health(host, port)
        say(f"{name:<10} :{port}  {'ok' if ok else 'FAIL'}  {body[:100]}")
    say(f"ssh        :{SSH_PORT}  {'open' if port_open(host, SSH_PORT) else 'closed'}")

    result = wsl("bash", "-lc", "cat /srv/_checker/status.json 2>/dev/null; echo; tail -5 /srv/_checker/scoreboard.log 2>/dev/null")
    say("== checker")
    say(result.stdout.decode("utf-8", "replace").strip())
    return 0


def cmd_down(_: argparse.Namespace) -> int:
    result = wsl(
        "bash",
        "-lc",
        "systemctl disable --now ad-checker.service ad-notes.service ad-archive.service ad-warehouse.service 2>&1 | tail -4",
    )
    say(result.stdout.decode("utf-8", "replace").strip() or "остановлено")
    return 0


def cmd_ssh_config(_: argparse.Namespace) -> int:
    host = resolve_host()
    say("# ~/.ssh/config")
    say("Host adlab")
    say(f"    HostName {host}")
    say(f"    Port {SSH_PORT}")
    say("    User root")
    say(f"    IdentityFile {KEYS / 'ad_lab'}")
    say("    StrictHostKeyChecking no")
    return 0


def cmd_reset_flags(_: argparse.Namespace) -> int:
    result = wsl("bash", "-lc", "rm -f /srv/_checker/flags.json /srv/_checker/status.json /srv/_checker/scoreboard.log; systemctl restart ad-checker; echo ok")
    say(result.stdout.decode("utf-8", "replace").strip())
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Полигон A/D в WSL")
    parser.add_argument("--interval", type=int, default=45, help="раунд чекера, секунды")
    sub = parser.add_subparsers(dest="command", required=True)
    for name, function in (
        ("up", cmd_up),
        ("status", cmd_status),
        ("down", cmd_down),
        ("ssh-config", cmd_ssh_config),
        ("reset-flags", cmd_reset_flags),
    ):
        handler = sub.add_parser(name)
        handler.set_defaults(func=function)
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
