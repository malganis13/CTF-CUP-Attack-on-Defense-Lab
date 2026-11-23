"""SSH backends.

Paramiko is used when installed (password or key). Otherwise the system
OpenSSH client is used with a key or an agent. The audit itself only needs
read-only commands and file reads.
"""
from __future__ import annotations

import shlex
import stat
import subprocess
import time
from pathlib import Path

try:
    import paramiko
except Exception:  # pragma: no cover - optional dependency
    paramiko = None


class SSHError(RuntimeError):
    """Raised when a connection or a remote read fails."""


# Соединение рвётся на короткое время: WSL усыпляет дистрибутив, NAT теряет
# первый SYN, sshd не успевает принять. Первая команда после паузы падает с
# "banner exchange", вторая проходит. Повтор дешевле, чем ложный вердикт "бокс
# недоступен" во время тура.
RETRIES = 3
RETRY_BACKOFF = 0.7

TRANSIENT = (
    "banner exchange",
    "connection refused",
    "connection reset",
    "connection closed",
    "kex_exchange_identification",
    "broken pipe",
    "connection timed out",
    "operation timed out",
)


def transient(stderr: str) -> bool:
    low = (stderr or "").lower()
    return any(marker in low for marker in TRANSIENT)


class BaseSSH:
    def run(self, command: str, timeout: int = 30, stdin: str | None = None) -> tuple[int, str, str]:
        raise NotImplementedError

    def read_file(self, path: str, max_bytes: int = 262144) -> bytes:
        raise NotImplementedError

    def list_dir(self, path: str) -> list[dict]:
        raise NotImplementedError

    def close(self) -> None:
        pass

    def label(self) -> str:
        return "ssh"


class ParamikoSSH(BaseSSH):
    def __init__(self, host: str, port: int, user: str, password: str | None = None,
                 key_path: str | None = None, passphrase: str | None = None,
                 password_only: bool = False) -> None:
        self.host = host
        self.port = port
        self.user = user
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        last: Exception | None = None
        for attempt in range(RETRIES):
            try:
                self.client.connect(
                    hostname=host,
                    port=port,
                    username=user,
                    password=password or None,
                    key_filename=key_path or None,
                    passphrase=passphrase or None,
                    timeout=8,
                    banner_timeout=8,
                    auth_timeout=8,
                    allow_agent=not password_only,
                    look_for_keys=not password_only,
                )
                return
            except Exception as exc:  # noqa: BLE001 - retried below
                last = exc
                if attempt + 1 < RETRIES:
                    time.sleep(RETRY_BACKOFF * (attempt + 1))
        if isinstance(last, paramiko.AuthenticationException):
            raise SSHError(
                "не удалось войти: неверный пароль или ключ. "
                "Введите пароль заново на вкладке «Подключение»"
            ) from last
        raise SSHError(f"{type(last).__name__}: {last}") from last

    @staticmethod
    def _read(stream, cap: int) -> bytes:
        chunks: list[bytes] = []
        total = 0
        while total < cap:
            chunk = stream.read(min(65536, cap - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        return b"".join(chunks)

    def run(self, command: str, timeout: int = 30,
            stdin: str | None = None) -> tuple[int, str, str]:
        try:
            stream, stdout, stderr = self.client.exec_command(command, timeout=timeout)
            if stdin is not None:
                stream.write(stdin.encode("utf-8"))
                stream.flush()
            stream.channel.shutdown_write()
            out = self._read(stdout, 2_000_000)
            err = self._read(stderr, 200_000)
            code = stdout.channel.recv_exit_status()
        except Exception as exc:
            raise SSHError(f"{type(exc).__name__}: {exc}") from exc
        return code, out.decode("utf-8", "replace"), err.decode("utf-8", "replace")

    def read_file(self, path: str, max_bytes: int = 262144) -> bytes:
        try:
            with self.client.open_sftp() as sftp:
                with sftp.open(path, "rb") as handle:
                    try:
                        handle.prefetch(max_bytes)
                    except Exception:
                        pass
                    return handle.read(max_bytes)
        except Exception as exc:
            raise SSHError(f"{type(exc).__name__}: {exc}") from exc

    def list_dir(self, path: str) -> list[dict]:
        try:
            with self.client.open_sftp() as sftp:
                entries = sftp.listdir_attr(path)
        except Exception as exc:
            raise SSHError(f"{type(exc).__name__}: {exc}") from exc
        result = []
        for entry in entries:
            mode = entry.st_mode or 0
            result.append({
                "name": entry.filename,
                "type": "dir" if stat.S_ISDIR(mode) else "file",
                "size": entry.st_size,
                "mtime": int(entry.st_mtime or 0),
            })
        result.sort(key=lambda item: (item["type"] != "dir", item["name"]))
        return result

    def close(self) -> None:
        self.client.close()

    def label(self) -> str:
        return f"{self.user}@{self.host}:{self.port} (paramiko)"


class OpenSSHSSH(BaseSSH):
    def __init__(self, host: str, port: int, user: str, key_path: str | None = None) -> None:
        self.host = host
        self.port = port
        self.user = user
        self.key_path = key_path

    def _base(self) -> list[str]:
        args = [
            "ssh",
            "-o", "BatchMode=yes",
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", "ConnectTimeout=8",
            "-p", str(self.port),
        ]
        if self.key_path:
            args += ["-i", self.key_path]
        args += [f"{self.user}@{self.host}", "--"]
        return args

    def run(self, command: str, timeout: int = 30,
            stdin: str | None = None) -> tuple[int, str, str]:
        proc = self._exec([command], timeout, stdin)
        return (
            proc.returncode,
            proc.stdout.decode("utf-8", "replace"),
            proc.stderr.decode("utf-8", "replace"),
        )

    def read_file(self, path: str, max_bytes: int = 262144) -> bytes:
        command = f"head -c {int(max_bytes)} -- {shlex.quote(path)}"
        proc = self._exec([command], 30)
        if proc.returncode != 0 and not proc.stdout:
            raise SSHError(proc.stderr.decode("utf-8", "replace").strip() or f"read failed: {path}")
        return proc.stdout

    def _exec(self, args: list[str], timeout: int,
              stdin: str | None = None) -> subprocess.CompletedProcess:
        proc: subprocess.CompletedProcess | None = None
        payload = stdin.encode("utf-8") if stdin is not None else None
        for attempt in range(RETRIES):
            try:
                proc = subprocess.run(
                    self._base() + args,
                    input=payload,
                    capture_output=True,
                    timeout=timeout,
                )
            except FileNotFoundError as exc:
                raise SSHError("OpenSSH client not found in PATH") from exc
            except subprocess.TimeoutExpired as exc:
                raise SSHError(f"ssh timed out after {timeout}s") from exc
            if proc.returncode == 0:
                return proc
            if proc.returncode != 255 or not transient(proc.stderr.decode("utf-8", "replace")):
                return proc
            if attempt + 1 < RETRIES:
                time.sleep(RETRY_BACKOFF * (attempt + 1))
        return proc

    def list_dir(self, path: str) -> list[dict]:
        quoted = shlex.quote(path)
        command = (
            f"find {quoted} -maxdepth 1 -mindepth 1 -type d -print; "
            "echo __AD_FILES__; "
            f"find {quoted} -maxdepth 1 -mindepth 1 -type f -print"
        )
        _, out, err = self.run(command, timeout=20)
        if err.strip() and "__AD_FILES__" not in out:
            raise SSHError(err.strip())
        dirs, _, files = out.partition("__AD_FILES__")
        entries: list[dict] = []
        for name in dirs.splitlines():
            name = name.strip()
            if name:
                entries.append({"name": Path(name).name, "type": "dir", "size": None, "mtime": None})
        for name in files.splitlines():
            name = name.strip()
            if name:
                entries.append({"name": Path(name).name, "type": "file", "size": None, "mtime": None})
        entries.sort(key=lambda item: (item["type"] != "dir", item["name"]))
        return entries

    def label(self) -> str:
        return f"{self.user}@{self.host}:{self.port} (openssh)"


def local_hint(host: str, error: str) -> str:
    """Подсказка для локального полигона: WSL засыпает и порт пропадает."""
    low = (error or "").lower()
    if host in {"127.0.0.1", "localhost", "::1"} and any(
            marker in low for marker in ("refused", "timed out", "unreachable")):
        return ("локальный полигон не отвечает: WSL уснул. Запустите `wsl -d kali-linux` "
                "и повторите; sshd слушает 2222 внутри дистрибутива.")
    return ""


def backend_name() -> str:
    return "paramiko" if paramiko is not None else "openssh"


def connect(target: dict, password: str | None = None,
            password_only: bool = False) -> BaseSSH:
    host = (target.get("host") or "").strip()
    user = (target.get("user") or "").strip()
    if not host or not user:
        raise SSHError("host and user are required")
    port = int(target.get("port") or 22)
    key_path = (target.get("key_path") or "").strip() or None
    passphrase = target.get("passphrase") or None
    auth = (target.get("auth") or "").strip()
    if auth == "password" and not password and not password_only:
        raise SSHError("выбран вход по паролю, но пароль не задан: вкладка «Подключение»")
    if password_only:
        key_path = None
    if paramiko is not None:
        return ParamikoSSH(host, port, user, password=password, key_path=key_path,
                           passphrase=passphrase, password_only=password_only)
    if password:
        raise SSHError("вход по паролю требует paramiko: python -m pip install paramiko "
                       "(в собранном exe он уже внутри)")
    return OpenSSHSSH(host, port, user, key_path=key_path)


def test_connection(ssh: BaseSSH) -> str:
    code, out, err = ssh.run("id", timeout=12)
    if code != 0:
        raise SSHError(err.strip() or out.strip() or f"ssh exited with {code}")
    return out.strip()
