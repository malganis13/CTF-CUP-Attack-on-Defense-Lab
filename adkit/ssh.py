"""SSH backends.

Paramiko is used when installed (password or key). Otherwise the system
OpenSSH client is used with a key or an agent. The audit itself only needs
read-only commands and file reads.
"""
from __future__ import annotations

import shlex
import stat
import subprocess
from pathlib import Path

try:
    import paramiko
except Exception:  # pragma: no cover - optional dependency
    paramiko = None


class SSHError(RuntimeError):
    """Raised when a connection or a remote read fails."""


class BaseSSH:
    def run(self, command: str, timeout: int = 30) -> tuple[int, str, str]:
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
                 key_path: str | None = None, passphrase: str | None = None) -> None:
        self.host = host
        self.port = port
        self.user = user
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
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
            allow_agent=True,
            look_for_keys=True,
        )

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

    def run(self, command: str, timeout: int = 30) -> tuple[int, str, str]:
        try:
            _, stdout, stderr = self.client.exec_command(command, timeout=timeout)
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

    def run(self, command: str, timeout: int = 30) -> tuple[int, str, str]:
        try:
            proc = subprocess.run(self._base() + [command], capture_output=True, timeout=timeout)
        except FileNotFoundError as exc:
            raise SSHError("OpenSSH client not found in PATH") from exc
        except subprocess.TimeoutExpired as exc:
            raise SSHError(f"ssh timed out after {timeout}s") from exc
        return (
            proc.returncode,
            proc.stdout.decode("utf-8", "replace"),
            proc.stderr.decode("utf-8", "replace"),
        )

    def read_file(self, path: str, max_bytes: int = 262144) -> bytes:
        command = f"head -c {int(max_bytes)} -- {shlex.quote(path)}"
        try:
            proc = subprocess.run(self._base() + [command], capture_output=True, timeout=30)
        except subprocess.TimeoutExpired as exc:
            raise SSHError(f"read timed out: {path}") from exc
        if proc.returncode != 0 and not proc.stdout:
            raise SSHError(proc.stderr.decode("utf-8", "replace").strip() or f"read failed: {path}")
        return proc.stdout

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


def backend_name() -> str:
    return "paramiko" if paramiko is not None else "openssh"


def connect(target: dict, password: str | None = None) -> BaseSSH:
    host = (target.get("host") or "").strip()
    user = (target.get("user") or "").strip()
    if not host or not user:
        raise SSHError("host and user are required")
    port = int(target.get("port") or 22)
    key_path = (target.get("key_path") or "").strip() or None
    passphrase = target.get("passphrase") or None
    if paramiko is not None:
        return ParamikoSSH(host, port, user, password=password, key_path=key_path, passphrase=passphrase)
    if password:
        raise SSHError("password auth needs paramiko; install it or use a key")
    return OpenSSHSSH(host, port, user, key_path=key_path)


def test_connection(ssh: BaseSSH) -> str:
    code, out, err = ssh.run("id", timeout=12)
    if code != 0:
        raise SSHError(err.strip() or out.strip() or f"ssh exited with {code}")
    return out.strip()
