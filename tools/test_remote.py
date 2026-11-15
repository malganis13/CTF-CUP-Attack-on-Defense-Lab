"""Службы на цели и смена пароля: разбор, права, отсутствие утечки пароля.

Проверка на подставном SSH: живого полигона для теста не требуется. Отдельно
проверяется главное свойство смены пароля — он уходит в stdin, а не в командную
строку, и не попадает в ответ ssh.
"""
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from adkit import remote

FAILED = 0


def check(title: str, ok: bool, detail: str = "") -> None:
    global FAILED
    if not ok:
        FAILED += 1
    print(f"{'ok' if ok else 'FAIL':>4} {title}{(' — ' + detail) if detail else ''}")


SCRIPT_OUT = """__SS__
State  Recv-Q Send-Q Local Address:Port Peer Address:PortProcess
LISTEN 0      128          0.0.0.0:8081      0.0.0.0:*    users:(("python3",pid=147,fd=3))
LISTEN 0      128             [::]:8081         [::]:*    users:(("python3",pid=147,fd=4))
LISTEN 0      128          0.0.0.0:2222      0.0.0.0:*    users:(("sshd",pid=194,fd=6))
__UNITS__
ad-notes.service loaded active running notes service
ssh.service loaded active running OpenSSH server
__SHOW__
Id=ad-notes.service
MainPID=147
WorkingDirectory=/srv/notes

Id=ssh.service
MainPID=194
WorkingDirectory=/
__DIRS__
/srv/notes
/srv/archive
__CWD__
147\t/srv/notes
194\t/
__DOCKER__
__SSHD__
PermitRootLogin prohibit-password
PasswordAuthentication yes
"""

DEGRADED_OUT = """__SS__
State  Recv-Q Send-Q Local Address:Port Peer Address:PortProcess
LISTEN 0 128 0.0.0.0:8081 0.0.0.0:*
__UNITS__
__SHOW__
__DIRS__
__CWD__
__DOCKER__
__SSHD__
"""


class FakeSSH:
    host = "10.0.0.5"

    def __init__(self, responses=None, uid="0"):
        self.responses = responses or []
        self.uid = uid
        self.calls: list[tuple[str, str | None]] = []

    def run(self, command: str, timeout: int = 30, stdin: str | None = None):
        self.calls.append((command, stdin))
        if command.strip() == "id -u":
            return 0, self.uid + "\n", ""
        for needle, answer in self.responses:
            if needle in command:
                return answer
        return 0, "", ""

    def label(self) -> str:
        return f"root@{self.host}:2222 (fake)"


def main() -> int:
    fake = FakeSSH([("__SS__", (0, SCRIPT_OUT, ""))])
    data = remote.services(fake)
    rows = {row["port"]: row for row in data["rows"]}
    check("службы прочитаны", len(rows) == 2, str(len(rows)))
    check("юнит найден по pid", rows.get(8081, {}).get("unit") == "ad-notes.service",
          str(rows.get(8081)))
    check("имя взято из юнита", rows.get(8081, {}).get("name") == "notes")
    check("каталог найден", rows.get(8081, {}).get("cwd") == "/srv/notes")
    check("дубль [::] схлопнут", sum(1 for row in data["rows"] if row["port"] == 8081) == 1)
    check("политика sshd разобрана",
          data["policy"].get("permitrootlogin") == "prohibit-password", str(data["policy"]))
    check("каталоги сервисов перечислены", "/srv/archive" in data["dirs"])

    degraded = FakeSSH([("sudo -n sh -c", (0, "", "")), ("__SS__", (0, DEGRADED_OUT, ""))],
                       uid="1001")
    data = remote.services(degraded)
    check("без root строки всё равно есть", len(data["rows"]) == 1)
    check("без root есть пометка", "не root" in data.get("note", ""), data.get("note", "")[:40])

    ssh = FakeSSH([("id -u 'bob'", (0, "1002\n", "")), ("chpasswd", (0, "", ""))])
    result = remote.rotate_password(ssh, "bob", "Secret123")
    check("пароль сменён", result.get("ok") is True and result.get("user") == "bob")
    sent = [(cmd, stdin) for cmd, stdin in ssh.calls if "chpasswd" in cmd]
    check("chpasswd получил пароль по stdin", sent and sent[-1][1] == "bob:Secret123\n",
          str(sent[-1][1] if sent else None))
    check("в команде нет пароля", all("Secret123" not in cmd for cmd, _ in ssh.calls))

    sudo = FakeSSH([
        ("id -u 'bob'", (0, "1002\n", "")),
        ("sudo -n chpasswd", (0, "", "")),
        ("chpasswd", (1, "", "chpasswd: Permission denied.")),
    ])
    result = remote.rotate_password(sudo, "bob", "Secret123")
    check("без root сработал sudo без пароля", result.get("ok") is True)

    denied = FakeSSH([
        ("id -u 'bob'", (0, "1002\n", "")),
        ("sudo -n chpasswd", (1, "", "sudo: a password is required")),
        ("chpasswd", (1, "", "chpasswd: Permission denied.")),
    ])
    try:
        remote.rotate_password(denied, "bob", "Secret123")
        check("отказ без прав объяснён", False)
    except remote.RemoteError as exc:
        check("отказ без прав объяснён", "root" in str(exc), str(exc))

    for bad_user in ("root; rm -rf /", "Bob", "a b"):
        try:
            remote.rotate_password(FakeSSH(), bad_user, "Secret123")
            check(f"имя отклонено: {bad_user}", False)
        except remote.RemoteError:
            check(f"имя отклонено: {bad_user}", True)

    try:
        remote.rotate_password(FakeSSH(), "bob", "123")
        check("короткий пароль отклонён", False)
    except remote.RemoteError:
        check("короткий пароль отклонён", True)

    secret = remote.generate_password()
    check("генератор даёт 20 символов", len(secret) == 20, str(len(secret)))
    check("генератор без похожих символов", not set(secret) & set("0O1lI"),
          "".join(sorted(set(secret) & set("0O1lI"))))

    total = 20
    print(f"\n{'пройдено' if FAILED == 0 else 'провалено'}: {total - FAILED}/{total}")
    return 0 if FAILED == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
