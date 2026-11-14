"""Проверяет повтор SSH-команды при обрыве соединения."""
import subprocess
import sys

sys.stdout.reconfigure(encoding="utf-8")

from adkit import ssh as S

KEY = "sim/keys/ad_lab"
real = subprocess.run
calls = {"n": 0}


class Fake:
    returncode = 255
    stdout = b""
    stderr = b"banner exchange: Connection to UNKNOWN port -1: Connection refused"


def fake(args, **kw):
    calls["n"] += 1
    if calls["n"] <= 2:
        return Fake()
    return real(args, **kw)


S.subprocess.run = fake
client = S.OpenSSHSSH("127.0.0.1", 2222, "root", KEY)
code, out, err = client.run("id")
print("retry: rc=%d calls=%d out=%s" % (code, calls["n"], out.strip()[:40]))
ok_retry = code == 0 and calls["n"] == 3

calls["n"] = 0


def always_fail(args, **kw):
    calls["n"] += 1
    return Fake()


S.subprocess.run = always_fail
code, out, err = S.OpenSSHSSH("127.0.0.1", 2222, "root", KEY).run("id")
print("dead:  rc=%d calls=%d" % (code, calls["n"]))
ok_dead = code == 255 and calls["n"] == S.RETRIES

S.subprocess.run = real
code, out, err = S.OpenSSHSSH("127.0.0.1", 2222, "root", KEY).run("hostname")
print("live:  rc=%d out=%s" % (code, out.strip()[:40]))

print("PASS" if ok_retry and ok_dead else "FAIL")
