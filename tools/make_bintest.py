"""Кладёт на полигон тестовый ELF-файл со строками system/strcpy/флаг."""
import base64
import sys

sys.stdout.reconfigure(encoding="utf-8")

from adkit import ssh as S

KEY = r"sim\keys\ad_lab"

payload = (
    b"\x7fELF\x02\x01\x01" + bytes(40)
    + b"/bin/sh\x00system\x00strcpy\x00note=CTF{deadbeef}\x00"
)
encoded = base64.b64encode(payload).decode()

client = S.OpenSSHSSH("127.0.0.1", 2222, "root", KEY)
print(client.run("mkdir -p /srv/bintest")[0])
code, out, err = client.run(
    f"echo {encoded} | base64 -d > /srv/bintest/runner && chmod +x /srv/bintest/runner && ls -la /srv/bintest"
)
print(code, out.strip(), err.strip()[:120])
client.close()
