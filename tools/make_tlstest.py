"""Поднимает на полигоне HTTPS-сервис, чтобы проверить TLS-детект в liveness."""
import base64
import sys

sys.stdout.reconfigure(encoding="utf-8")

from adkit import ssh as S

KEY = r"sim\keys\ad_lab"

SERVER = b"""
import http.server, ssl
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain('/srv/tlstest/cert.pem', '/srv/tlstest/key.pem')
httpd = http.server.HTTPServer(('0.0.0.0', 8443), http.server.SimpleHTTPRequestHandler)
httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
httpd.serve_forever()
"""

client = S.OpenSSHSSH("127.0.0.1", 2222, "root", KEY)

print("openssl:", client.run("command -v openssl || echo none")[1].strip())
client.run("mkdir -p /srv/tlstest")
client.run(
    "cd /srv/tlstest && [ -f cert.pem ] || "
    "openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem "
    "-days 2 -subj /CN=ad-lab >/dev/null 2>&1"
)
encoded = base64.b64encode(SERVER).decode()
client.run(f"echo {encoded} | base64 -d > /srv/tlstest/srv.py")
client.run("pkill -f tlstest/srv.py || true")
client.run("cd /srv/tlstest && nohup python3 srv.py >/dev/null 2>&1 & sleep 1")
code, out, err = client.run("ss -lntp | grep 8443 | head -2")
print("listen:", code, out.strip())
client.close()
