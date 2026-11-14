"""Регрессия пары «без сессии / с сессией».

Поднимает три маршрута и проверяет, что вердикт соответствует тому, как
маршрут написан: открытый — open, с проверкой — guarded, страница входа с
кодом 200 — guarded, а не «доступ».
"""
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from adkit import probe

BODY = "<html><body>" + ("<p>note line</p>" * 40) + "</body></html>"
LOGIN = '<html><body><form><input type="password" name="password"><button>sign in</button></form></body></html>'


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        return

    def do_GET(self):
        cookie = self.headers.get("Cookie", "")
        path = self.path.split("?")[0]
        if path == "/open":
            self.answer(200, BODY)
        elif path == "/guarded":
            if "session=abc" in cookie:
                self.answer(200, BODY)
            else:
                self.answer(401, "unauthorized")
        elif path == "/login":
            self.answer(200, LOGIN)
        elif path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/login")
            self.send_header("Content-Length", "0")
            self.end_headers()
        else:
            self.answer(404, "none")

    def answer(self, status, text):
        payload = text.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


def main() -> int:
    server = HTTPServer(("127.0.0.1", 0), Handler)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{port}"
    opener = probe._opener()

    cases = [
        ("/open", None, "open"),
        ("/open", "session=abc", "open"),
        ("/guarded", None, "guarded"),
        ("/guarded", "session=abc", "guarded"),
        ("/login", None, "guarded"),
        ("/redirect", None, "guarded"),
    ]

    failed = 0
    for path, cookie, expected in cases:
        row = probe.auth_diff(base, path, opener, cookie=cookie)
        mark = "ok" if row["verdict"] == expected else "FAIL"
        if mark == "FAIL":
            failed += 1
        label = f"{path:<10} cookie={'yes' if cookie else 'no ':<3}"
        print(f"{mark:>4} {label} -> {row['verdict']:<8} {row['evidence'][:70]}")

    # Интеграция: один GET через run(), auth-пара должна попасть в результат
    # и списаться из бюджета вместе с полезной нагрузкой.
    probe.BUDGET.capacity = 100
    finding = {"kind": "SQL injection", "param": "q"}
    result = probe.run(base, [{"label": "quote", "path": "/open?q='", "marker": None}],
                       delay=0.1, cookie="session=abc")
    auth = result.get("auth") or {}
    checks = [
        ("auth в результате", bool(auth)),
        ("вердикт open", auth.get("verdict") == "open"),
        ("в summary есть auth", result["summary"].get("auth") == "open"),
        ("бюджет потрачен", probe.BUDGET.peek()["used"] >= 4),
    ]
    for title, ok in checks:
        print(f"{'ok' if ok else 'FAIL':>4} {title}")
        if not ok:
            failed += 1

    server.shutdown()
    print(f"\n{'пройдено' if failed == 0 else 'провалено'}: {len(cases) + len(checks) - failed}/{len(cases) + len(checks)}")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
