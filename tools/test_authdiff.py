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
        elif path.startswith("/bola-open/"):
            self.answer(200, BODY)
        elif path.startswith("/bola-closed/"):
            if "session=a" in cookie:
                self.answer(200, BODY)
            else:
                self.answer(404, "not found")
        elif path.startswith("/bola-other/"):
            who = "a" if "session=a" in cookie else "b"
            self.answer(200, f"<html><body>object of {who}</body></html>")
        else:
            self.answer(404, "none")

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        path = self.path.split("?")[0]
        if path == "/mass":
            self.answer(200, '{"ok":true,"role":"admin"}' if b"role" in body else '{"ok":true}')
        else:
            self.answer(405, "no")

    def answer(self, status, text):
        payload = text.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


def check(title: str, ok: bool, detail: str = "") -> int:
    print(f"{'ok' if ok else 'FAIL':>4} {title}{(' — ' + detail) if detail else ''}")
    return 0 if ok else 1


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

    # Пара «два аккаунта»: объект, закрытый владельцем, объект, открытый всем,
    # и маршрут, который отвечает обоим разным содержимым.
    bola_cases = [
        ("/bola-open/1", "shared", "объект виден обоим"),
        ("/bola-closed/1", "isolated", "объект закрыт владельцем"),
        ("/bola-other/1", "other", "объекты разные"),
        ("/bola-closed/1", "no-access", "A без сессии — доказывать нечего", None),
    ]
    for case in bola_cases:
        path, expected, title = case[0], case[1], case[2]
        cookie_a = case[3] if len(case) > 3 else "session=a"
        row = probe.bola_diff(base, path, opener, cookie_a, "session=b")
        ok = row["verdict"] == expected
        if not ok:
            failed += 1
        print(f"{'ok' if ok else 'FAIL':>4} {path:<16} {title:<30} -> {row['verdict']}")

    # POST: без флага не отправляется, с флагом уходит ровно один POST.
    mass = {"kind": "Mass assignment", "param": "role"}
    quiet = probe.build_requests(mass, "/mass", 80, allow_post=False)
    loud = probe.build_requests(mass, "/mass", 80, allow_post=True)
    failed += check("POST молчит без флага", quiet == [], f"{len(quiet)} запросов")
    failed += check("POST появился с флагом", len(loud) == 3, f"{len(loud)} запросов")

    probe.BUDGET.capacity = 200
    posted = probe.run(base, loud[:1], delay=0.1, cookie="session=a", allow_post=True)
    row = (posted.get("results") or [{}])[0]
    failed += check("POST ушёл методом POST", row.get("method") == "POST", str(row.get("method")))
    failed += check("тело POST дошло", row.get("status") == 200 and row.get("verdict") in {"diff", "clean"},
                    f"{row.get('status')} {row.get('verdict')}")

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
    total = len(cases) + len(bola_cases) + 4 + len(checks)
    print(f"\n{'пройдено' if failed == 0 else 'провалено'}: {total - failed}/{total}")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
