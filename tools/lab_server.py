#!/usr/bin/env python3
"""Лаборатория для проверки проб: намеренно уязвимый сервер на stdlib.

Поднимает HTTP-сервер с шестью ручками: пять уязвимых и одна чистая.
Нужен, чтобы проверить, что проба действительно находит сигнал, а не просто
делает GET. Ничего не импортирует из проекта, запускается где угодно:

    python tools/lab_server.py --port 9300

Каждый запрос пишется в журнал; тест проверяет, что проба ни разу не
обратилась к /_checker/*.
"""
from __future__ import annotations

import argparse
import sys
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HITS: list[str] = []
STAMPS: list[float] = []

FLAG = "ctfcup{lab_flag_do_not_submit}"


class LabHandler(BaseHTTPRequestHandler):
    server_version = "ADLab/1.0"

    def log_message(self, *args) -> None:  # тихо
        pass

    def _send(self, status: int, body: str, headers: dict | None = None) -> None:
        payload = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:  # noqa: N802
        HITS.append(self.path)
        STAMPS.append(time.monotonic())
        parsed = urllib.parse.urlparse(self.path)
        query = urllib.parse.parse_qs(parsed.query)
        path = parsed.path

        if path == "/clean":
            self._send(200, "ok: nothing to see")
            return

        if path == "/sqli":
            value = query.get("id", [""])[0]
            if "'" in value or '"' in value or "\\" in value:
                self._send(500, "sqlite3.OperationalError: unrecognized token: \"'\"")
            else:
                self._send(200, "row 1: note")
            return

        if path == "/file":
            name = query.get("name", [""])[0]
            if ".." in name or name.startswith("/etc/"):
                self._send(200, "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin")
            else:
                self._send(200, "readme contents")
            return

        if path == "/ping":
            host = query.get("host", [""])[0]
            if any(token in host for token in (";", "|", "$(", "`")):
                self._send(200, "PING ok\nuid=0(root) gid=0(root) groups=0(root)")
            else:
                self._send(200, "PING ok")
            return

        if path == "/render":
            name = query.get("name", [""])[0]
            if "{{7*7}}" in name or "<%= 7*7 %>" in name or "#{7*7}" in name or "${7*7}" in name:
                self._send(200, "Hello 49")
            else:
                self._send(200, "Hello guest")
            return

        if path == "/go":
            target = query.get("next", ["/"])[0]
            if target.startswith("//") or target.startswith("http"):
                self._send(302, "redirecting", {"Location": target})
            else:
                self._send(200, "home")
            return

        if path.startswith("/_checker"):
            self._send(200, FLAG)
            return

        self._send(404, "not found")


def start(port: int = 0) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer(("127.0.0.1", port), LabHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def main() -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=9300)
    args = parser.parse_args()
    server = ThreadingHTTPServer(("127.0.0.1", args.port), LabHandler)
    print(f"lab on http://127.0.0.1:{args.port}")
    print("  /sqli?id=1   /file?name=readme   /ping?host=x")
    print("  /render?name=x   /go?next=/   /clean?q=x")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
