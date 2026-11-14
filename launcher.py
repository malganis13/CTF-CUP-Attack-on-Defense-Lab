#!/usr/bin/env python3
"""Точка входа приложения: поднимает сервер и открывает браузер.

    python launcher.py             # обычный запуск
    python launcher.py --demo      # с демо-данными, без SSH

Собрано в exe (Windows) или запущено из .desktop (Linux) — ведёт себя
одинаково: окно консоли не нужно, браузер открывается сам, порт выбирается
свободный, второй экземпляр не плодится.
"""
from __future__ import annotations

import argparse
import socket
import threading
import time
import urllib.request
import webbrowser

import app


def port_free(port: int) -> bool:
    with socket.socket() as sock:
        sock.settimeout(0.4)
        return sock.connect_ex(("127.0.0.1", port)) != 0


def ours(port: int) -> bool:
    """На порту уже живёт наш сервер?"""
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/state", timeout=0.8) as response:  # noqa: S310
            body = response.read(400).decode("utf-8", "replace")
            return '"version"' in body
    except Exception:  # noqa: BLE001
        return False


def pick_port(preferred: int = 8765, span: int = 12) -> tuple[int, bool]:
    """(порт, уже_запущено)."""
    for offset in range(span):
        port = preferred + offset
        if ours(port):
            return port, True
        if port_free(port):
            return port, False
    raise SystemExit("нет свободного порта в диапазоне 8765–8776")


def main() -> int:
    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--demo", action="store_true")
    parser.add_argument("--no-browser", action="store_true")
    args = parser.parse_args()

    port, running = pick_port(args.port)
    url = f"http://127.0.0.1:{port}/"

    if running:
        if not args.no_browser:
            webbrowser.open(url)
        return 0

    server = app.build_server("127.0.0.1", port, args.demo)
    worker = threading.Thread(target=server.serve_forever, name="ad-audit", daemon=True)
    worker.start()

    if not args.no_browser:
        threading.Thread(target=lambda: (time.sleep(0.4), webbrowser.open(url)), daemon=True).start()

    try:
        while not app.SHUTDOWN.wait(0.5):
            if not worker.is_alive():
                break
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
