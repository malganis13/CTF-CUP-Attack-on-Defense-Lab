#!/usr/bin/env python3
"""AD Audit — local, read-only Attack-Defense service auditor.

Run:
    python app.py                # normal mode, http://127.0.0.1:8765
    python app.py --demo         # UI with a canned audit, no SSH

The server binds 127.0.0.1 only. It never writes to the target, never restarts
services and never sends requests to the checker.
"""
from __future__ import annotations

import argparse
import json
import mimetypes
import secrets
import sys
import threading
import time
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from adkit import __version__, fixes, patterns, probe
from adkit.audit import Audit, analyze_sources
from adkit.generate import generate_probe, generate_report, pick_endpoint
from adkit.ratelimit import BUDGET
from adkit.ssh import SSHError, backend_name, connect, test_connection

def _resource_base() -> Path:
    """Каталог с web/, knowledge/, demo/ — внутри exe или рядом с исходником."""
    frozen = getattr(sys, "frozen", False)
    if frozen:
        return Path(getattr(sys, "_MEIPASS", Path(sys.executable).resolve().parent))
    return Path(__file__).resolve().parent


def _data_base() -> Path:
    """Каталог, куда можно писать: config.json рядом с exe, не во временной распаковке."""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


BASE = _data_base()
RES = _resource_base()
WEB = RES / "web"
KNOWLEDGE = RES / "knowledge"
CONFIG_PATH = BASE / "config.json"
DEMO_AUDIT = RES / "demo" / "audit.json"
DEMO_SRC = RES / "demo" / "src"

DEFAULT_CONFIG = {
    "target": {
        "host": "",
        "port": 22,
        "user": "root",
        "auth": "key",
        "key_path": "",
    },
    "audit": {
        "max_files": 300,
        "max_file_bytes": 262144,
    },
}

SESSION: dict = {
    "config": json.loads(json.dumps(DEFAULT_CONFIG)),
    "password": None,
    "last_audit": None,
    "demo": False,
}
JOBS: dict[str, dict] = {}
SHUTDOWN = threading.Event()


def load_config() -> dict:
    if CONFIG_PATH.is_file():
        try:
            data = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            data = {}
        merged = json.loads(json.dumps(DEFAULT_CONFIG))
        for key, value in data.items():
            if isinstance(value, dict) and isinstance(merged.get(key), dict):
                merged[key].update(value)
            else:
                merged[key] = value
        return merged
    return json.loads(json.dumps(DEFAULT_CONFIG))


def save_config(config: dict) -> None:
    public = json.loads(json.dumps(config))
    public.get("target", {}).pop("password", None)
    CONFIG_PATH.write_text(json.dumps(public, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def public_state() -> dict:
    target = SESSION["config"].get("target", {})
    return {
        "version": __version__,
        "backend": backend_name(),
        "demo": SESSION["demo"],
        "target": target,
        "has_password": bool(SESSION.get("password")),
        "has_audit": SESSION.get("last_audit") is not None,
        "rules": len(patterns.RULES),
        "budget": probe.BUDGET.peek(),
    }


def start_job(kind: str, function) -> str:
    job_id = secrets.token_hex(6)
    JOBS[job_id] = {"id": job_id, "kind": kind, "status": "running", "log": [], "result": None, "error": None}

    def log(message: str) -> None:
        JOBS[job_id]["log"].append(message)

    def worker() -> None:
        try:
            result = function(log)
            JOBS[job_id]["result"] = result
            if kind == "audit" and isinstance(result, dict):
                SESSION["last_audit"] = result
            JOBS[job_id]["status"] = "done"
        except Exception as exc:  # noqa: BLE001 - surfaced to the UI
            JOBS[job_id]["error"] = f"{type(exc).__name__}: {exc}"
            JOBS[job_id]["status"] = "error"

    threading.Thread(target=worker, daemon=True).start()
    return job_id


def demo_audit() -> dict:
    if not DEMO_AUDIT.is_file():
        raise RuntimeError("demo/audit.json missing; run tools/build_demo.py")
    return json.loads(DEMO_AUDIT.read_text(encoding="utf-8"))


def demo_resolve(path: str) -> Path | None:
    """Map an audit path such as /srv/notes/app.py onto demo/src/notes/app.py."""
    if not DEMO_SRC.is_dir():
        return None
    root = DEMO_SRC.resolve()
    raw = (path or "/").strip().lstrip("/")
    candidates: list[Path] = [DEMO_SRC] if not raw else [DEMO_SRC / raw]
    for prefix in ("srv", "opt", "app", "data", "var/www", "home/ctf"):
        if raw == prefix:
            candidates.append(DEMO_SRC)
        elif raw.startswith(prefix + "/"):
            candidates.append(DEMO_SRC / raw[len(prefix) + 1:])
    for candidate in candidates:
        try:
            resolved = candidate.resolve()
        except OSError:
            continue
        if (resolved == root or root in resolved.parents) and (resolved.is_dir() or resolved.is_file()):
            return resolved
    name = Path(path).name
    if name and name not in {".", ".."}:
        hits = [item for item in DEMO_SRC.rglob(name) if item.is_file()]
        if len(hits) == 1:
            return hits[0]
    return None


class Handler(BaseHTTPRequestHandler):
    server_version = "ADAudit/1.0"

    def log_message(self, fmt: str, *args) -> None:  # noqa: A003
        print(f"[ad-audit] {self.address_string()} {fmt % args}")

    def send_json(self, status: int, body) -> None:
        payload = json.dumps(body, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(payload)

    def send_text(self, status: int, text: str, content_type: str = "text/plain; charset=utf-8") -> None:
        payload = text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(payload)

    def body(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        if length > 1_000_000:
            raise ValueError("body too large")
        raw = self.rfile.read(length) if length else b"{}"
        data = json.loads(raw.decode("utf-8"))
        return data if isinstance(data, dict) else {}

    def serve_web(self, name: str) -> None:
        filename = Path(name).name
        path = WEB / filename
        if not filename or not path.is_file():
            self.send_text(404, "not found")
            return
        data = path.read_bytes()
        content_type = mimetypes.guess_type(str(path))[0] or "application/octet-stream"
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)
        try:
            if path == "/":
                self.serve_web("index.html")
            elif path.startswith("/web/"):
                self.serve_web(path[len("/web/"):])
            elif path == "/api/health":
                self.send_json(200, {"status": "ok", "version": __version__, "backend": backend_name(), "demo": SESSION["demo"]})
            elif path == "/api/state":
                self.send_json(200, public_state())
            elif path == "/api/patterns":
                self.send_json(200, {"rules": patterns.rule_catalog(), "coverage": patterns.coverage_matrix()})
            elif path == "/api/knowledge":
                items = []
                for file in sorted(KNOWLEDGE.glob("*.md")) if KNOWLEDGE.is_dir() else []:
                    items.append({"name": file.stem, "text": file.read_text(encoding="utf-8", errors="replace")})
                self.send_json(200, {"items": items})
            elif path == "/api/job":
                job = JOBS.get(query.get("id", [""])[0])
                if not job:
                    self.send_json(404, {"error": "job not found"})
                else:
                    self.send_json(200, job)
            elif path == "/api/files":
                self.handle_files(query.get("path", ["/"])[0])
            elif path == "/api/file":
                self.handle_file(query.get("path", [""])[0])
            elif path == "/api/fix":
                self.handle_fix(query.get("id", [""])[0])
            elif path == "/api/traffic":
                self.send_json(200, traffic_profile())
            elif path == "/api/demo":
                self.send_json(200, demo_audit())
            elif path == "/api/last":
                audit = SESSION.get("last_audit")
                if audit is None:
                    self.send_json(404, {"error": "no audit yet"})
                else:
                    self.send_json(200, audit)
            else:
                self.send_json(404, {"error": "not found"})
        except Exception as exc:  # noqa: BLE001 - surfaced to the UI
            self.send_json(500, {"error": f"{type(exc).__name__}: {exc}"})

    def do_POST(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        try:
            body = self.body()
            if path == "/api/config":
                target = body.get("target") or {}
                current = SESSION["config"].setdefault("target", {})
                for key in ("host", "port", "user", "auth", "key_path"):
                    if key in target:
                        current[key] = target[key]
                if "password" in body:
                    SESSION["password"] = body.get("password") or None
                save_config(SESSION["config"])
                self.send_json(200, {"ok": True, "state": public_state()})
            elif path == "/api/test":
                if SESSION["demo"]:
                    self.send_json(200, {"ok": True, "output": "demo mode", "backend": "demo"})
                    return
                target = SESSION["config"].get("target", {})
                ssh = connect(target, SESSION.get("password"))
                try:
                    output = test_connection(ssh)
                finally:
                    ssh.close()
                self.send_json(200, {"ok": True, "output": output, "backend": backend_name()})
            elif path == "/api/audit":
                if SESSION["demo"]:
                    self.send_json(200, {"job": start_job("audit", lambda log: demo_audit())})
                    return
                target = SESSION["config"].get("target", {})
                if not target.get("host") or not target.get("user"):
                    self.send_json(400, {"error": "host and user are required"})
                    return
                password = SESSION.get("password")

                def run(log):
                    ssh = connect(target, password)
                    try:
                        log(f"connected: {ssh.label()}")
                        return Audit(ssh, log).run()
                    finally:
                        ssh.close()

                self.send_json(200, {"job": start_job("audit", run)})
            elif path == "/api/generate":
                audit = SESSION.get("last_audit")
                if not audit:
                    self.send_json(400, {"error": "run an audit first"})
                    return
                finding_id = body.get("id", "")
                finding = next((item for item in audit.get("findings", []) if item.get("id") == finding_id), None)
                if not finding:
                    self.send_json(404, {"error": "finding not found"})
                    return
                service = body.get("service") or "service"
                endpoint = body.get("endpoint") or None
                port = int(body.get("port") or 80)
                self.send_json(200, generate_probe(finding, service, endpoint, port, audit.get("endpoints")))
            elif path == "/api/probe":
                audit = SESSION.get("last_audit")
                if not audit:
                    self.send_json(400, {"error": "run an audit first"})
                    return
                finding_id = body.get("id", "")
                finding = next((item for item in audit.get("findings", []) if item.get("id") == finding_id), None)
                if not finding:
                    self.send_json(404, {"error": "finding not found"})
                    return
                port = int(body.get("port") or 80)
                endpoint = body.get("endpoint") or pick_endpoint(finding, audit.get("endpoints"))
                base = (body.get("base") or "").strip()
                if not base:
                    host = SESSION["config"].get("target", {}).get("host") or "127.0.0.1"
                    base = f"http://{host}:{port}"
                result = probe.run_for(finding, endpoint, base, port)
                result["budget"] = probe.BUDGET.peek()
                self.send_json(200, result)
            elif path == "/api/report":
                audit = SESSION.get("last_audit")
                if not audit:
                    self.send_json(400, {"error": "run an audit first"})
                    return
                self.send_json(200, {"markdown": generate_report(audit)})
            elif path == "/api/shutdown":
                self.send_json(200, {"stopping": True})
                SHUTDOWN.set()
            else:
                self.send_json(404, {"error": "not found"})
        except probe.BudgetExhausted as exc:
            self.send_json(429, {
                "error": f"бюджет запросов исчерпан, повтор через {int(exc.retry_after) + 1} с",
                "retry_after": round(exc.retry_after, 1),
            })
        except SSHError as exc:
            self.send_json(502, {"error": str(exc)})
        except Exception as exc:  # noqa: BLE001 - surfaced to the UI
            self.send_json(500, {"error": f"{type(exc).__name__}: {exc}"})

    @staticmethod
    def is_checker_path(path: str) -> bool:
        parts = [part for part in path.split("/") if part]
        return "_checker" in parts

    def handle_files(self, path: str) -> None:
        if not path.startswith("/"):
            self.send_json(400, {"error": "absolute path required"})
            return
        if self.is_checker_path(path):
            self.send_json(403, {"error": "каталог чекера не читается: /_checker/* вне зоны аудита"})
            return
        if SESSION["demo"]:
            resolved = demo_resolve(path)
            entries = []
            if resolved is not None and resolved.is_dir():
                for file in sorted(resolved.iterdir(), key=lambda p: (p.is_file(), p.name)):
                    entries.append({
                        "name": file.name,
                        "type": "dir" if file.is_dir() else "file",
                        "size": file.stat().st_size,
                        "mtime": int(file.stat().st_mtime),
                    })
            self.send_json(200, {"path": path, "entries": entries})
            return
        target = SESSION["config"].get("target", {})
        ssh = connect(target, SESSION.get("password"))
        try:
            entries = ssh.list_dir(path)
        finally:
            ssh.close()
        self.send_json(200, {"path": path, "entries": entries})

    def handle_file(self, path: str) -> None:
        if not path:
            self.send_json(400, {"error": "path required"})
            return
        if self.is_checker_path(path):
            self.send_json(403, {"error": "файлы чекера не читаются: /_checker/* вне зоны аудита"})
            return
        resolved: Path | None = None
        if SESSION["demo"]:
            resolved = demo_resolve(path)
            data = resolved.read_bytes()[:262144] if resolved and resolved.is_file() else b""
        else:
            target = SESSION["config"].get("target", {})
            ssh = connect(target, SESSION.get("password"))
            try:
                data = ssh.read_file(path)
            finally:
                ssh.close()
        shown = str(resolved) if resolved is not None else path
        if b"\x00" in data[:4096]:
            self.send_json(200, {"path": shown, "binary": True, "findings": [], "lines": []})
            return
        text = data.decode("utf-8", "replace")
        self.send_json(200, {
            "path": shown,
            "binary": False,
            "text": text,
            "lines": text.splitlines(),
            "findings": patterns.scan_text(path, text),
            "truncated": len(data) >= 262144,
        })


    def handle_fix(self, finding_id: str) -> None:
        audit = SESSION.get("last_audit") or {}
        finding = next((item for item in audit.get("findings", []) if item.get("id") == finding_id), None)
        if finding is None:
            self.send_json(404, {"error": "находка не найдена — перезапустите аудит"})
            return
        fix = fixes.build_fix(finding.get("rule", ""), finding.get("language", "any"), finding.get("snippet", ""))
        self.send_json(200, {
            "finding": {
                "id": finding.get("id"),
                "kind": finding.get("kind"),
                "file": finding.get("file"),
                "line": finding.get("line"),
                "severity": finding.get("severity"),
            },
            "fix": fix,
        })


def traffic_profile() -> dict:
    """Профиль трафика инструмента — доказательство, что это не флуд."""
    events = list(probe.JOURNAL)
    now = time.time()
    last_minute = [event for event in events if now - event.get("at", 0) <= 60]
    sends = [event for event in events if event.get("status") is not None]
    bytes_total = sum(event.get("bytes", 0) for event in sends)
    ms_values = [event.get("ms", 0) for event in sends if event.get("ms")]
    statuses: dict[str, int] = {}
    for event in sends:
        key = str(event.get("status", 0))
        statuses[key] = statuses.get(key, 0) + 1

    capacity = BUDGET.capacity
    window = BUDGET.window

    return {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "events": events[-200:],
        "summary": {
            "total": len(events),
            "last_minute": len(last_minute),
            "bytes": bytes_total,
            "avg_bytes": round(bytes_total / max(1, len(sends))),
            "avg_ms": round(sum(ms_values) / max(1, len(ms_values))),
            "statuses": statuses,
        },
        "caps": {
            "max_requests_per_probe": probe.MAX_REQUESTS,
            "baseline_requests": 1,
            "min_delay_s": probe.MIN_DELAY,
            "timeout_s": probe.TIMEOUT,
            "max_body_bytes": probe.MAX_BODY,
            "budget_capacity": capacity,
            "budget_window_s": window,
            "checker_paths_blocked": list(probe.BLOCKED),
        },
        "claims": [
            f"не больше {probe.MAX_REQUESTS} GET на пробу, плюс один базовый запрос для сравнения",
            f"пауза между запросами не меньше {probe.MIN_DELAY:.2f} с — это меньше 10 запросов в секунду на пробу",
            f"общий бюджет процесса: {capacity} запросов за {window} с, списывается до отправки",
            "только GET без тела; POST не отправляется, изменения состояния — только заготовкой вручную",
            "ответ читается не больше 64 КБ, редиректы не переходятся, id не перебираются",
            "пути /_checker/* блокируются до отправки и в журнал попадают как blocked",
        ],
    }


def build_server(host: str, port: int, demo: bool = False) -> ThreadingHTTPServer:
    """Готовит сервер и сессию. Используется и CLI, и лаунчером приложения."""
    SESSION["config"] = load_config()
    SESSION["demo"] = demo
    if demo:
        try:
            SESSION["last_audit"] = demo_audit()
        except Exception as exc:  # noqa: BLE001
            print(f"[ad-audit] demo data unavailable: {exc}")
    return ThreadingHTTPServer((host, port), Handler)


def main() -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--demo", action="store_true")
    args = parser.parse_args()

    server = build_server(args.host, args.port, args.demo)
    print(f"AD Audit {__version__} on http://{args.host}:{args.port}  backend={backend_name()}  demo={args.demo}")
    print("Read-only audit. Bind 127.0.0.1 only. Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[ad-audit] stopped")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
