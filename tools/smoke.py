#!/usr/bin/env python3
"""End-to-end smoke test against the demo server.

Starts app.py --demo on a free port, exercises every API route, asserts the
invariants that matter, and shuts the server down.

    python tools/smoke.py
"""
from __future__ import annotations

import json
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
PORT = 8799
ROOT = f"http://127.0.0.1:{PORT}"

failures: list[str] = []
checks = 0


def check(name: str, condition: bool, detail: str = "") -> None:
    global checks
    checks += 1
    if condition:
        print(f"  ok    {name}")
    else:
        print(f"  FAIL  {name} {detail}")
        failures.append(name)


def get(path: str):
    with urllib.request.urlopen(ROOT + path, timeout=10) as response:
        return json.loads(response.read().decode("utf-8"))


def post(path: str, body: dict | None = None):
    data = json.dumps(body or {}).encode("utf-8")
    request = urllib.request.Request(
        ROOT + path, data=data, headers={"Content-Type": "application/json"}, method="POST"
    )
    with urllib.request.urlopen(request, timeout=15) as response:
        return json.loads(response.read().decode("utf-8"))


def wait_ready(deadline: float = 20.0) -> bool:
    started = time.time()
    while time.time() - started < deadline:
        try:
            get("/api/health")
            return True
        except (urllib.error.URLError, ConnectionError, OSError):
            time.sleep(0.2)
    return False


def main() -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    sys.path.insert(0, str(BASE))
    sys.path.insert(0, str(BASE / "tools"))
    import lab_server  # noqa: PLC0415

    lab = lab_server.start(0)
    lab_port = lab.server_address[1]

    def lab_hits() -> list[str]:
        return lab_server.HITS

    config_path = BASE / "config.json"
    original = config_path.read_bytes() if config_path.is_file() else None
    server = subprocess.Popen(
        [sys.executable, "app.py", "--demo", "--port", str(PORT)],
        cwd=str(BASE),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        if not wait_ready():
            print("server did not start")
            return 1

        print("server")
        health = get("/api/health")
        check("health ok", health.get("status") == "ok", str(health))
        check("demo flag", health.get("demo") is True)

        state = get("/api/state")
        check("state has version", bool(state.get("version")))
        check("state has backend", bool(state.get("backend")))
        check("rules registered", state.get("rules", 0) >= 15, str(state.get("rules")))

        print("audit")
        audit = get("/api/last")
        check("audit returned", isinstance(audit.get("findings"), list))
        check("findings present", len(audit["findings"]) > 0)
        check("services present", len(audit.get("services", [])) >= 8, str(len(audit.get("services", []))))
        check("counts match", sum(audit["counts"].values()) == len(audit["findings"]))
        check(
            "every finding has file+line",
            all(item.get("file") and item.get("line") for item in audit["findings"]),
        )
        kinds = {item["kind"] for item in audit["findings"]}
        for kind in ("SQL injection", "Path traversal", "IDOR / BOLA", "Command injection"):
            check(f"detects {kind}", kind in kinds)

        languages = {item["language"] for item in audit.get("languages", [])}
        for language in ("python", "go", "rust", "javascript", "php", "java", "csharp", "c", "ruby", "lua"):
            check(f"scans {language}", language in languages, str(sorted(languages)))

        stacks = {item.get("stack", "") for item in audit["services"]}
        for stack in ("python", "go/gin", "php/laravel", "javascript/express", "rust/axum", "java/spring", "ruby/sinatra"):
            check(f"stack {stack}", stack in stacks, str(sorted(stacks)))

        check(
            "language rules stayed in their lane",
            all(item.get("language") for item in audit["findings"]),
        )

        print("patterns")
        catalog = get("/api/patterns")
        check("catalog size", len(catalog["rules"]) == state["rules"])
        check("coverage table", len(catalog.get("coverage", [])) >= 9, str(len(catalog.get("coverage", []))))
        go_rules = [item for item in catalog["rules"] if "go" in item["languages"]]
        check("go has rules", len(go_rules) >= 3, str(len(go_rules)))

        print("files")
        listing = get("/api/files?path=/srv")
        names = {entry["name"] for entry in listing["entries"]}
        check("lists service dirs", {"notes", "files", "profile"} <= names, str(sorted(names)))
        file = get("/api/file?path=/srv/notes/app.py")
        check("file has text", bool(file.get("text")))
        check("file has findings", len(file.get("findings", [])) > 0)
        deep = get("/api/file?path=/srv/files/app.py")
        check("resolves second service", "UPLOAD_ROOT" in (deep.get("text") or ""))

        print("generator")
        high = next(item for item in audit["findings"] if item["severity"] == "high")
        probe = post("/api/generate", {"id": high["id"], "service": "notes", "port": lab_port})
        check("probe has code", bool(probe.get("code")))
        check("probe lint clean", probe.get("lint", {}).get("ok") is True, str(probe.get("lint")))
        code = probe.get("code") or ""
        check("probe is GET-only", 'method="GET"' in code and "data=" not in code)
        check("probe has requests", len(probe.get("requests") or []) >= 1)
        check(
            "probe requests avoid checker",
            all("/_checker" not in item["path"] for item in (probe.get("requests") or [])),
        )
        check("probe avoids state change", "requests.post" not in code)

        manual = next(item for item in audit["findings"] if item["kind"] == "Mass assignment")
        scaffold = post("/api/generate", {"id": manual["id"], "service": "profile", "port": lab_port})
        check("manual finding is inert", scaffold.get("manual") is True)
        check("scaffold lint ok", scaffold.get("lint", {}).get("ok") is True, str(scaffold.get("lint")))
        check("scaffold carries dry-run", "--send" in (scaffold.get("code") or ""))

        print("probe run")
        sqli = next(item for item in audit["findings"]
                    if item["kind"] == "SQL injection" and item["file"].endswith("main.go"))
        run = post("/api/probe", {
            "id": sqli["id"], "service": "lab", "endpoint": "/sqli",
            "port": lab_port, "base": f"http://127.0.0.1:{lab_port}",
        })
        check("probe hit the lab", run.get("summary", {}).get("requests", 0) >= 3, str(run.get("summary")))
        check("probe confirmed", run.get("summary", {}).get("verdict") == "confirmed", str(run.get("summary")))
        check("probe evidence present", all("verdict" in row for row in run.get("results", [])))
        check("probe stayed off checker", not any("/_checker" in hit for hit in lab_hits()))

        print("report")
        report = post("/api/report")
        markdown = report.get("markdown") or ""
        check("report header", markdown.startswith("# Отчёт аудита A/D"), markdown.splitlines()[0] if markdown else "")
        check("report lists services", "| 8081 |" in markdown)
        check("report warns on checker", "/_checker" in markdown)

        print("treatment")
        fix_target = next(item for item in audit["findings"] if item["rule"] == "sql-fstring")
        fix = get("/api/fix?id=" + fix_target["id"])
        check("fix returned", fix.get("fix", {}).get("available") is True, str(fix.get("fix"))[:120])
        check("fix has safe code", bool(fix["fix"].get("after")))
        check("fix names the risk", "риск" in (fix["fix"].get("title") or "") or bool(fix["fix"].get("breaks")))
        missing_ok = False
        try:
            get("/api/fix?id=nope")
        except Exception as error:  # noqa: BLE001
            missing_ok = "404" in str(error)
        check("unknown finding is 404", missing_ok)

        print("traffic")
        traffic = get("/api/traffic")
        caps = traffic.get("caps", {})
        check("traffic journal present", isinstance(traffic.get("events"), list))
        check("cap per probe", caps.get("max_requests_per_probe") == 14, str(caps))
        check("budget cap", caps.get("budget_capacity") == 30 and caps.get("budget_window_s") == 60, str(caps))
        check("checker paths blocked", "_checker" in (caps.get("checker_paths_blocked") or [""])[0])
        check("traffic claims non-empty", len(traffic.get("claims") or []) >= 4)
        check("liveness caps", caps.get("liveness_requests_per_service") == 2, str(caps))

        print("liveness")
        before = len(get("/api/traffic").get("events") or [])
        live = get("/api/liveness")
        check("liveness in demo is off", bool(live.get("error")), str(live)[:160])
        check("liveness summary shape",
              all(key in (live.get("summary") or {}) for key in ("up", "down", "sick", "open", "local")),
              str(live.get("summary")))
        after = len(get("/api/traffic").get("events") or [])
        check("liveness made no requests", after == before, f"{before} -> {after}")

        print("checker guard")
        denied_dir = ""
        denied_file = ""
        try:
            get("/api/files?path=/srv/_checker")
        except Exception as error:  # noqa: BLE001
            denied_dir = str(error)
        try:
            get("/api/file?path=/srv/_checker/flags.json")
        except Exception as error:  # noqa: BLE001
            denied_file = str(error)
        check("checker dir refused", "403" in denied_dir, denied_dir)
        check("checker file refused", "403" in denied_file, denied_file)

        print("config")
        saved = post("/api/config", {"target": {"host": "10.0.0.5", "port": 2222, "user": "root", "auth": "key"}})
        check("config saved", saved.get("ok") is True)
        check("host persisted", saved["state"]["target"]["host"] == "10.0.0.5")
        checked = post("/api/test")
        check("demo test passes", checked.get("ok") is True)

        print("knowledge")
        knowledge = get("/api/knowledge")
        names = {item["name"] for item in knowledge["items"]}
        check(
            "knowledge notes present",
            {"ad-rules", "triage", "patch-playbook", "attack-playbook", "checker-safety"} <= names,
            str(sorted(names)),
        )

        print("linter")
        sys.path.insert(0, str(BASE))
        from adkit.lint import lint_code  # noqa: PLC0415

        check("linter accepts a GET probe", lint_code("import urllib.request\nurllib.request.urlopen('http://h/').read()\n")["ok"] is True)
        check("linter rejects POST", lint_code("import requests\nrequests.post('http://h/', data={})\n")["ok"] is False)
        check("linter rejects checker path", lint_code("import urllib.request\nurllib.request.urlopen('http://h/_checker/x')\n")["ok"] is False)
        check("linter rejects subprocess", lint_code("import subprocess\nsubprocess.run(['id'])\n")["ok"] is False)
        check("linter rejects file write", lint_code("open('/tmp/x', 'w').write('x')\n")["ok"] is False)
        check(
            "linter accepts a docstring",
            lint_code('"""never call /_checker/*"""\nx = 1\n')["ok"] is True,
        )
    finally:
        lab.shutdown()
        server.terminate()
        try:
            server.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server.kill()
        # The config route writes to disk; leave the working tree as it was found.
        if original is None:
            config_path.unlink(missing_ok=True)
        else:
            config_path.write_bytes(original)

    print()
    if failures:
        print(f"{len(failures)} failed of {checks}: {', '.join(failures)}")
        return 1
    print(f"{checks}/{checks} passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
