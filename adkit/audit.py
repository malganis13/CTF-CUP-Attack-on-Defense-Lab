"""Read-only audit engine.

Only fixed, read-only commands are executed on the target. The engine never
writes files, never restarts services and never sends traffic to the checker.
"""
from __future__ import annotations

import re
import shlex
import time
from pathlib import Path

from . import patterns
from .languages import detect_stacks, stack_for
from .ssh import BaseSSH

AUDIT_SCRIPT = r'''
echo __OS__
cat /etc/os-release 2>/dev/null; uname -a
echo __ID__
id
echo __HOST__
hostname
echo __SS__
(ss -lntup 2>/dev/null || netstat -lntup 2>/dev/null)
echo __PS__
ps auxww 2>/dev/null | head -200
echo __SYSTEMD__
systemctl list-units --type=service --state=running --no-pager 2>/dev/null | head -80
echo __DOCKER__
docker ps --no-trunc 2>/dev/null; docker images 2>/dev/null
echo __K3S__
kubectl get pods -A -o wide 2>/dev/null; kubectl get svc -A 2>/dev/null
echo __CRON__
crontab -l 2>/dev/null; ls -la /etc/cron* 2>/dev/null
echo __ENV__
env 2>/dev/null | sort | head -200
echo __ROOTS__
ls -la /opt /srv /app /var/www /home /root /data 2>/dev/null
echo __PIDS__
pids=$(ss -lntp 2>/dev/null | awk 'NR>1{print $6}' | sed -n 's/.*pid=\([0-9]*\).*/\1/p' | sort -u)
if [ -n "$pids" ]; then
  for p in $pids; do
    echo "== $p"
    ls -l /proc/$p/cwd 2>/dev/null
    tr '\0' ' ' < /proc/$p/cmdline 2>/dev/null; echo
  done
fi
echo __END__
'''

FIND_COMMAND = (
    "find {roots} -maxdepth 5 -type f \\("
    " -name '*.py' -o -name '*.go' -o -name '*.rs' -o -name '*.js' -o -name '*.mjs' -o -name '*.ts'"
    " -o -name '*.jsx' -o -name '*.tsx' -o -name '*.vue' -o -name '*.svelte'"
    " -o -name '*.php' -o -name '*.rb' -o -name '*.java' -o -name '*.kt' -o -name '*.cs'"
    " -o -name '*.c' -o -name '*.cc' -o -name '*.cpp' -o -name '*.h' -o -name '*.hpp'"
    " -o -name '*.lua' -o -name '*.pl' -o -name '*.sh' -o -name '*.sql' -o -name '*.proto'"
    " -o -name '*.yml' -o -name '*.yaml' -o -name '*.toml' -o -name '*.ini'"
    " -o -name 'Dockerfile' -o -name '*.service' -o -name '*.conf'"
    " \\) 2>/dev/null"
    " | grep -vE '/(node_modules|\\.git|vendor|target|dist|build|__pycache__|site-packages|\\.venv)/'"
    " | head -400"
)

MANIFEST_COMMAND = (
    "find {roots} -maxdepth 5 -type f \\("
    " -name 'go.mod' -o -name 'Cargo.toml' -o -name 'package.json' -o -name 'composer.json'"
    " -o -name 'pom.xml' -o -name 'build.gradle' -o -name 'build.gradle.kts' -o -name 'Gemfile'"
    " -o -name 'requirements.txt' -o -name 'pyproject.toml' -o -name 'Pipfile' -o -name '*.csproj'"
    " -o -name 'Dockerfile' -o -name 'docker-compose.yml' -o -name 'docker-compose.yaml'"
    " \\) 2>/dev/null"
    " | grep -vE '/(node_modules|\\.git|vendor|target|__pycache__|site-packages|\\.venv)/'"
    " | head -80"
)

DEFAULT_ROOTS = ("/opt", "/srv", "/app", "/var/www", "/home", "/root", "/data")


def parse_sections(raw: str) -> dict[str, str]:
    sections: dict[str, list[str]] = {}
    current: str | None = None
    for line in raw.splitlines():
        stripped = line.strip()
        if stripped.startswith("__") and stripped.endswith("__") and 3 < len(stripped) < 32:
            name = stripped.strip("_").lower()
            if name.isidentifier():
                current = name
                sections[current] = []
                continue
        if current is not None:
            sections[current].append(line)
    return {name: "\n".join(lines) for name, lines in sections.items()}


def parse_pids(text: str) -> dict[int, dict]:
    info: dict[int, dict] = {}
    current: int | None = None
    for line in text.splitlines():
        if line.startswith("== "):
            try:
                current = int(line[3:].strip())
            except ValueError:
                current = None
            if current is not None:
                info[current] = {"cwd": "", "cmdline": ""}
        elif current is not None and "cwd -> " in line:
            info[current]["cwd"] = line.split("cwd -> ", 1)[1].strip()
        elif current is not None and line.strip():
            info[current]["cmdline"] = (info[current]["cmdline"] + " " + line.strip()).strip()
    return info


def build_services(ss_text: str, pids: dict[int, dict]) -> list[dict]:
    services: dict[int, dict] = {}
    for line in ss_text.splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue
        proto = parts[0].lower()
        if proto not in {"tcp", "tcp6", "udp", "udp6"}:
            continue
        state = parts[1].upper()
        if state not in {"LISTEN", "UNCONN"}:
            continue
        address = parts[4]
        port_text = address.rsplit(":", 1)[-1]
        if not port_text.isdigit():
            continue
        port = int(port_text)
        if port in services:
            continue
        pid_match = re.search(r"pid=(\d+)", line)
        pid = int(pid_match.group(1)) if pid_match else None
        process_match = re.search(r'users:\(\("([^"]+)"', line)
        process = process_match.group(1) if process_match else ""
        detail = pids.get(pid or -1, {})
        cmdline = detail.get("cmdline", "")
        name = process
        if cmdline:
            first = cmdline.split()[0]
            name = Path(first).name or process
        services[port] = {
            "port": port,
            "proto": proto,
            "state": state,
            "address": address,
            "process": process,
            "pid": pid,
            "cwd": detail.get("cwd", ""),
            "cmdline": cmdline[:300],
            "service": name or "unknown",
            "language": patterns.language_of(name) if name else "unknown",
        }
    return [services[port] for port in sorted(services)]


def roots_from_pids(pids: dict[int, dict]) -> list[str]:
    roots = {detail["cwd"] for detail in pids.values() if detail.get("cwd", "").startswith("/")}
    return sorted(roots | set(DEFAULT_ROOTS))


def analyze_sources(sources: dict[str, str], services: list[dict], host: str) -> dict:
    findings: list[dict] = []
    files: list[dict] = []
    endpoints: list[dict] = []
    literals: set[str] = set()
    checker_refs: list[str] = []
    storage: set[str] = set()
    language_counts: dict[str, int] = {}

    for path, text in sources.items():
        language = patterns.language_of(path, text)
        language_counts[language] = language_counts.get(language, 0) + 1
        file_findings = patterns.scan_text(path, text, language)
        findings.extend(file_findings)
        endpoints.extend(patterns.map_endpoints(path, text))
        literals.update(patterns.find_flags(text))
        checker_refs.extend(patterns.find_checker_refs(text))
        if re.search(r"(flag|secret|\.sqlite3$|\.db$)", path, re.I):
            storage.add(path)
        files.append({
            "path": path,
            "language": language,
            "lines": len(text.splitlines()),
            "findings": len(file_findings),
        })

    stacks = detect_stacks(sources)
    enriched_services = []
    for service in services:
        item = dict(service)
        stack = stack_for(item.get("cwd", ""), stacks)
        item["stack"] = stack["label"]
        item["languages"] = stack["languages"]
        item["frameworks"] = stack["frameworks"]
        enriched_services.append(item)

    findings.sort(key=lambda item: (patterns.SEVERITY_ORDER.get(item["severity"], 9), item["file"], item["line"]))
    counts = {severity: sum(1 for item in findings if item["severity"] == severity)
              for severity in ("high", "medium", "low", "info")}

    notable = {"text", "json", "yaml", "toml", "ini", "docker", "systemd"}
    return {
        "host": host,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "services": enriched_services,
        "files": files,
        "endpoints": endpoints,
        "findings": findings,
        "counts": counts,
        "languages": [
            {"language": name, "files": count}
            for name, count in sorted(language_counts.items(), key=lambda pair: (-pair[1], pair[0]))
            if name not in notable
        ],
        "stacks": [
            {"directory": directory, **entry}
            for directory, entry in sorted(stacks.items())
            if entry["languages"] or entry["frameworks"]
        ],
        "checker": {
            "refs": [item for item in findings if item["rule"] == "checker-ref"],
            "mentions": sorted(set(checker_refs))[:50],
            "warning": "Never send requests to /_checker/*. Never modify checker state.",
        },
        "flags": {
            "literals": sorted(literals),
            "storage": sorted(storage),
        },
        "meta": {
            "roots": sorted({str(Path(item["path"]).parent) for item in files})[:50],
            "source_files": len(files),
        },
    }


class Audit:
    def __init__(self, ssh: BaseSSH, log) -> None:
        self.ssh = ssh
        self.log = log
        self.commands: list[str] = []

    def _run(self, command: str, timeout: int = 40) -> str:
        self.commands.append(command)
        try:
            code, out, err = self.ssh.run(command, timeout=timeout)
        except Exception as exc:
            self.log(f"command failed: {type(exc).__name__}: {exc}")
            return ""
        if err.strip() and code != 0:
            self.log(f"stderr: {err.strip()[:180]}")
        return out

    def _find_files(self, roots: list[str]) -> list[str]:
        roots = [root for root in roots if root.startswith("/")]
        command = FIND_COMMAND.format(roots=" ".join(shlex.quote(root) for root in roots))
        out = self._run(command, timeout=40)
        return [line.strip() for line in out.splitlines() if line.strip().startswith("/")][:400]

    def _find_manifests(self, roots: list[str]) -> list[str]:
        roots = [root for root in roots if root.startswith("/")]
        if not roots:
            return []
        command = MANIFEST_COMMAND.format(roots=" ".join(shlex.quote(root) for root in roots))
        out = self._run(command, timeout=30)
        return [line.strip() for line in out.splitlines() if line.strip().startswith("/")][:80]

    def _read_files(self, paths: list[str]) -> dict[str, str]:
        if not paths:
            return {}
        listing = "\n".join(paths)
        script = (
            "while IFS= read -r f; do echo \"===FILE $f\"; sed -n '1,200p' \"$f\" 2>/dev/null; done "
            "<<'__AD_LIST__'\n" + listing + "\n__AD_LIST__\n"
        )
        script = "(\n" + script + "\n) | head -c 2000000"
        raw = self._run(script, timeout=50)
        sources: dict[str, str] = {}
        current: str | None = None
        buffer: list[str] = []
        for line in raw.splitlines():
            if line.startswith("===FILE "):
                if current is not None:
                    sources[current] = "\n".join(buffer)
                current = line[len("===FILE "):].strip()
                buffer = []
            elif current is not None:
                buffer.append(line)
        if current is not None:
            sources[current] = "\n".join(buffer)
        return sources

    def run(self) -> dict:
        started = time.time()
        self.log("collecting host, ports, processes")
        raw = self._run(AUDIT_SCRIPT, timeout=50)
        sections = parse_sections(raw)
        pids = parse_pids(sections.get("pids", ""))
        services = build_services(sections.get("ss", ""), pids)
        roots = roots_from_pids(pids)
        self.log(f"services: {len(services)}; roots: {', '.join(roots[:8])}")
        self.log("listing source files")
        files = self._find_files(roots)
        manifests = self._find_manifests(roots)
        self.log(f"source files: {len(files)}; manifests: {len(manifests)}")
        sources = self._read_files(sorted(set(files) | set(manifests)))
        self.log(f"read {len(sources)} files; scanning")
        result = analyze_sources(sources, services, self.ssh.label())
        result["os"] = [line for line in sections.get("os", "").splitlines() if line.strip()][:4]
        result["meta"].update({
            "duration_ms": int((time.time() - started) * 1000),
            "commands": self.commands,
            "roots": roots,
            "findings_total": len(result["findings"]),
        })
        self.log(f"done: {len(result['findings'])} findings")
        return result
