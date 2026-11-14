"""Probe scaffold generator.

Default output is a read-only GET probe: one request per candidate, no state
change, no checker endpoints, no brute force. Findings that need a state change
produce an inert template marked MANUAL REVIEW instead of auto-generated code.
"""
from __future__ import annotations

import re
from string import Template

from . import patterns
from .lint import lint_code

MANUAL_KINDS = {"Mass assignment", "Business logic", "Unsafe upload", "Checker reference"}

GET_TEMPLATE = Template('''"""Generated probe for ${kind} at ${file}:${line}.

SAFETY
- read-only GET, no state change
- never calls /_checker/*
- one request per candidate, no brute force
- run against your own lab first
"""
from __future__ import annotations

import re
import ssl
import sys
import urllib.request

SERVICE = ${service}
NAME = ${name}
FLAG_RE = re.compile(r"ctfcup\\{[^}]{1,200}\\}")

CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE

CANDIDATES = ${candidates}


def run(target, timeout=5.0):
    port = int(target["ports"][SERVICE])
    base = f"http://{target['host']}:{port}"
    flags = []
    for path in CANDIDATES:
        req = urllib.request.Request(base + path, headers={"User-Agent": "ad-probe/1.0"})
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=CTX) as res:
                body = res.read(65536).decode("utf-8", "replace")
        except Exception:
            continue
        flags.extend(FLAG_RE.findall(body))
    return flags


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("usage: probe.py <host> <port>")
    print(run({"host": sys.argv[1], "ports": {SERVICE: int(sys.argv[2])}}))
''')

MANUAL_TEMPLATE = Template('''"""Generated scaffold for ${kind} at ${file}:${line}.

MANUAL REVIEW
This finding likely needs a state-changing request or a multi-step flow.
The code below is intentionally inert. Edit it against your own lab first
and keep the SLA monitor running while you test.

SAFETY
- do not call /_checker/*
- do not delete data
- do not restart services
- one request at a time
"""
SERVICE = ${service}
NAME = ${name}


def run(target, timeout=5.0):
    # TODO: build the request from this context:
    # ${snippet}
    return []
''')


def _slug(value: str) -> str:
    cleaned = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return cleaned[:40] or "probe"


def _endpoint(finding: dict) -> str:
    for line in finding.get("context", []):
        match = patterns.ENDPOINT_RE.search(line)
        if match:
            return match.group(1)
    return "/"


def generate_probe(finding: dict, service: str, endpoint: str | None = None) -> dict:
    kind = finding.get("kind", "Finding")
    manual = kind in MANUAL_KINDS or finding.get("checker_risk") == "high"
    name = f"{service}-{_slug(kind)}"
    target_endpoint = endpoint or _endpoint(finding)
    values = {
        "kind": kind,
        "file": finding.get("file", "?"),
        "line": finding.get("line", 0),
        "service": repr(service),
        "name": repr(name),
        "candidates": repr([target_endpoint]),
        "snippet": finding.get("snippet", "").replace("\n", " ")[:200],
    }
    if manual:
        code = MANUAL_TEMPLATE.safe_substitute(values)
    else:
        code = GET_TEMPLATE.safe_substitute(values)
    return {
        "code": code,
        "manual": manual,
        "endpoint": target_endpoint,
        "service": service,
        "name": name,
        "lint": lint_code(code),
    }


def generate_report(audit: dict) -> str:
    counts = audit.get("counts", {})
    lines = [
        "# AD audit report",
        "",
        f"- host: `{audit.get('host', 'unknown')}`",
        f"- generated: {audit.get('generated_at', '')}",
        f"- services: {len(audit.get('services', []))}",
        f"- source files: {len(audit.get('files', []))}",
        f"- findings: high {counts.get('high', 0)}, medium {counts.get('medium', 0)}, "
        f"low {counts.get('low', 0)}, info {counts.get('info', 0)}",
        "",
        "## Services",
        "",
        "| port | service | process | cwd |",
        "|---:|---|---|---|",
    ]
    for service in audit.get("services", []):
        lines.append(
            f"| {service.get('port')} | {service.get('service')} | "
            f"{service.get('process')} | `{service.get('cwd')}` |"
        )
    lines += ["", "## Findings", "", "| severity | kind | file:line | checker |", "|---|---|---|---|"]
    for finding in audit.get("findings", [])[:80]:
        lines.append(
            f"| {finding.get('severity')} | {finding.get('kind')} | "
            f"`{finding.get('file')}:{finding.get('line')}` | {finding.get('checker_risk')} |"
        )
    lines += ["", "## Checker", "", f"> {audit.get('checker', {}).get('warning', '')}", ""]
    for ref in audit.get("checker", {}).get("mentions", [])[:20]:
        lines.append(f"- `{ref}`")
    lines += ["", "## Flags", ""]
    for literal in audit.get("flags", {}).get("literals", [])[:20]:
        lines.append(f"- literal: `{literal}`")
    for path in audit.get("flags", {}).get("storage", [])[:20]:
        lines.append(f"- storage: `{path}`")
    lines += [
        "",
        "## Next steps",
        "",
        "1. Open each high finding and read the context window.",
        "2. Generate a GET probe; run it against your own instance first.",
        "3. Keep the SLA monitor on while testing.",
        "4. Patch one service at a time; back up before the patch.",
        "5. Never send requests to `/_checker/*`.",
    ]
    return "\n".join(lines) + "\n"
