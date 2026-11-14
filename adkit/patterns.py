"""Rule engine: language-agnostic sinks, endpoints, flags, checker references.

This is a heuristic scanner, not a compiler. It reads source text line by line
and reports places where user input and dangerous operations meet. Findings are
starting points for a human, not proof of exploitability.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}

FLAG_RE = re.compile(r"(?:ctfcup|TRAINING|flag)\{[^}]{1,200}\}", re.IGNORECASE)
CHECKER_RE = re.compile(r"(/_checker/[A-Za-z0-9_./-]*|X-Checker-Token|\bputflag\b|\bgetflag\b|\bcheckflag\b)", re.IGNORECASE)
ENDPOINT_RE = re.compile(r"""["'](/[A-Za-z0-9_./?=&{}:-]{1,120})["']""")


@dataclass(frozen=True)
class Rule:
    id: str
    kind: str
    severity: str
    why: str
    patch: str
    pattern: re.Pattern
    checker_risk: str = "low"
    absent: tuple[str, ...] = ()
    languages: tuple[str, ...] = ()


RULES: tuple[Rule, ...] = (
    Rule(
        id="sql-fstring",
        kind="SQL injection",
        severity="high",
        why="A query is assembled with an f-string. User input becomes SQL syntax.",
        patch="Pass values as bound parameters: WHERE title LIKE ? with (value,). Never format SQL.",
        pattern=re.compile(r"""\bf["'][^"']*\b(?:select|insert|update|delete)\b""", re.I),
    ),
    Rule(
        id="sql-format",
        kind="SQL injection",
        severity="high",
        why="A query is assembled with +, % or .format(). User input becomes SQL syntax.",
        patch="Use parameter binding. Allowlist column and sort names; they cannot be bound.",
        pattern=re.compile(r"""["'][^"']*\b(?:select|insert|update|delete)\b[^"']*["']\s*(?:\+|%|\.format\s*\()""", re.I),
    ),
    Rule(
        id="sql-exec-var",
        kind="SQL injection",
        severity="medium",
        why="A query variable is executed directly. Trace where that variable was built.",
        patch="Check the construction site; if it contains request data, bind parameters instead.",
        pattern=re.compile(r"""\b(?:execute|executemany|query|raw)\s*\(\s*(?:sql|query|q)\s*[,)]""", re.I),
    ),
    Rule(
        id="idor-id-only",
        kind="IDOR / BOLA",
        severity="high",
        why="An object is fetched by id alone. The owner is not part of the query.",
        patch="Bind the object to the authenticated principal: WHERE id=? AND owner=?.",
        pattern=re.compile(r"""\bwhere\b[^;\n]*\bid\s*=\s*(?:\?|%s|\$\d+|:id)""", re.I),
        absent=("owner", "user_id", "team_id", "account_id", "tenant"),
    ),
    Rule(
        id="path-join",
        kind="Path traversal",
        severity="high",
        why="A filesystem path is joined from request-controlled data without a containment check.",
        patch="Resolve the real path and verify it stays under the intended root; prefer an allowlist.",
        pattern=re.compile(
            r"""\b(?:os\.path\.join|filepath\.Join|path\.join|Path)\s*\(?[^)\n]*"""
            r"""\b(?:request|params|query|body|filename|name|user_input|user)\b""",
            re.I,
        ),
    ),
    Rule(
        id="path-sink",
        kind="Path traversal",
        severity="high",
        why="A file read or send call receives request-controlled data.",
        patch="Normalize, resolve symlinks, and check the prefix before reading or sending.",
        pattern=re.compile(
            r"""\b(?:send_file|sendFile|readFile|ReadFile|fs\.readFile|open|listdir)\s*\([^)\n]*"""
            r"""\b(?:request|params|query|filename|name|user_input|user)\b""",
            re.I,
        ),
    ),
    Rule(
        id="cmd-shell",
        kind="Command injection",
        severity="high",
        why="A shell or command executor is reachable from request data.",
        patch="Avoid the shell; pass an argument vector. Allowlist the command and its arguments.",
        pattern=re.compile(
            r"""\b(?:subprocess\.(?:run|call|Popen|check_output)\s*\([^)\n]*shell\s*=\s*True"""
            r"""|os\.system\s*\(|os\.popen\s*\(|Runtime\.getRuntime\(\)\.exec|child_process\.exec\s*\()""",
            re.I,
        ),
    ),
    Rule(
        id="deserialization",
        kind="Unsafe deserialization",
        severity="high",
        why="Untrusted data reaches a deserializer that can construct objects or execute code.",
        patch="Use a data-only format (JSON), signed payloads, or an allowlist of classes.",
        pattern=re.compile(
            r"""\b(?:pickle\.loads?|yaml\.load|unserialize|ObjectInputStream|readObject|boost::archive|Marshal\.load)\s*\(""",
            re.I,
        ),
    ),
    Rule(
        id="ssti",
        kind="Server-side template injection",
        severity="high",
        why="Request data reaches a template engine or eval-like sink.",
        patch="Render a fixed template with data passed as context; never compile user input.",
        pattern=re.compile(
            r"""\b(?:render_template_string|Template)\s*\([^)\n]*(?:request|req\.|params|query)""",
            re.I,
        ),
    ),
    Rule(
        id="jwt-none",
        kind="JWT verification bypass",
        severity="high",
        why="JWT verification is disabled or the none algorithm is accepted.",
        patch="Verify signature and algorithms explicitly; never trust alg from the token.",
        pattern=re.compile(
            r"""(?:verify\s*=\s*False|algorithms\s*=\s*\[\s*["']none["']|jwt\.decode\s*\([^)]*\)\s*$)""",
            re.I,
        ),
    ),
    Rule(
        id="mass-assign",
        kind="Mass assignment",
        severity="high",
        why="A privileged field such as role is taken from the request body.",
        patch="Use an explicit allowlist of user-editable fields; set role server-side.",
        pattern=re.compile(
            r"""(?:\brole\s*=\s*(?:payload|body|data|request|req\.body)"""
            r"""|\.get\(\s*["']role["']"""
            r"""|Object\.assign\s*\([^)]*req\.body"""
            r"""|\*\*\s*request\.json"""
            r"""|\bupdate\s*\(\s*\*\*\s*)""",
            re.I,
        ),
    ),
    Rule(
        id="ssrf",
        kind="SSRF",
        severity="medium",
        why="A server-side HTTP client receives request-controlled URL data.",
        patch="Allowlist scheme, host and port; block link-local and metadata addresses.",
        pattern=re.compile(
            r"""\b(?:requests\.(?:get|post|put)|urlopen|http\.Get)\s*\([^)\n]*"""
            r"""(?:request|req\.|params|query|r\.URL|target_url|endpoint|\burl\b)""",
            re.I,
        ),
    ),
    Rule(
        id="checker-ref",
        kind="Checker reference",
        severity="info",
        why="The code mentions the checker protocol. These paths are not attack targets.",
        patch="Do not send requests to /_checker/*. Do not modify checker state. Read only.",
        pattern=CHECKER_RE,
        checker_risk="high",
    ),
    Rule(
        id="flag-literal",
        kind="Flag literal",
        severity="info",
        why="A flag-shaped literal or storage path is present in source.",
        patch="Locate where the checker writes it. Read it through the intended API, not the disk.",
        pattern=FLAG_RE,
    ),
    Rule(
        id="hardcoded-secret",
        kind="Hardcoded secret",
        severity="medium",
        why="A password, token or key is embedded in source or a default value.",
        patch="Load secrets from the environment; rotate this value before deployment.",
        pattern=re.compile(r"""\b(?:password|passwd|secret|api[_-]?key|token)\s*=\s*["'][^"']{6,}["']""", re.I),
    ),
    Rule(
        id="debug-on",
        kind="Debug mode",
        severity="medium",
        why="Debug mode or an interactive debugger is enabled.",
        patch="Disable debug and reload in production; it often exposes a console.",
        pattern=re.compile(r"""\b(?:debug\s*=\s*True|DEBUG\s*=\s*True|app\.run\([^)]*debug\s*=\s*True)"""),
    ),
    Rule(
        id="upload",
        kind="Unsafe upload",
        severity="medium",
        why="An uploaded file or its client-supplied name is written without validation.",
        patch="Generate the stored name, allowlist extensions, store outside the web root.",
        pattern=re.compile(r"""\b(?:\.save|save_file|upload)\s*\(\s*(?:request|filename|file)""", re.I),
    ),
    Rule(
        id="open-redirect",
        kind="Open redirect",
        severity="low",
        why="A redirect target comes from request data.",
        patch="Allowlist relative paths or known hosts; never redirect to arbitrary input.",
        pattern=re.compile(r"""\bredirect\s*\(\s*(?:request|req\.|params|query)""", re.I),
    ),
    Rule(
        id="xxe",
        kind="XXE",
        severity="medium",
        why="An XML parser is reachable from request data with external entities enabled.",
        patch="Disable DTDs and external entities; use a hardened parser configuration.",
        pattern=re.compile(r"""\b(?:etree\.parse|XMLParser|DocumentBuilderFactory|SAXParser)\s*\(""", re.I),
    ),
    Rule(
        id="debug-path",
        kind="Sensitive route",
        severity="low",
        why="A debug, admin or metrics route is defined in source.",
        patch="Check authorization on the route; it is often the shortest path to secrets.",
        pattern=re.compile(r"""["']/(?:debug|admin|internal|metrics)["']""", re.I),
    ),
    Rule(
        id="autoescape-off",
        kind="Template escaping disabled",
        severity="medium",
        why="Output escaping is disabled or a value is marked safe.",
        patch="Keep autoescape on; sanitize with a real HTML sanitizer if rich text is required.",
        pattern=re.compile(r"""(?:autoescape\s*=\s*False|\bMarkup\s*\(|\|\s*safe\b)"""),
    ),
)


_EXT_LANG = {
    ".py": "python", ".go": "go", ".rs": "rust", ".js": "javascript",
    ".ts": "typescript", ".php": "php", ".rb": "ruby", ".java": "java",
    ".c": "c", ".cc": "cpp", ".cpp": "cpp", ".h": "c", ".hpp": "cpp",
    ".lua": "lua", ".yml": "yaml", ".yaml": "yaml", ".json": "json",
    ".toml": "toml", ".sh": "bash", ".sql": "sql",
}


def language_of(path: str) -> str:
    suffix = Path(path).suffix.lower()
    if suffix in _EXT_LANG:
        return _EXT_LANG[suffix]
    name = Path(path).name.lower()
    if name == "dockerfile":
        return "docker"
    return "text"


def scan_text(path: str, text: str, language: str | None = None) -> list[dict]:
    """Return findings for one file. Line-based, context ±3 lines, deduped."""
    lines = text.splitlines()
    findings: list[dict] = []
    seen: set[tuple[str, int]] = set()
    seen_kind: set[tuple[str, int]] = set()
    for rule in RULES:
        for number, line in enumerate(lines, 1):
            if rule.pattern.search(line) is None:
                continue
            if (rule.id, number) in seen:
                continue
            if (rule.kind, number) in seen_kind:
                continue
            window = "\n".join(lines[max(0, number - 4): min(len(lines), number + 3)])
            if rule.absent and any(word in window.lower() for word in rule.absent):
                continue
            seen.add((rule.id, number))
            seen_kind.add((rule.kind, number))
            risk = rule.checker_risk
            if "/_checker" in line or re.search(r"\b(?:putflag|getflag|checkflag)\b", line, re.I):
                risk = "high"
            elif risk == "low" and re.search(r"\b(?:POST|PUT|DELETE|UPDATE|INSERT|DROP)\b", line, re.I):
                risk = "medium"
            digest = hashlib.sha1(f"{path}:{number}:{rule.id}".encode()).hexdigest()[:10]
            context_start = max(0, number - 4) + 1
            findings.append({
                "id": digest,
                "rule": rule.id,
                "kind": rule.kind,
                "severity": rule.severity,
                "file": path,
                "line": number,
                "snippet": line.strip()[:240],
                "context": lines[max(0, number - 4): min(len(lines), number + 3)],
                "context_start": context_start,
                "why": rule.why,
                "patch": rule.patch,
                "checker_risk": risk,
                "language": language or language_of(path),
            })
    findings.sort(key=lambda item: (SEVERITY_ORDER.get(item["severity"], 9), item["file"], item["line"]))
    return findings


def map_endpoints(path: str, text: str) -> list[dict]:
    """Best-effort endpoint extraction for the common frameworks."""
    endpoints: list[dict] = []
    patterns = (
        (re.compile(r"""@\w+\.(?:route|get|post|put|delete|patch)\(\s*["']([^"']+)["']"""), None),
        (re.compile(r"""\b(?:app|router|r)\.(get|post|put|delete|patch)\(\s*["']([^"']+)["']"""), 1),
        (re.compile(r"""HandleFunc\(\s*["']([^"']+)["']"""), None),
        (re.compile(r"""\.route\(\s*["']([^"']+)["']"""), None),
        (re.compile(r"""\$_GET\[\s*["']([^"']+)["']\s*\]"""), None),
    )
    for number, line in enumerate(text.splitlines(), 1):
        for pattern, method_group in patterns:
            match = pattern.search(line)
            if not match:
                continue
            if method_group:
                method = match.group(1).upper()
                target = match.group(2)
            else:
                method = "ANY"
                target = match.group(1)
            endpoints.append({"path": target, "method": method, "file": path, "line": number})
    return endpoints


def find_flags(text: str) -> list[str]:
    return FLAG_RE.findall(text)


def find_checker_refs(text: str) -> list[str]:
    return CHECKER_RE.findall(text)


def rule_catalog() -> list[dict]:
    return [
        {"id": rule.id, "kind": rule.kind, "severity": rule.severity,
         "why": rule.why, "patch": rule.patch}
        for rule in RULES
    ]
