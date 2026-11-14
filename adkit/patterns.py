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

from .languages import COVERAGE, language_of

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
    context: re.Pattern | None = None
    window: int = 6
    once: bool = False


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
        pattern=re.compile(r"""\bwhere\b[^;\n]*\bid\s*=\s*(?:\?|:\w+|\$\d+|\{\w+\})""", re.I),
        absent=("owner", "user_id", "team_id", "account_id", "tenant", "select 1"),
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


# Language-specific rules. `languages` is enforced in scan_text: a rule only
# runs on files detected as one of the listed languages. An empty tuple means
# the rule is language-agnostic.
LANG_RULES: tuple[Rule, ...] = (
    # Go
    Rule(
        id="go-sql-sprintf",
        kind="SQL injection",
        severity="high",
        why="A query is assembled with fmt.Sprintf. The interpolated value becomes SQL syntax.",
        patch="Pass values as query arguments: db.QueryRow(\"… WHERE id = $1\", id).",
        pattern=re.compile(r"""fmt\.Sprintf\(\s*(?:`|")[^`"]*\b(?:SELECT|INSERT|UPDATE|DELETE)\b""", re.I),
        languages=("go",),
    ),
    Rule(
        id="go-exec-user",
        kind="Command injection",
        severity="high",
        why="exec.Command receives request-controlled data.",
        patch="Allowlist the binary and pass fixed arguments; never build the command from input.",
        pattern=re.compile(r"""exec\.Command\([^)\n]*(?:r\.|req\.|c\.(?:Query|Param)|FormValue|URL\.Query|mux\.Vars|chi\.URLParam|input|param|name)"""),
        languages=("go",),
    ),
    Rule(
        id="go-path-sink",
        kind="Path traversal",
        severity="high",
        why="A file is opened from a request-derived path.",
        patch="Join against a fixed root and verify filepath.Clean stays inside it.",
        pattern=re.compile(r"""os\.(?:ReadFile|Open|Create|OpenFile)\([^)\n]*(?:r\.|c\.(?:Query|Param)|FormValue|URL\.Query|mux\.Vars|chi\.URLParam|param|name)"""),
        languages=("go",),
    ),
    Rule(
        id="go-template-html",
        kind="Cross-site scripting",
        severity="medium",
        why="A template is rendered from a string built with request data.",
        patch="Render a parsed template file; pass data as context, never as template text.",
        pattern=re.compile(r"""template\.(?:HTML|JS|URL)\(\s*"""),
        languages=("go",),
    ),
    # Rust
    Rule(
        id="rust-sql-format",
        kind="SQL injection",
        severity="high",
        why="A query is assembled with format!. The interpolated value becomes SQL syntax.",
        patch="Use query arguments: sqlx::query(\"… WHERE id = $1\").bind(id).",
        pattern=re.compile(r"""format!\(\s*"[^"]*\b(?:SELECT|INSERT|UPDATE|DELETE)\b""", re.I),
        languages=("rust",),
    ),
    Rule(
        id="rust-command-format",
        kind="Command injection",
        severity="high",
        why="Command::arg receives a formatted value.",
        patch="Validate against an allowlist before passing an argument to a child process.",
        pattern=re.compile(r"""\.arg\(\s*&?format!\("""),
        languages=("rust",),
    ),
    Rule(
        id="rust-command-user",
        kind="Command injection",
        severity="medium",
        why="Command::new receives a request-derived program or argument.",
        patch="Use a fixed program name and an allowlisted argument set.",
        pattern=re.compile(r"""Command::new\([^)\n]*(?:user|input|param|name)"""),
        languages=("rust",),
    ),
    Rule(
        id="rust-path",
        kind="Path traversal",
        severity="high",
        why="A filesystem read receives request-derived data.",
        patch="Canonicalise and check the prefix; prefer an allowlist of file names.",
        pattern=re.compile(r"""(?:fs|tokio::fs)::(?:read_to_string|read|write|File::open)\([^)\n]*(?:user|input|param|name|path)"""),
        languages=("rust",),
    ),
    Rule(
        id="rust-unwrap-input",
        kind="Unhandled error",
        severity="low",
        why="Parsed input is unwrapped. A malformed value panics the worker.",
        patch="Handle the error and return a 4xx; a panic is a free denial of service.",
        pattern=re.compile(r"""(?:parse|from_str|decode|from_utf8)[^;\n]*\.unwrap\(\)"""),
        languages=("rust",),
    ),
    # PHP
    Rule(
        id="php-sql-request",
        kind="SQL injection",
        severity="high",
        why="A query built with request data reaches the database driver.",
        patch="Use prepared statements: $stmt = $pdo->prepare('… WHERE id = ?'); $stmt->execute([$id]);",
        pattern=re.compile(r"""(?:->query|mysqli_query|mysql_query|pg_query)\s*\(\s*["'][^"']*\$_(?:GET|POST|REQUEST|COOKIE)"""),
        languages=("php",),
    ),
    Rule(
        id="php-sql-concat",
        kind="SQL injection",
        severity="high",
        why="A SQL string is concatenated with request data.",
        patch="Bind the value; never concatenate it into the statement.",
        pattern=re.compile(r"""\$sql\s*=\s*["'][^"']*["']\s*\.\s*\$_(?:GET|POST|REQUEST|COOKIE)"""),
        languages=("php",),
    ),
    Rule(
        id="php-shell",
        kind="Command injection",
        severity="high",
        why="A shell function receives request data.",
        patch="Use escapeshellarg on every argument, or drop the shell call entirely.",
        pattern=re.compile(r"""\b(?:system|exec|shell_exec|passthru|popen|proc_open)\s*\(\s*[^)\n]*\$_(?:GET|POST|REQUEST|COOKIE)"""),
        languages=("php",),
    ),
    Rule(
        id="php-eval",
        kind="Remote code execution",
        severity="high",
        why="eval() receives request data.",
        patch="Remove eval. There is no safe way to run request data as PHP.",
        pattern=re.compile(r"""\beval\s*\(\s*[^)\n]*\$_(?:GET|POST|REQUEST|COOKIE)"""),
        languages=("php",),
    ),
    Rule(
        id="php-include",
        kind="Local file inclusion",
        severity="high",
        why="include/require takes a request-derived path.",
        patch="Map an allowlisted key to a fixed file; never include a path from input.",
        pattern=re.compile(r"""\b(?:include|include_once|require|require_once)\s*\(?\s*[^)\n]*\$_(?:GET|POST|REQUEST|COOKIE)"""),
        languages=("php",),
    ),
    Rule(
        id="php-upload",
        kind="Unsafe upload",
        severity="medium",
        why="An uploaded file is moved into place without a name or type check.",
        patch="Generate the stored name, allowlist extensions, store outside the web root.",
        pattern=re.compile(r"""move_uploaded_file\s*\("""),
        languages=("php",),
    ),
    Rule(
        id="php-unserialize",
        kind="Unsafe deserialization",
        severity="high",
        why="unserialize() receives request data and can construct objects.",
        patch="Use json_decode; if you must, pass allowed_classes to unserialize.",
        pattern=re.compile(r"""unserialize\s*\(\s*[^)\n]*\$_(?:GET|POST|REQUEST|COOKIE)"""),
        languages=("php",),
    ),
    # JavaScript / TypeScript
    Rule(
        id="js-sql-template",
        kind="SQL injection",
        severity="high",
        why="A query is assembled with a template literal. The interpolated value becomes SQL syntax.",
        patch="Use placeholders: db.query('… WHERE id = $1', [id]).",
        pattern=re.compile(r"""(?:query|execute|raw)\s*\(\s*`[^`]*\$\{"""),
        languages=("javascript", "typescript"),
    ),
    Rule(
        id="js-eval",
        kind="Remote code execution",
        severity="high",
        why="eval() receives request data.",
        patch="Remove eval. Parse JSON or dispatch through a lookup table.",
        pattern=re.compile(r"""\beval\s*\(\s*(?:req\.|request\.|ctx\.|event\.)"""),
        languages=("javascript", "typescript"),
    ),
    Rule(
        id="js-path",
        kind="Path traversal",
        severity="high",
        why="A filesystem read receives request-derived data.",
        patch="Resolve against a fixed root and verify the result stays inside it.",
        pattern=re.compile(r"""(?:readFile|readFileSync|sendFile|createReadStream|writeFile)\s*\([^)\n]*\breq\."""),
        languages=("javascript", "typescript"),
    ),
    Rule(
        id="js-xss",
        kind="Cross-site scripting",
        severity="medium",
        why="Request data is written into markup without escaping.",
        patch="Use textContent, or a templating engine with autoescaping on.",
        pattern=re.compile(r"""\.innerHTML\s*=\s*(?:req\.|data\.|user|`[^`]*\$\{)"""),
        languages=("javascript", "typescript"),
    ),
    Rule(
        id="js-exec-request",
        kind="Command injection",
        severity="high",
        why="child_process receives request-derived data.",
        patch="Use execFile with an argument array, and allowlist the program.",
        pattern=re.compile(r"""\b(?:exec|execSync|execFile|spawn|spawnSync)\s*\(\s*[^)\n]*(?:req\.|request\.|`[^`]*\$\{)"""),
        languages=("javascript", "typescript"),
    ),
    Rule(
        id="js-jwt-noverify",
        kind="JWT verification bypass",
        severity="high",
        why="jwt.decode is called without a key or algorithms list, so nothing is verified.",
        patch="Use jwt.verify(token, key, { algorithms: ['HS256'] }).",
        pattern=re.compile(r"""jwt\.decode\s*\(\s*[^,)]+\s*\)"""),
        languages=("javascript", "typescript"),
    ),
    # Java / Kotlin
    Rule(
        id="java-sql-concat",
        kind="SQL injection",
        severity="high",
        why="A statement is built by concatenating request data.",
        patch="Use a PreparedStatement with ? placeholders.",
        pattern=re.compile(r"""(?:executeQuery|executeUpdate|execute|prepareStatement)\s*\(\s*"[^"]*"\s*\+"""),
        languages=("java", "kotlin"),
    ),
    Rule(
        id="java-path",
        kind="Path traversal",
        severity="high",
        why="A file path is built from request data.",
        patch="Normalise and check the prefix; prefer an allowlist of names.",
        pattern=re.compile(r"""new\s+File\s*\(\s*request\.getParameter"""),
        languages=("java", "kotlin"),
    ),
    # C#
    Rule(
        id="cs-sql-concat",
        kind="SQL injection",
        severity="high",
        why="A SqlCommand text is built by concatenation.",
        patch="Use SqlParameter, not string concatenation.",
        pattern=re.compile(r"""new\s+SqlCommand\s*\(\s*"[^"]*"\s*\+"""),
        languages=("csharp",),
    ),
    Rule(
        id="cs-process",
        kind="Command injection",
        severity="high",
        why="Process.Start takes request-derived or user-supplied arguments.",
        patch="Allowlist the executable and pass fixed arguments.",
        pattern=re.compile(r"""Process\.Start\([^)\n]*(?:Request|request|req\.|name|args\[|input)"""),
        languages=("csharp",),
    ),
    # C / C++
    Rule(
        id="c-unsafe-copy",
        kind="Unsafe C string function",
        severity="high",
        why="An unbounded copy or format function writes into a fixed buffer.",
        patch="Use strncpy/snprintf and check the return value, or a sized buffer type.",
        pattern=re.compile(r"""\b(?:strcpy|strcat|sprintf|gets|scanf)\s*\("""),
        languages=("c", "cpp"),
    ),
    Rule(
        id="c-memcpy-length",
        kind="Unsafe memory copy",
        severity="medium",
        why="memcpy is used without a sizeof bound in the surrounding lines.",
        patch="Bound the length against the destination size: min(len, sizeof(dst)).",
        pattern=re.compile(r"""\bmemcpy\s*\("""),
        absent=("sizeof",),
        languages=("c", "cpp"),
    ),
    Rule(
        id="c-shell",
        kind="Command injection",
        severity="high",
        why="A shell or process launcher is called from C/C++ code.",
        patch="Use execve with an argument vector; never pass input through a shell.",
        pattern=re.compile(r"""\b(?:system|popen|execl|execlp|execv|execvp)\s*\("""),
        languages=("c", "cpp"),
    ),
    # Ruby
    Rule(
        id="rb-sql-interp",
        kind="SQL injection",
        severity="high",
        why="A query is built with string interpolation.",
        patch="Use a placeholder: where('id = ?', id).",
        pattern=re.compile(r"""where\(\s*"[^"]*#\{"""),
        languages=("ruby",),
    ),
    Rule(
        id="rb-shell",
        kind="Command injection",
        severity="high",
        why="A shell call receives request data.",
        patch="Use the array form of system() with validated arguments.",
        pattern=re.compile(r"""\b(?:system|exec|spawn)\s*\(?\s*(?:params|ARGV|request)"""),
        languages=("ruby",),
    ),
    Rule(
        id="rb-eval",
        kind="Remote code execution",
        severity="high",
        why="eval receives request data.",
        patch="Remove eval; dispatch through an explicit allowlist.",
        pattern=re.compile(r"""\beval\s*\(\s*params"""),
        languages=("ruby",),
    ),
    # Lua
    Rule(
        id="lua-loadstring",
        kind="Remote code execution",
        severity="medium",
        why="loadstring compiles a string at runtime.",
        patch="Load a fixed chunk; never compile request data.",
        pattern=re.compile(r"""\bloadstring\s*\("""),
        languages=("lua",),
    ),
    Rule(
        id="lua-exec",
        kind="Command injection",
        severity="high",
        why="os.execute runs a shell command.",
        patch="Avoid the shell; validate every argument against an allowlist.",
        pattern=re.compile(r"""os\.execute\s*\("""),
        languages=("lua",),
    ),
    Rule(
        id="py-key-truncation",
        kind="Crypto: weak key",
        severity="high",
        why="An integer key is converted through hex() and cut to a length.",
        patch="Build the key with os.urandom; never derive it from a hex string slice.",
        pattern=re.compile(r"""\bhex\(\s*\w*key\w*\s*\)\s*\[""", re.I),
        languages=("python",),
    ),
    Rule(
        id="py-static-iv",
        kind="Crypto: static IV",
        severity="medium",
        why="The IV is taken from the key or a constant instead of fresh randomness.",
        patch="Random IV per message (CBC) or nonce (GCM); send it with the ciphertext.",
        pattern=re.compile(r"""\biv\s*=\s*(?:\w*key\w*(?:\s*\[[^\]]*\])?|b?["'][^"']*["'])""", re.I),
        languages=("python",),
    ),
    Rule(
        id="py-xor-reuse",
        kind="Crypto: repeating-key XOR",
        severity="high",
        why="The keystream repeats: the same key bytes are reused for the whole message.",
        patch="Use a stream cipher with a nonce or AES-GCM; repeating XOR leaks both texts.",
        pattern=re.compile(r"""zip\([^,]+,\s*cycle\(""", re.I),
        languages=("python",),
    ),
    Rule(
        id="js-weak-sanitizer",
        kind="Manual input filter",
        severity="medium",
        why="Input is filtered with a character blacklist instead of validated.",
        patch="Validate by type and allowlist; pass values as parameters, not as SQL text.",
        pattern=re.compile(r"""\.replace\(\s*/\s*\[\^"""),
        languages=("javascript", "typescript"),
    ),
    Rule(
        id="cs-weak-token",
        kind="Weak session token",
        severity="high",
        why="The session token is a hash of a rotating seed plus a small counter: the id part is guessable and the seed leaks with every token.",
        patch="Sign a random value with an HMAC key kept server-side; store only the digest. Do not build tokens from a counter.",
        pattern=re.compile(r"""\b(?:Convert\.ToBase64String|BitConverter\.GetBytes)\s*\("""),
        context=re.compile(r"""(?s)(?:GetSha256|SHA256|sha256).{0,600}(?:Convert\.ToBase64String|ToBase64String)|(?:Convert\.ToBase64String|ToBase64String).{0,600}(?:GetSha256|SHA256|sha256)"""),
        window=8,
        once=True,
        languages=("csharp",),
    ),
    Rule(
        id="php-laravel-idor",
        kind="IDOR / BOLA",
        severity="high",
        why="A record is looked up by a value taken straight from the request: any id returns any owner's object.",
        patch="Scope the query to the current user: where('user_id', auth()->id())->find($id), or check the policy before returning.",
        pattern=re.compile(r"""->where\(\s*["'][^"']+["']\s*,\s*(?:request\(|\$_(?:GET|POST|REQUEST))""", re.I),
        languages=("php",),
    ),
    Rule(
        id="php-laravel-ssrf",
        kind="SSRF",
        severity="medium",
        why="The server fetches a URL taken from the request: internal addresses become reachable through the service.",
        patch="Allowlist hosts and schemes; resolve and reject private ranges before the request.",
        pattern=re.compile(r"""(?:Http::(?:get|post|put|patch)|file_get_contents|curl_init)\s*\(\s*(?:request\(|\$_(?:GET|POST|REQUEST))""", re.I),
        languages=("php",),
    ),
    Rule(
        id="crypto-custom-cipher",
        kind="Crypto: custom cipher",
        severity="medium",
        why="A hand-written block cipher or its key schedule: rotations, S-boxes and a fixed number of rounds chosen by the author, not a reviewed primitive.",
        patch="Replace with AES-GCM or ChaCha20-Poly1305 from a maintained library; keep only the key exchange custom.",
        pattern=re.compile(r"""\b(?:FEAL|Feistel|feistel|S-?box|sbox|key_?schedule|key_?expansion)\b"""),
    ),
    Rule(
        id="logic-balance-update",
        kind="Business logic: balance update",
        severity="medium",
        why="A balance is incremented in place with no idempotency key and no transaction guard: replaying the request adds money again.",
        patch="Mark the source document used inside the same transaction (UPDATE ... WHERE is_used=false RETURNING), then credit once.",
        pattern=re.compile(r"""(?:\bbalance\s*=\s*balance\s*\+|SET\s+balance\s*=\s*balance\s*\+|\bbalance\s*\+=)""", re.I),
    ),
    Rule(
        id="logic-missing-owner-check",
        kind="Business logic: object owner",
        severity="high",
        why="The object is loaded by an identifier from the request and returned without checking the owner.",
        patch="Compare the object owner with the session principal before acting; return 404 on mismatch.",
        pattern=re.compile(r"""\bget_object_or_404\(\s*\w+\s*,\s*(?:pk|id)\s*=|\.objects\.get\(\s*(?:pk|id)\s*="""),
        languages=("python",),
    ),
    Rule(
        id="cpp-boost-archive",
        kind="Unsafe deserialization",
        severity="high",
        why="A boost archive is reconstructed from untrusted bytes: the library trusts the sizes it reads (CVE-2023-34399 class).",
        patch="Do not deserialize from the network; use a versioned schema with length checks, or protobuf/JSON with a size cap.",
        pattern=re.compile(r"""boost::archive::(?:text|binary|xml|polymorphic)_iarchive|#include\s*<boost/archive/[^>]*_iarchive"""),
        languages=("c", "cpp"),
    ),
    Rule(
        id="go-owner-from-request",
        kind="Business logic: owner from request",
        severity="high",
        why="The owner of a new object is taken from a request field, so any user can create objects under another user's name.",
        patch="Take the owner from the session or token claims only; ignore an owner field sent by the client.",
        pattern=re.compile(r"""\breq\.(?:Username|UserID|UserId|OwnerID|OwnerId|SellerID|SellerId|Role)\b""", re.I),
        context=re.compile(r"""(?s)Owner(?:ID|Id)\s*[:=].{0,300}req\.(?:Username|UserID|UserId|SellerID)|req\.(?:Username|UserID|UserId|SellerID).{0,300}Owner(?:ID|Id)\s*[:=]"""),
        window=8,
        once=True,
        languages=("go",),
    ),
    Rule(
        id="infra-image-latest",
        kind="Infrastructure: mutable image tag",
        severity="medium",
        why="The container image is pinned to a mutable tag: the next pull can bring a different build, including a vulnerable one.",
        patch="Pin the image by digest or exact version; update deliberately.",
        pattern=re.compile(r"""\bimage:\s*["']?[\w./-]+:latest\b"""),
    ),
    Rule(
        id="infra-privileged",
        kind="Infrastructure: privileged container",
        severity="high",
        why="A privileged container has the host's devices and kernel capabilities: an escape is a root shell on the node.",
        patch="Drop privileged; grant only the capabilities the workload needs.",
        pattern=re.compile(r"""\bprivileged:\s*true\b"""),
    ),
    Rule(
        id="infra-hostpath",
        kind="Infrastructure: host path mount",
        severity="medium",
        why="A host directory is mounted into the pod: code in the container writes to the node filesystem.",
        patch="Use a dedicated volume or CSI; never mount /, /etc, /var/run or the docker socket.",
        pattern=re.compile(r"""\bhostPath:\s*$|path:\s*["']?/(?:etc|var/run|root|)\b""", re.M),
    ),
    Rule(
        id="secret-minio-default",
        kind="Hardcoded secret",
        severity="high",
        why="Default object-storage credentials are in use: anyone who knows the default signs requests as the service.",
        patch="Generate credentials at deploy time and pass them through a secret.",
        pattern=re.compile(r"""\bminioadmin\b|access_key\s*[:=]\s*["'][A-Z0-9]{16,}["']""", re.I),
    ),
)

RULES: tuple[Rule, ...] = RULES + LANG_RULES

# Сборки, вендоренные копии и минифицированные бандлы: находки в них — шум,
# который отнимает внимание в раунде (three.core.min.js, chunk-vendors, crow/json.h).
GENERATED_MARKERS = (
    "/node_modules/",
    "/vendor/",
    "/third_party/",
    "/3rdparty/",
    "/external/",
    "/public/js/",
    "/static/js/",
    "/dist/",
    "/build/static/",
    ".min.js",
    ".min.css",
    "chunk-vendors",
    "-bundle.js",
    ".map",
)


def is_generated(path: str, lines: list[str]) -> bool:
    """Файл — сборка или чужой код, а не сервис, который правит команда."""
    low = path.lower()
    if any(marker in low for marker in GENERATED_MARKERS):
        return True
    if not lines:
        return False
    longest = max((len(line) for line in lines[:400]), default=0)
    if longest > 2000:
        return True
    average = sum(len(line) for line in lines) / len(lines)
    if average > 400:
        return True
    # Заголовок на тысячу строк — это библиотека, а не код сервиса.
    if low.endswith((".h", ".hpp", ".hh")) and len(lines) > 800:
        return True
    return False


def scan_text(path: str, text: str, language: str | None = None) -> list[dict]:
    """Return findings for one file. Line-based, context ±3 lines, deduped."""
    lines = text.splitlines()
    findings: list[dict] = []
    seen: set[tuple[str, int]] = set()
    seen_kind: set[tuple[str, int]] = set()
    detected = language or language_of(path, text)
    if is_generated(path, lines):
        return findings
    for rule in RULES:
        if rule.languages and detected not in rule.languages:
            continue
        if rule.context is not None:
            # контекстные правила считаются отдельным проходом по окну строк
            continue
        for number, line in enumerate(lines, 1):
            stripped = line.lstrip()
            if stripped.startswith(("//", "/*", "*", "<!--", "--")):
                # комментарий описывает дыру, но дырой не является
                continue
            if stripped.startswith("#") and detected not in {"c", "cpp", "csharp", "go", "rust", "java", "kotlin", "php"}:
                continue
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
    for rule in RULES:
        if rule.context is None:
            continue
        if rule.languages and detected not in rule.languages:
            continue
        span = max(1, rule.window)
        for number in range(1, len(lines) + 1):
            low = max(0, number - 1 - span)
            high = min(len(lines), number + span)
            window_text = "\n".join(lines[low:high])
            if rule.context.search(window_text) is None:
                continue
            if (rule.id, number) in seen:
                continue
            seen.add((rule.id, number))
            digest = hashlib.sha1(f"{path}:{number}:{rule.id}".encode()).hexdigest()[:10]
            findings.append({
                "id": digest,
                "rule": rule.id,
                "kind": rule.kind,
                "severity": rule.severity,
                "file": path,
                "line": number,
                "snippet": lines[number - 1].strip()[:240],
                "context": lines[max(0, number - 4): min(len(lines), number + 3)],
                "context_start": max(0, number - 4) + 1,
                "why": rule.why,
                "patch": rule.patch,
                "checker_risk": "high",
                "language": language or language_of(path),
            })
            if rule.once:
                break
    findings.sort(key=lambda item: (SEVERITY_ORDER.get(item["severity"], 9), item["file"], item["line"]))
    return findings


_ROUTE_DECORATOR = re.compile(r"""@\w+\.(route|get|post|put|delete|patch)\(\s*["']([^"']+)""", re.I)
_ROUTE_DOTTED = re.compile(r"""\.(GET|POST|PUT|DELETE|PATCH|Get|Post|Put|Delete|Patch)\(\s*["']([^"']+)""")
_ROUTE_GO_STD = re.compile(r"""\b(?:http|mux)\.HandleFunc\(\s*["']([^"']+)""")
_ROUTE_DISPATCH = re.compile(
    r"""(?:self\.path|\bpath|route|req\.url|url\.pathname)\s*(?:===?|\.equals\(|in\s*\()\s*["'](/[^"']+)"""
)
_ROUTE_GO_HANDLE = re.compile(r"""\.(?:HandleFunc|Handle)\(\s*["']([^"']+)""")
_ROUTE_LARAVEL = re.compile(r"""Route::(get|post|put|delete|patch)\(\s*["']([^"']+)""", re.I)
_ROUTE_SPRING = re.compile(r"""@(Get|Post|Put|Delete|Patch|Request)Mapping\(\s*(?:value\s*=\s*)?["']([^"']+)""")
_ROUTE_ASPNET = re.compile(r"""\[Http(Get|Post|Put|Delete|Patch)(?:\(\s*["']?([^"')\]]*)["']?\))?\]""")
_ROUTE_AXUM = re.compile(r"""\.route\(\s*["']([^"']+)["']\s*,\s*(get|post|put|delete|patch)""", re.I)
_ROUTE_ATTRIBUTE = re.compile(r"""#\[(get|post|put|delete|patch)\(\s*["']([^"']+)""", re.I)
_ROUTE_RAILS = re.compile(r"""^\s*(get|post|put|delete|patch)\s+["']([^"']+)""", re.I)
_ROUTE_RESOURCES = re.compile(r"""^\s*resources\s+:(\w+)""")
_ROUTE_PHP_PARAM = re.compile(r"""\$_GET\[\s*["']([^"']+)""")

# (pattern, method: group index or literal, path group)
_ENDPOINT_PATTERNS: tuple[tuple[re.Pattern, object, int], ...] = (
    (_ROUTE_DECORATOR, 1, 2),      # flask, fastapi, blueprint, nestjs-style decorators
    (_ROUTE_DOTTED, 1, 2),         # gin, chi, echo, fiber, express, koa, fastify
    (_ROUTE_GO_STD, "ANY", 1),     # net/http, gorilla mux
    (_ROUTE_GO_HANDLE, "ANY", 1),
    (_ROUTE_DISPATCH, "ANY", 1),   # ручной роутинг: if path == "/api/x"
    (_ROUTE_LARAVEL, 1, 2),
    (_ROUTE_SPRING, 1, 2),
    (_ROUTE_ASPNET, 1, 2),
    (_ROUTE_AXUM, 2, 1),
    (_ROUTE_ATTRIBUTE, 1, 2),      # actix, rocket
    (_ROUTE_RAILS, 1, 2),
    (_ROUTE_RESOURCES, "ANY", 1),
    (_ROUTE_PHP_PARAM, "PARAM", 1),
)


def map_endpoints(path: str, text: str) -> list[dict]:
    """Best-effort endpoint extraction across the frameworks shipped in rules."""
    endpoints: list[dict] = []
    seen: set[tuple[str, str]] = set()

    def plausible(raw: str) -> bool:
        # Регистрируется маршрут, а не путь к файлу: строка с расширением
        # (`/tmp/notes_ping.txt`) или без ведущего слэша — не ручка.
        if not raw.startswith("/") or " " in raw or len(raw) > 120:
            return False
        last = raw.rsplit("/", 1)[-1]
        if "." in last and not last.startswith("{") and not last.startswith(":"):
            return False
        return True

    for number, line in enumerate(text.splitlines(), 1):
        for pattern, method_spec, path_group in _ENDPOINT_PATTERNS:
            match = pattern.search(line)
            if not match:
                continue
            raw_path = match.group(path_group) or "/"
            if isinstance(method_spec, int):
                method = (match.group(method_spec) or "ANY").upper()
            else:
                method = str(method_spec)
            if pattern is _ROUTE_RESOURCES:
                raw_path = "/" + raw_path
            if method in {"REQUEST", "ROUTE"}:
                method = "ANY"
            if not plausible(raw_path):
                continue
            key = (method, raw_path)
            if key in seen:
                continue
            seen.add(key)
            endpoints.append({"path": raw_path, "method": method, "file": path, "line": number})
    return endpoints


def find_flags(text: str) -> list[str]:
    return FLAG_RE.findall(text)


def find_checker_refs(text: str) -> list[str]:
    return CHECKER_RE.findall(text)


def coverage_matrix() -> list[dict]:
    """Rules-per-language table for the UI."""
    rows: list[dict] = []
    for entry in COVERAGE:
        code = entry["language"]
        count = sum(1 for rule in RULES if not rule.languages or code in rule.languages)
        rows.append({
            "language": entry["language"],
            "shown_as": entry["shown as"],
            "depth": entry["depth"],
            "rules": count,
        })
    return rows


def rule_catalog() -> list[dict]:
    return [
        {"id": rule.id, "kind": rule.kind, "severity": rule.severity,
         "why": rule.why, "patch": rule.patch,
         "languages": list(rule.languages) or ["any"]}
        for rule in RULES
    ]
