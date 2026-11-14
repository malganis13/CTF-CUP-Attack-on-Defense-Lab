"""Language and framework detection.

The auditor reads source text, so it can read any language it has rules for.
This module answers three questions:

- what language is this file (extension, then shebang, then a default)
- what framework does this manifest name
- what languages and frameworks live in a given directory tree

It also carries the coverage matrix shown in the Rules tab, so the answer to
"does this thing understand Go?" is visible in the UI instead of implied.
"""
from __future__ import annotations

import re
from pathlib import PurePosixPath

EXT_LANG = {
    ".py": "python", ".pyw": "python",
    ".go": "go",
    ".rs": "rust",
    ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript", ".jsx": "javascript",
    ".ts": "typescript", ".tsx": "typescript",
    ".php": "php", ".phtml": "php",
    ".rb": "ruby",
    ".java": "java", ".kt": "kotlin", ".kts": "kotlin",
    ".cs": "csharp",
    ".c": "c", ".h": "c",
    ".cc": "cpp", ".cpp": "cpp", ".cxx": "cpp", ".hpp": "cpp", ".hh": "cpp",
    ".lua": "lua",
    ".pl": "perl", ".pm": "perl",
    ".sh": "bash", ".bash": "bash", ".zsh": "bash",
    ".sql": "sql",
    ".yml": "yaml", ".yaml": "yaml",
    ".json": "json", ".toml": "toml", ".ini": "ini",
    ".proto": "protobuf", ".graphql": "graphql", ".gql": "graphql",
    ".vue": "vue", ".svelte": "svelte",
}

SHEBANGS = (
    (re.compile(r"python"), "python"),
    (re.compile(r"\bnode\b|\bdeno\b"), "javascript"),
    (re.compile(r"\bruby\b"), "ruby"),
    (re.compile(r"\bphp\b"), "php"),
    (re.compile(r"\b(?:ba|z|k)?sh\b"), "bash"),
    (re.compile(r"\bperl\b"), "perl"),
    (re.compile(r"\blua\b"), "lua"),
)

# Manifest name -> (regex over the manifest text, framework label)
FRAMEWORK_HINTS: dict[str, tuple[tuple[re.Pattern, str], ...]] = {
    "requirements.txt": (
        (re.compile(r"^\s*flask\b", re.I | re.M), "flask"),
        (re.compile(r"^\s*fastapi\b", re.I | re.M), "fastapi"),
        (re.compile(r"^\s*django\b", re.I | re.M), "django"),
        (re.compile(r"^\s*aiohttp\b", re.I | re.M), "aiohttp"),
        (re.compile(r"^\s*(?:bottle|sanic|tornado)\b", re.I | re.M), "wsgi"),
        (re.compile(r"^\s*sqlalchemy\b", re.I | re.M), "sqlalchemy"),
    ),
    "pyproject.toml": (
        (re.compile(r"\bflask\b", re.I), "flask"),
        (re.compile(r"\bfastapi\b", re.I), "fastapi"),
        (re.compile(r"\bdjango\b", re.I), "django"),
    ),
    "pipfile": (
        (re.compile(r"flask", re.I), "flask"),
        (re.compile(r"fastapi", re.I), "fastapi"),
        (re.compile(r"django", re.I), "django"),
    ),
    "go.mod": (
        (re.compile(r"github\.com/gin-gonic/gin"), "gin"),
        (re.compile(r"github\.com/gorilla/mux"), "gorilla/mux"),
        (re.compile(r"github\.com/labstack/echo"), "echo"),
        (re.compile(r"github\.com/gofiber/fiber"), "fiber"),
        (re.compile(r"github\.com/go-chi/chi"), "chi"),
        (re.compile(r"github\.com/julienschmidt/httprouter"), "httprouter"),
    ),
    "cargo.toml": (
        (re.compile(r"^\s*axum\b", re.I | re.M), "axum"),
        (re.compile(r"^\s*actix-web\b", re.I | re.M), "actix-web"),
        (re.compile(r"^\s*rocket\b", re.I | re.M), "rocket"),
        (re.compile(r"^\s*warp\b", re.I | re.M), "warp"),
        (re.compile(r"^\s*poem\b", re.I | re.M), "poem"),
    ),
    "package.json": (
        (re.compile(r'"express"'), "express"),
        (re.compile(r'"koa"'), "koa"),
        (re.compile(r'"fastify"'), "fastify"),
        (re.compile(r'"@nestjs/core"'), "nestjs"),
        (re.compile(r'"next"'), "next"),
        (re.compile(r'"@hapi/hapi"'), "hapi"),
    ),
    "composer.json": (
        (re.compile(r"laravel/framework"), "laravel"),
        (re.compile(r"symfony/"), "symfony"),
        (re.compile(r"slim/slim"), "slim"),
    ),
    "pom.xml": (
        (re.compile(r"spring-boot"), "spring"),
        (re.compile(r"quarkus"), "quarkus"),
        (re.compile(r"micronaut"), "micronaut"),
    ),
    "build.gradle": (
        (re.compile(r"spring-boot"), "spring"),
        (re.compile(r"ktor"), "ktor"),
    ),
    "build.gradle.kts": (
        (re.compile(r"spring-boot"), "spring"),
        (re.compile(r"ktor"), "ktor"),
    ),
    "gemfile": (
        (re.compile(r"^\s*gem\s+['\"]rails", re.I | re.M), "rails"),
        (re.compile(r"^\s*gem\s+['\"]sinatra", re.I | re.M), "sinatra"),
        (re.compile(r"^\s*gem\s+['\"]hanami", re.I | re.M), "hanami"),
    ),
    "dockerfile": (
        (re.compile(r"^FROM\s+\S*python", re.I | re.M), "python"),
        (re.compile(r"^FROM\s+\S*node", re.I | re.M), "node"),
        (re.compile(r"^FROM\s+\S*golang", re.I | re.M), "go"),
        (re.compile(r"^FROM\s+\S*php", re.I | re.M), "php"),
        (re.compile(r"^FROM\s+\S*(?:ruby|jruby)", re.I | re.M), "ruby"),
        (re.compile(r"^FROM\s+\S*(?:openjdk|jdk|jre)", re.I | re.M), "java"),
        (re.compile(r"^FROM\s+\S*rust", re.I | re.M), "rust"),
    ),
}

MANIFEST_NAMES = frozenset(FRAMEWORK_HINTS) | {"docker-compose.yml", "docker-compose.yaml", "go.sum"}

# Shown in the Rules tab. `rules` is filled from the live rule table.
COVERAGE = (
    {"language": "python", "shown as": "python", "depth": "all rules: SQL, IDOR, path, command, pickle, SSTI, JWT, upload"},
    {"language": "go", "shown as": "go", "depth": "SQL via Sprintf, exec.Command, os.ReadFile, net/http and chi/gin/echo routes"},
    {"language": "rust", "shown as": "rust", "depth": "SQL via format!, Command::arg, fs::read, unwrap on parsed input, axum/actix/rocket routes"},
    {"language": "javascript", "shown as": "js / ts", "depth": "template SQL, eval, fs read, child_process, innerHTML, jwt.decode, express/koa/fastify routes"},
    {"language": "php", "shown as": "php", "depth": "$_GET into query/eval/include/system, move_uploaded_file, unserialize, Route::"},
    {"language": "java", "shown as": "java / kotlin", "depth": "string concat SQL, new File(request), Runtime.exec, ObjectInputStream, Spring mappings"},
    {"language": "csharp", "shown as": "c#", "depth": "SqlCommand concat, Process.Start, [HttpGet] routes"},
    {"language": "c", "shown as": "c / c++", "depth": "strcpy/sprintf/gets, system/popen, memcpy with untrusted length"},
    {"language": "ruby", "shown as": "ruby", "depth": "where interpolation, system/eval, YAML.load, rails and sinatra routes"},
    {"language": "lua", "shown as": "lua", "depth": "loadstring, os.execute"},
)


def language_of(path: str, text: str | None = None) -> str:
    """Language for one path. Extension first, then shebang, then a default."""
    name = PurePosixPath(path).name
    lowered = name.lower()
    suffix = PurePosixPath(path).suffix.lower()
    if suffix in EXT_LANG:
        return EXT_LANG[suffix]
    if lowered.startswith("dockerfile") or lowered.endswith(".dockerfile"):
        return "docker"
    if lowered.endswith(".service"):
        return "systemd"
    if lowered.endswith(".sql"):
        return "sql"
    if text:
        first = text.splitlines()[0] if text.splitlines() else ""
        if first.startswith("#!"):
            for pattern, language in SHEBANGS:
                if pattern.search(first):
                    return language
    return "text"


def frameworks_from_manifest(name: str, text: str) -> list[str]:
    """Framework labels named by one manifest file."""
    hints = FRAMEWORK_HINTS.get(PurePosixPath(name).name.lower())
    if not hints:
        return []
    found = [label for pattern, label in hints if pattern.search(text)]
    return sorted(set(found))


def is_manifest(name: str) -> bool:
    lowered = PurePosixPath(name).name.lower()
    return lowered in MANIFEST_NAMES or lowered.endswith(".csproj")


def detect_stacks(sources: dict[str, str]) -> dict[str, dict]:
    """Group languages and frameworks by directory.

    Returns {directory: {"languages": [...], "frameworks": [...]}}. A service
    whose cwd sits above these directories inherits the union.
    """
    per_dir: dict[str, dict[str, set[str]]] = {}
    for path, text in sources.items():
        directory = str(PurePosixPath(path).parent)
        bucket = per_dir.setdefault(directory, {"languages": set(), "frameworks": set()})
        bucket["languages"].add(language_of(path, text))
        for framework in frameworks_from_manifest(PurePosixPath(path).name, text):
            bucket["frameworks"].add(framework)
    return {
        directory: {
            "languages": sorted(item for item in bucket["languages"] if item not in {"text", "json", "yaml", "toml", "docker", "systemd", "ini"}),
            "frameworks": sorted(bucket["frameworks"]),
        }
        for directory, bucket in per_dir.items()
    }


def stack_for(cwd: str, stacks: dict[str, dict]) -> dict:
    """Best-effort stack for a service working directory."""
    if not cwd:
        return {"languages": [], "frameworks": [], "label": ""}
    prefix = cwd.rstrip("/")
    if not prefix:
        # cwd == "/" совпадает с любым каталогом: объединение всех стеков
        # приписывало sshd язык первого попавшегося сервиса.
        return {"languages": [], "frameworks": [], "label": ""}
    languages: set[str] = set()
    frameworks: set[str] = set()
    matched = False
    for directory, entry in stacks.items():
        if directory == prefix or directory.startswith(prefix + "/"):
            matched = True
            languages.update(entry["languages"])
            frameworks.update(entry["frameworks"])
    if not matched:
        tail = PurePosixPath(prefix).name
        for directory, entry in stacks.items():
            if directory.endswith("/" + tail) or f"/{tail}/" in directory:
                languages.update(entry["languages"])
                frameworks.update(entry["frameworks"])
    primary = sorted(languages)[0] if languages else ""
    framework = sorted(frameworks)[0] if frameworks else ""
    label = "/".join(part for part in (primary, framework) if part)
    return {"languages": sorted(languages), "frameworks": sorted(frameworks), "label": label}
