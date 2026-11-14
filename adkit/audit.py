"""Read-only audit engine.

Only fixed, read-only commands are executed on the target. The engine never
writes files, never restarts services and never sends traffic to the checker.
"""
from __future__ import annotations

import re
import shlex
import tarfile
import tempfile
import time
import zipfile
from pathlib import Path

from . import binaries, patterns, priority, ru
from .binaries import ELF_COMMAND, STRINGS_COMMAND
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
pids=$(ss -lntp 2>/dev/null | grep -o 'pid=[0-9]*' | cut -d= -f2 | sort -u)
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
    "find {roots} -maxdepth 8 -type f \\("
    " -name '*.py' -o -name '*.go' -o -name '*.rs' -o -name '*.js' -o -name '*.mjs' -o -name '*.ts'"
    " -o -name '*.jsx' -o -name '*.tsx' -o -name '*.vue' -o -name '*.svelte'"
    " -o -name '*.php' -o -name '*.rb' -o -name '*.java' -o -name '*.kt' -o -name '*.cs'"
    " -o -name '*.c' -o -name '*.cc' -o -name '*.cpp' -o -name '*.h' -o -name '*.hpp'"
    " -o -name '*.lua' -o -name '*.pl' -o -name '*.sh' -o -name '*.sql' -o -name '*.proto'"
    " -o -name '*.yml' -o -name '*.yaml' -o -name '*.toml' -o -name '*.ini'"
    " -o -name 'Dockerfile' -o -name '*.service' -o -name '*.conf'"
    " \\) 2>/dev/null"
    " | grep -vE '/(_checker|node_modules|\\.git|vendor|target|dist|build|__pycache__|site-packages|\\.venv)/'"
    " | head -400"
)

MANIFEST_COMMAND = (
    "find {roots} -maxdepth 8 -type f \\("
    " -name 'go.mod' -o -name 'Cargo.toml' -o -name 'package.json' -o -name 'composer.json'"
    " -o -name 'pom.xml' -o -name 'build.gradle' -o -name 'build.gradle.kts' -o -name 'Gemfile'"
    " -o -name 'requirements.txt' -o -name 'pyproject.toml' -o -name 'Pipfile' -o -name '*.csproj'"
    " -o -name 'Dockerfile' -o -name 'docker-compose.yml' -o -name 'docker-compose.yaml'"
    " \\) 2>/dev/null"
    " | grep -vE '/(_checker|node_modules|\\.git|vendor|target|__pycache__|site-packages|\\.venv)/'"
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
        # у php и node в одной строке несколько pid: берём первый, для которого
        # прочитан /proc, иначе cwd и cmdline теряются
        all_pids = [int(value) for value in re.findall(r"pid=(\d+)", line)]
        detail = next((pids[value] for value in all_pids if value in pids), {})
        if detail:
            pid = next(value for value in all_pids if value in pids)
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
            "root": root_from_cmdline(cmdline),
            "cmdline": cmdline[:300],
            "service": name or "unknown",
            "language": patterns.language_of(name) if name else "unknown",
        }
    return [services[port] for port in sorted(services)]


SYSTEM_ROOTS = (
    "/usr",
    "/etc",
    "/var/lib",
    "/var/log",
    "/var/cache",
    "/var/run",
    "/run",
    "/proc",
    "/sys",
    "/dev",
    "/boot",
    "/tmp",
    "/snap",
    "/lib",
    "/lib64",
    "/bin",
    "/sbin",
    "/mnt",
    "/media",
)


def root_from_cmdline(cmdline: str) -> str:
    """Каталог сервиса из командной строки процесса.

    `php -S 0.0.0.0:8083 -t /srv/warehouse`, `python3 /srv/app/main.py` —
    cwd у таких процессов часто `/`, и без этой подсказки стек не определяется.
    """
    parts = (cmdline or "").split()
    for index, token in enumerate(parts):
        if token.startswith("--root=") or token.startswith("--app-dir="):
            value = token.split("=", 1)[1]
            if value.startswith("/"):
                return value.rstrip("/")
        if token in {"-t", "--root", "--app-dir", "--directory", "-d"} and index + 1 < len(parts):
            value = parts[index + 1]
            if value.startswith("/"):
                return value.rstrip("/")
    for token in parts:
        if token.startswith("/") and token.endswith((".py", ".js", ".mjs", ".rb", ".php")):
            return str(Path(token).parent)
    return ""


def normalise_roots(roots: list[str]) -> list[str]:
    """Оставляет каталоги сервисов, выкидывает корень и системные деревья.

    cwd слушающего процесса бывает `/`, `/usr/sbin`, `/var/lib/...`: скан
    такого корня — это обход всей файловой системы, таймаут и мусор в
    находках. Оставляем только то, что похоже на каталог приложения, и
    убираем вложенные корни, если родитель уже есть.
    """
    cleaned: set[str] = set(DEFAULT_ROOTS)
    for raw in roots:
        root = (raw or "").rstrip("/") or "/"
        if root == "/" or not root.startswith("/"):
            continue
        if any(root == prefix or root.startswith(prefix + "/") for prefix in SYSTEM_ROOTS):
            continue
        parts = [part for part in root.split("/") if part]
        if len(parts) < 2:
            continue
        cleaned.add(root)

    ordered = sorted(cleaned, key=lambda item: (len(item), item))
    result: list[str] = []
    for root in ordered:
        if any(root == kept or root.startswith(kept + "/") for kept in result):
            continue
        result.append(root)
    return result[:10]


def roots_from_pids(pids: dict[int, dict]) -> list[str]:
    roots = {detail["cwd"] for detail in pids.values() if detail.get("cwd", "").startswith("/")}
    return normalise_roots(sorted(roots))


def _sink_variables(line: str) -> list[str]:
    """Variables that reach the sink on this line, most specific first."""
    names: list[str] = []

    def add(name: str) -> None:
        if name in {"self", "this", "req", "request", "err", "error", "title", "body", "id"}:
            # id/title/body — имена колонок, а не параметров; их берём только
            # если они подставлены интерполяцией (ниже), не из текста запроса
            if name not in {"id", "title", "body"}:
                return
        if name not in names:
            names.append(name)

    # сильные признаки: значение подставлено в строку
    for pattern in (r"\{(\w+)\}", r"\$\{?(\w+)\}?", r"\+\s*\$?(\w+)"):
        for match in re.finditer(pattern, line):
            add(match.group(1))
    # слабые: аргументы вызова, суперглобальные, правая часть присваивания
    for pattern in (
        r"\$_(?:GET|POST|REQUEST|COOKIE|SERVER)\[\s*[\"']?(\w+)",
        r"[\(\,]\s*\$?([a-zA-Z_]\w*)\s*(?=[,\)])",
        r"=\s*\$?([a-zA-Z_]\w*)\s*(?=[;,)]|$)",
    ):
        for match in re.finditer(pattern, line):
            name = match.group(1)
            if name not in names:
                names.append(name)
    return names


PARAM_READ = re.compile(
    r"""(?:\.get|\.one|\bone|Query|Param|FormValue|Input|params?|args?|request|GET|POST)\s*[\(\[][^,)\]\n]{0,12}?["'](\w+)["']""",
    re.IGNORECASE,
)


def guess_param_detail(lines: list[str], index: int) -> tuple[str, int] | None:
    """(параметр, строка его чтения) для sink-строки."""
    if not lines or index < 0 or index >= len(lines):
        return None
    variables = _sink_variables(lines[index])
    if not variables:
        return None
    best: tuple[tuple[int, int], str, int] | None = None
    for number, line in enumerate(lines):
        for match in PARAM_READ.finditer(line):
            name = match.group(1)
            if name in variables:
                rank = variables.index(name)
            else:
                # `const term = q.get("q")`: переменная sink присваивается
                # из параметра в этой же строке
                assigned = [variable for variable in variables
                            if re.search(rf"\b{variable}\w*\s*=", line)]
                if not assigned:
                    continue
                rank = len(variables) + variables.index(assigned[0])
            key = (rank, abs(number - index))
            if best is None or key < best[0]:
                best = (key, name, number)
    return (best[1], best[2]) if best else None


def guess_param(lines: list[str], index: int) -> str | None:
    """Which request parameter feeds this line.

    The sink names its variable (`... {q} ...`). The handler reads that
    variable from a parameter somewhere else in the file (`one("q")`,
    `$_GET['q']`). The nearest read wins.
    """
    detail = guess_param_detail(lines, index)
    return detail[0] if detail else None


def attach_endpoint(endpoints: list[dict], lines: list[str], read_line: int, sink_line: int) -> str:
    """Ручка, в чьём блоке читается параметр.

    Ручной роутинг (`if path == "/api/search":`) идёт таблицей: адрес, под ним
    обработчик. Параметр читается внутри блока своего обработчика, поэтому
    ищем блок, где встречается литерал параметра, а не просто ближайшую строку.
    """
    if not endpoints:
        return "/"
    first = endpoints[0]["line"]
    last = endpoints[-1]["line"]
    if read_line + 1 > last or read_line + 1 < first:
        # параметр читается вне таблицы маршрутов — это скрипт верхнего уровня
        return "/"
    name = None
    if 0 <= read_line < len(lines):
        for match in PARAM_READ.finditer(lines[read_line]):
            name = match.group(1)
            break
    candidates: list[tuple[int, str]] = []
    if name:
        literals = (f'"{name}"', f"'{name}'")
        for position, endpoint in enumerate(endpoints):
            start = max(0, endpoint["line"] - 1)
            end = endpoints[position + 1]["line"] - 1 if position + 1 < len(endpoints) else len(lines)
            block = "\n".join(lines[start:end])
            if any(literal in block for literal in literals):
                candidates.append((abs(start - read_line), endpoint["path"]))
    if candidates:
        candidates.sort()
        return candidates[0][1]

    if name is None:
        # параметр не определён: ручку не угадываем, корень нейтрален
        return "/"
    nearest = min(endpoints, key=lambda endpoint: abs(endpoint["line"] - (sink_line + 1)))
    return nearest["path"]


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
        lines = text.splitlines()
        file_endpoints = sorted(patterns.map_endpoints(path, text), key=lambda item: item["line"])
        for finding in file_findings:
            index = int(finding.get("line", 1)) - 1
            detail = guess_param_detail(lines, index)
            if detail:
                finding["param"], read_line = detail
                finding["endpoint"] = attach_endpoint(file_endpoints, lines, read_line, index)
        findings.extend(file_findings)
        endpoints.extend(file_endpoints)
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
        base = item.get("cwd") or ""
        if base in {"", "/"}:
            base = item.get("root") or base
        stack = stack_for(base, stacks)
        item["stack"] = stack["label"]
        item["languages"] = stack["languages"]
        item["frameworks"] = stack["frameworks"]
        enriched_services.append(item)

    for item in findings:
        if not item.get("kind_ru"):
            item["kind_ru"] = ru.kind_ru(item.get("kind", ""))
        if not item.get("patch_ru"):
            item["patch_ru"] = ru.patch_ru(item.get("rule", ""), item.get("patch", ""))
        priority.enrich(item)
    findings.sort(key=priority.sort_key)

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

    def _scan_binaries(self, roots: list[str]) -> list[dict]:
        """Строки ELF-бинарников в каталогах сервисов: оболочка, строки C, флаги."""
        roots = [root for root in roots if root.startswith("/")]
        if not roots:
            return []
        command = ELF_COMMAND.format(roots=" ".join(shlex.quote(root) for root in roots), limit=8)
        out = self._run(command, timeout=40)
        paths = [line.strip() for line in out.splitlines() if line.strip().startswith("/")][:8]
        if not paths:
            return []
        findings: list[dict] = []
        for path in paths:
            text = self._run(STRINGS_COMMAND.format(path=shlex.quote(path)), timeout=30)
            findings.extend(binaries.scan_strings(text, path))
        self.log(f"binaries: {len(paths)} files, {len(findings)} findings")
        return findings

    def _read_files(self, paths: list[str]) -> dict[str, str]:
        if not paths:
            return {}
        listing = "\n".join(paths)
        # Маркер печатается с ведущим переводом строки: файл без завершающего
        # \n иначе склеивает свой хвост со следующим маркером, и содержимое
        # соседнего файла попадает в чужой буфер (номера строк уезжают).
        # head -c вместо sed -n '1,200p': файлы длиннее 200 строк читались
        # частично, и находки во второй половине файла просто не находились.
        script = (
            "while IFS= read -r f; do printf '\\n===FILE %s\\n' \"$f\"; "
            "head -c 262144 -- \"$f\" 2>/dev/null; done "
            "<<'__AD_LIST__'\n" + listing + "\n__AD_LIST__\n"
        )
        script = "(\n" + script + "\n) | head -c 8000000"
        raw = self._run(script, timeout=60)
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
        try:
            result["findings"].extend(self._scan_binaries(roots))
        except Exception as exc:  # noqa: BLE001 - бинарники не должны ронять аудит
            self.log(f"binaries skipped: {type(exc).__name__}: {exc}")
        result["os"] = [line for line in sections.get("os", "").splitlines() if line.strip()][:4]
        result["meta"].update({
            "duration_ms": int((time.time() - started) * 1000),
            "commands": self.commands,
            "roots": roots,
            "findings_total": len(result["findings"]),
        })
        self.log(f"done: {len(result['findings'])} findings")
        return result


# Оффлайн-аудит: распакованный архив сервиса, без SSH и без живого хоста.
OFFLINE_SUFFIXES = (
    ".py", ".pyw", ".go", ".rs", ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx",
    ".php", ".phtml", ".rb", ".java", ".kt", ".cs", ".c", ".h", ".cc", ".cpp",
    ".hpp", ".hh", ".lua", ".pl", ".pm", ".sql", ".proto", ".graphql", ".sh",
    ".yml", ".yaml", ".toml", ".ini", ".conf", ".service", ".tf", ".tpl",
)
OFFLINE_SKIP = {
    "node_modules", ".git", "__pycache__", "vendor", "dist", "build", "target",
    "site-packages", ".venv", "obj", "bin", ".idea", "coverage",
}


def scan_directory(root: str, log=lambda message: None) -> dict:
    """Аудит каталога: тот же движок, только источники берутся с диска."""
    base = Path(root).expanduser()
    if not base.is_dir():
        raise FileNotFoundError(f"нет каталога: {root}")
    sources: dict[str, str] = {}
    for path in sorted(base.rglob("*")):
        if not path.is_file():
            continue
        if path.suffix.lower() not in OFFLINE_SUFFIXES:
            continue
        if any(part in OFFLINE_SKIP for part in path.parts):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        sources[str(path)] = text[:262144]
    log(f"offline files: {len(sources)}")
    return analyze_sources(sources, [], f"offline:{base}")


ARCHIVE_SUFFIXES = (".zip", ".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz")


def _is_archive(path: Path) -> bool:
    name = path.name.lower()
    return any(name.endswith(suffix) for suffix in ARCHIVE_SUFFIXES)


def _extract(archive: Path, into: Path) -> None:
    """Распаковать архив сервиса во временный каталог.

    Распаковка недоверенного архива — это операция с путями: zip и tar умеют
    писать наружу через `..` и абсолютные имена. Каждый элемент проверяется
    на выход за пределы каталога до записи.
    """
    target = into.resolve()

    def safe(name: str) -> Path:
        candidate = (target / name).resolve()
        if target not in candidate.parents and candidate != target:
            raise ValueError(f"archive entry escapes the directory: {name}")
        return candidate

    if archive.name.lower().endswith(".zip"):
        with zipfile.ZipFile(archive) as handle:
            for member in handle.infolist():
                if member.is_dir():
                    continue
                destination = safe(member.filename)
                destination.parent.mkdir(parents=True, exist_ok=True)
                with handle.open(member) as source, open(destination, "wb") as sink:
                    sink.write(source.read())
        return

    with tarfile.open(archive) as handle:
        for member in handle.getmembers():
            if not member.isfile():
                continue
            destination = safe(member.name)
            destination.parent.mkdir(parents=True, exist_ok=True)
            source = handle.extractfile(member)
            if source is None:
                continue
            with source, open(destination, "wb") as sink:
                sink.write(source.read())


def scan_target(path: str, log=lambda message: None) -> dict:
    """Аудит без SSH: каталог или архив сервиса, снятый с машины любым способом.

    Это второй вход в тот же движок. Нужен там, где SSH к сервису нет: архив
    с площадки, распакованный образ, копия исходников с чужого ноутбука.
    """
    base = Path(path).expanduser()
    if base.is_dir():
        return scan_directory(str(base), log)
    if base.is_file() and _is_archive(base):
        log(f"archive: {base.name}")
        with tempfile.TemporaryDirectory(prefix="ad-audit-") as workdir:
            extracted = Path(workdir) / "src"
            extracted.mkdir()
            _extract(base, extracted)
            result = scan_directory(str(extracted), log)
        result["source"] = str(base)
        return result
    raise FileNotFoundError(f"нет ни каталога, ни архива: {path}")
