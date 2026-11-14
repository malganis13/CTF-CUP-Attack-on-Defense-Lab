"""Read-only audit engine.

Only fixed, read-only commands are executed on the target. The engine never
writes files, never restarts services and never sends traffic to the checker.
"""
from __future__ import annotations

import re
import shlex
import time
from pathlib import Path

from . import patterns, ru
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
    " | grep -vE '/(_checker|node_modules|\\.git|vendor|target|dist|build|__pycache__|site-packages|\\.venv)/'"
    " | head -400"
)

MANIFEST_COMMAND = (
    "find {roots} -maxdepth 5 -type f \\("
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
        stack = stack_for(item.get("cwd", ""), stacks)
        item["stack"] = stack["label"]
        item["languages"] = stack["languages"]
        item["frameworks"] = stack["frameworks"]
        enriched_services.append(item)

    findings.sort(key=lambda item: (patterns.SEVERITY_ORDER.get(item["severity"], 9), item["file"], item["line"]))
    for item in findings:
        if not item.get("kind_ru"):
            item["kind_ru"] = ru.kind_ru(item.get("kind", ""))
        if not item.get("patch_ru"):
            item["patch_ru"] = ru.patch_ru(item.get("rule", ""), item.get("patch", ""))
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
