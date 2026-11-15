"""Разбор манифестов зависимостей: имя, версия, экосистема, строка.

Сканер правил смотрит код. Здесь смотрится то, что код тянет: пакеты и их
версии. Из этого списка `cve.py` спрашивает OSV, а без сети — сверяет с
небольшой встроенной таблицей.

Точность честная: диапазон `>=1.2,<2` даёт нижнюю границу с пометкой
`approximate`. Лок-файлы (`package-lock.json`, `poetry.lock`, `go.sum`) не
разбираются: в них дерево целиком, и вопрос «какая версия стоит на машине»
решается на машине, а не по репозиторию.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import PurePosixPath


@dataclass(frozen=True)
class Dependency:
    ecosystem: str
    name: str
    version: str
    file: str
    line: int
    approximate: bool = False

    @property
    def key(self) -> str:
        return f"{self.ecosystem}/{self.name}@{self.version}"


VERSION = r"[0-9][0-9A-Za-z.\-+_]*"
_RANGE = re.compile(rf"^[\^~>=<!\s]*({VERSION})")

PY_FILES = ("requirements.txt", "pipfile", "pyproject.toml", "setup.py", "setup.cfg")


def _clean(raw: str) -> tuple[str, bool]:
    """`^4.17.21` -> (`4.17.21`, False); `>=1.2,<2` -> (`1.2`, True)."""
    raw = raw.strip().strip('"').strip("'")
    approximate = any(token in raw for token in (",", "*", "x", "||")) or raw.startswith((">", "<"))
    match = _RANGE.match(raw)
    if not match:
        return "", False
    return match.group(1), approximate


def _lines(text: str):
    for number, line in enumerate(text.splitlines(), start=1):
        yield number, line


def _requirements(path: str, text: str) -> list[Dependency]:
    found = []
    pattern = re.compile(rf"^\s*([A-Za-z0-9][A-Za-z0-9_.\-]*)\s*(?:\[[^\]]*\])?\s*(?:==|>=|~=)\s*({VERSION})")
    for number, line in _lines(text):
        if line.lstrip().startswith(("#", "-")):
            continue
        match = pattern.match(line)
        if match:
            found.append(Dependency("PyPI", match.group(1).lower(), match.group(2), path, number))
    return found


def _pyproject(path: str, text: str) -> list[Dependency]:
    found = []
    section = ""
    inline = re.compile(rf'^\s*([A-Za-z0-9][A-Za-z0-9_.\-]*)\s*=\s*"\s*[\^~>=<\s]*({VERSION})')
    quoted = re.compile(rf'"([A-Za-z0-9][A-Za-z0-9_.\-]*)\s*(?:==|>=|~=)\s*({VERSION})')
    for number, line in _lines(text):
        stripped = line.strip()
        if stripped.startswith("["):
            section = stripped
            continue
        if "poetry.dependencies" not in section and "poetry.dev-dependencies" not in section:
            if "dependencies" in section or "project" in section:
                for match in quoted.finditer(line):
                    found.append(Dependency("PyPI", match.group(1).lower(), match.group(2), path, number))
            continue
        if stripped.startswith("#") or not stripped:
            continue
        match = inline.match(line)
        if match and match.group(1).lower() != "python":
            found.append(Dependency("PyPI", match.group(1).lower(), match.group(2), path, number))
    return found


def _go_mod(path: str, text: str) -> list[Dependency]:
    found = []
    require = re.compile(rf"^\s*(?:require\s+)?([\w.\-]+(?:/[\w.\-]+)+)\s+v({VERSION})")
    for number, line in _lines(text):
        if line.strip().startswith("//"):
            continue
        match = require.match(line)
        if match:
            found.append(Dependency("Go", match.group(1), match.group(2), path, number))
    return found


def _json_block(path: str, text: str, keys: tuple[str, ...], ecosystem: str) -> list[Dependency]:
    try:
        data = json.loads(text)
    except ValueError:
        return []
    found = []
    for key in keys:
        block = data.get(key)
        if not isinstance(block, dict):
            continue
        for name, raw in block.items():
            if not isinstance(raw, str):
                continue
            version, approximate = _clean(raw)
            if not version:
                continue
            line = next((number for number, item in _lines(text) if f'"{name}"' in item), 1)
            found.append(Dependency(ecosystem, name, version, path, line, approximate))
    return found


def _cargo(path: str, text: str) -> list[Dependency]:
    found = []
    section = ""
    plain = re.compile(rf'^([A-Za-z0-9_.\-]+)\s*=\s*"\s*({VERSION})')
    table = re.compile(rf'^([A-Za-z0-9_.\-]+)\s*=\s*\{{[^}}]*version\s*=\s*"\s*({VERSION})')
    for number, line in _lines(text):
        stripped = line.strip()
        if stripped.startswith("["):
            section = stripped
            continue
        if "dependencies" not in section:
            continue
        match = table.match(stripped) or plain.match(stripped)
        if match:
            found.append(Dependency("crates.io", match.group(1), match.group(2), path, number))
    return found


def _pom(path: str, text: str) -> list[Dependency]:
    found = []
    block = re.compile(r"<dependency>(.*?)</dependency>", re.S)
    for match in block.finditer(text):
        chunk = match.group(1)
        name = re.search(r"<artifactId>\s*([^<\s]+)\s*</artifactId>", chunk)
        version = re.search(r"<version>\s*([^<\s]+)\s*</version>", chunk)
        if not name or not version:
            continue
        cleaned, approximate = _clean(version.group(1))
        if not cleaned:
            continue
        line = text[: match.start()].count("\n") + 1
        found.append(Dependency("Maven", name.group(1), cleaned, path, line, approximate))
    return found


def _gemfile_lock(path: str, text: str) -> list[Dependency]:
    found = []
    # {{4}} — это четыре пробела после подстановки в f-строку: Gemfile.lock
    # печатает версии с отступом в четыре пробела.
    pattern = re.compile(rf"^ {{4}}([A-Za-z0-9_.\-]+) \(({VERSION})\)")
    for number, line in _lines(text):
        match = pattern.match(line)
        if match:
            found.append(Dependency("RubyGems", match.group(1), match.group(2), path, number))
    return found


def _cmake(path: str, text: str) -> list[Dependency]:
    found = []
    pattern = re.compile(r"find_package\s*\(\s*(Boost|OpenSSL|libxml2|zlib)\s+([0-9][0-9.]*)", re.I)
    for number, line in _lines(text):
        match = pattern.search(line)
        if match:
            found.append(Dependency("native", match.group(1), match.group(2), path, number))
    return found


def parse(path: str, text: str) -> list[Dependency]:
    name = PurePosixPath(path.replace("\\", "/")).name.lower()
    if name.startswith("requirements") and name.endswith(".txt"):
        return _requirements(path, text)
    if name == "pyproject.toml":
        return _pyproject(path, text)
    if name == "go.mod":
        return _go_mod(path, text)
    if name == "package.json":
        return _json_block(path, text, ("dependencies", "devDependencies"), "npm")
    if name == "composer.json":
        return _json_block(path, text, ("require", "require-dev"), "Packagist")
    if name == "cargo.toml":
        return _cargo(path, text)
    if name == "pom.xml":
        return _pom(path, text)
    if name == "gemfile.lock":
        return _gemfile_lock(path, text)
    if name == "cmakelists.txt" or name.endswith(".cmake"):
        return _cmake(path, text)
    return []


def parse_sources(sources: dict[str, str]) -> list[Dependency]:
    found: list[Dependency] = []
    seen: set[str] = set()
    for path, text in sources.items():
        for dependency in parse(path, text):
            if dependency.key in seen:
                continue
            seen.add(dependency.key)
            found.append(dependency)
    return found


def summary(deps: list[Dependency]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for dependency in deps:
        counts[dependency.ecosystem] = counts.get(dependency.ecosystem, 0) + 1
    return counts
