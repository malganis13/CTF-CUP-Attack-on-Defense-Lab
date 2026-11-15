"""ELF: разбор заголовка, сегментов, секций и таблиц символов.

Это не дизассемблер. Это ответ на вопросы, которые `strings` не задаёт:

- какие функции бинарник импортирует (`system`, `strcpy`, `gets`) — по таблице
  символов, а не по случайной строке в `.rodata`;
- собрана ли программа позиционно-независимой (PIE) и есть ли у стека признак
  исполняемости;
- включён ли канарейка стека и полная RELRO;
- на каком языке бинарник собран (Go выдаёт себя заметкой `.note.go.buildid`).

Формат разбирается по спецификации ELF: заголовок, таблица сегментов, таблица
секций, `.dynsym`/`.symtab`, `.strtab`. Ничего не исполняется и не пишется.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path

ELF_MAGIC = b"\x7fELF"

ET_EXEC = 2
ET_DYN = 3

PT_LOAD = 1
PT_GNU_STACK = 0x6474E551
PT_GNU_RELRO = 0x6474E552

SHT_SYMTAB = 2
SHT_STRTAB = 3
SHT_DYNSYM = 11

SHF_WRITE = 0x1
SHF_EXECINSTR = 0x4

PF_X = 0x1
PF_W = 0x2

# Импорты, которые на A/D означают «вход может стать командой или копией».
DANGEROUS = {
    "system": "Binary: shell call",
    "popen": "Binary: shell call",
    "execl": "Binary: shell call",
    "execlp": "Binary: shell call",
    "execv": "Binary: shell call",
    "execvp": "Binary: shell call",
    "strcpy": "Binary: unsafe string",
    "strcat": "Binary: unsafe string",
    "sprintf": "Binary: unsafe string",
    "gets": "Binary: unsafe string",
}


@dataclass
class ElfInfo:
    path: str
    class_bits: int = 0
    little: bool = True
    e_type: int = 0
    machine: int = 0
    entry: int = 0
    segments: list[dict] = field(default_factory=list)
    sections: list[dict] = field(default_factory=list)
    symbols: set[str] = field(default_factory=set)
    imported: set[str] = field(default_factory=set)
    defined: set[str] = field(default_factory=set)
    notes: set[str] = field(default_factory=set)
    error: str = ""

    @property
    def is_go(self) -> bool:
        return any("go.buildid" in name or "go.buildinfo" in name for name in self.notes) or "go.buildid" in self.symbols

    @property
    def has_stack_guard(self) -> bool:
        return any(name in self.symbols for name in ("__stack_chk_fail", "__stack_chk_guard", "__stack_chk_fail_local"))

    def segment(self, kind: int) -> dict | None:
        return next((item for item in self.segments if item["type"] == kind), None)


def _read(data: bytes, offset: int, size: int) -> bytes:
    return data[offset:offset + size]


def parse_bytes(data: bytes, path: str = "") -> ElfInfo:
    info = ElfInfo(path=path)
    if len(data) < 52 or data[:4] != ELF_MAGIC:
        info.error = "not an ELF file"
        return info

    info.class_bits = 64 if data[4] == 2 else 32
    info.little = data[5] == 1
    end = "<" if info.little else ">"

    try:
        if info.class_bits == 64:
            header = struct.unpack_from(end + "HHIQQQIHHHHHH", data, 16)
        else:
            header = struct.unpack_from(end + "HHIIIIIHHHHHH", data, 16)
    except struct.error:
        info.error = "truncated header"
        return info

    (info.e_type, info.machine, _version, info.entry, phoff, shoff,
     _flags, _ehsize, phentsize, phnum, shentsize, shnum, shstrndx) = header

    try:
        for index in range(phnum):
            offset = phoff + index * phentsize
            if info.class_bits == 64:
                p_type, p_flags, p_offset, p_vaddr, _paddr, p_filesz, _memsz, _align = struct.unpack_from(
                    end + "IIQQQQQQ", data, offset)
            else:
                p_type, p_offset, p_vaddr, _paddr, p_filesz, _memsz, p_flags, _align = struct.unpack_from(
                    end + "IIIIIIII", data, offset)
            info.segments.append({
                "type": p_type, "flags": p_flags, "offset": p_offset,
                "vaddr": p_vaddr, "filesz": p_filesz,
            })
    except struct.error:
        info.error = "truncated program headers"

    sections: list[dict] = []
    try:
        for index in range(shnum):
            offset = shoff + index * shentsize
            if info.class_bits == 64:
                (name, sh_type, sh_flags, sh_addr, sh_offset, sh_size,
                 sh_link, _info, _align, sh_entsize) = struct.unpack_from(end + "IIQQQQIIQQ", data, offset)
            else:
                (name, sh_type, sh_flags, sh_addr, sh_offset, sh_size,
                 sh_link, _info, _align, sh_entsize) = struct.unpack_from(end + "IIIIIIIIII", data, offset)
            sections.append({
                "name_offset": name, "type": sh_type, "flags": sh_flags,
                "offset": sh_offset, "size": sh_size, "link": sh_link, "entsize": sh_entsize,
            })
    except struct.error:
        info.error = info.error or "truncated section headers"

    names: dict[int, str] = {}
    try:
        if 0 <= shstrndx < len(sections):
            strtab = sections[shstrndx]
            blob = _read(data, strtab["offset"], strtab["size"])
            for index in range(len(sections)):
                start = sections[index]["name_offset"]
                stop = blob.find(b"\0", start)
                names[index] = blob[start:stop].decode("ascii", "replace") if stop > 0 else ""
    except (IndexError, struct.error):
        pass

    for index, section in enumerate(sections):
        section["name"] = names.get(index, "")
        info.sections.append(section)

    for section in sections:
        if section["type"] not in (SHT_SYMTAB, SHT_DYNSYM):
            continue
        if not section["entsize"]:
            continue
        strings = b""
        if 0 <= section["link"] < len(sections):
            link = sections[section["link"]]
            strings = _read(data, link["offset"], link["size"])
        entry = 24 if info.class_bits == 64 else 16
        count = section["size"] // entry
        for index in range(count):
            offset = section["offset"] + index * entry
            try:
                if info.class_bits == 64:
                    st_name, st_info, _other, st_shndx, _value, _size = struct.unpack_from(
                        end + "IBBHQQ", data, offset)
                else:
                    st_name, _value, _size, st_info, _other, st_shndx = struct.unpack_from(
                        end + "IIIBBH", data, offset)
            except struct.error:
                break
            stop = strings.find(b"\0", st_name)
            if stop <= st_name:
                continue
            name = strings[st_name:stop].decode("ascii", "replace")
            if not name:
                continue
            info.symbols.add(name)
            if st_shndx == 0:
                info.imported.add(name)
            else:
                info.defined.add(name)

    for section in sections:
        if section["type"] == 7 and section["name"] in (".note.go.buildid", ".note.go.buildinfo"):
            info.notes.add(section["name"])

    return info


def parse_file(path: str, limit: int = 8 * 1024 * 1024) -> ElfInfo:
    try:
        with open(path, "rb") as handle:
            data = handle.read(limit)
    except OSError as error:
        info = ElfInfo(path=path)
        info.error = f"{type(error).__name__}: {error}"
        return info
    return parse_bytes(data, path)


def is_elf(path: str) -> bool:
    try:
        with open(path, "rb") as handle:
            return handle.read(4) == ELF_MAGIC
    except OSError:
        return False


def hardening(info: ElfInfo) -> list[dict]:
    """Находки по защитам. Для Go и Rust канарейка не применима — не считаем."""
    found: list[dict] = []
    if info.error:
        return found

    def add(rule: str, kind: str, severity: str, why: str, patch: str, snippet: str) -> None:
        found.append({
            "rule": rule, "kind": kind, "severity": severity,
            "file": info.path, "line": 0, "snippet": snippet[:200],
            "context": [], "context_start": 1,
            "why": why, "patch": patch, "checker_risk": "low",
            "language": "binary", "binary": True,
        })

    native = not info.is_go and "rust" not in " ".join(sorted(info.defined))[:4000]

    if info.e_type == ET_EXEC and native:
        add("elf-no-pie", "Binary: fixed image", "medium",
            "Собран как ET_EXEC: адреса фиксированы, ASLR для образа не работает.",
            "Собирать с -fPIE -pie; пересобрать сервис.", f"e_type=ET_EXEC ({info.class_bits}-bit)")

    stack = info.segment(PT_GNU_STACK)
    if stack is not None and stack["flags"] & PF_X:
        add("elf-exec-stack", "Binary: executable stack", "high",
            "Сегмент стека помечен исполняемым: данные на стеке можно выполнить.",
            "Собирать с -z noexecstack; убрать вложенные ассемблерные вставки без .note.GNU-stack.",
            "PT_GNU_STACK RWE")

    if info.segment(PT_GNU_RELRO) is None and native:
        add("elf-no-relro", "Binary: no RELRO", "low",
            "Нет PT_GNU_RELRO: таблица GOT остаётся записываемой после старта.",
            "Собирать с -Wl,-z,relro,-z,now.", "PT_GNU_RELRO отсутствует")

    if native and not info.has_stack_guard:
        add("elf-no-canary", "Binary: no stack canary", "medium",
            "Нет ссылки на __stack_chk_fail: переполнение буфера не ловится.",
            "Собирать с -fstack-protector-strong.", "нет __stack_chk_fail в символах")

    # W^X: сегмент, который одновременно пишется и исполняется.
    for segment in info.segments:
        if segment["type"] == PT_LOAD and segment["flags"] & PF_X and segment["flags"] & PF_W:
            add("elf-writable-text", "Binary: writable code", "high",
                "Сегмент кода с правом записи: после записи в него код исполняется.",
                "Убрать W из сегмента кода линкером; проверить, что его не ставит упаковщик.",
                f"LOAD RWX at 0x{segment['vaddr']:x}")
            break

    by_kind: dict[str, list[str]] = {}
    for name in sorted(info.imported):
        kind = DANGEROUS.get(name)
        if not kind:
            continue
        by_kind.setdefault(kind, []).append(name)
    for kind, names in by_kind.items():
        add("binary-" + kind.split(": ")[-1].replace(" ", "-"), kind, "high",
            "Бинарник импортирует функцию, которая исполняет команду или копирует без размера.",
            "Убрать вызов; проверять длину и использовать snprintf/strlcpy.",
            "импорт " + ", ".join(names[:4]))
    return found
