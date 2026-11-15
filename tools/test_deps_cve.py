"""Регрессия разбора манифестов, сверки версий и ELF.

Три части:
  1. deps: каждый формат манифеста даёт имя, версию и экосистему;
  2. cve: встроенная таблица срабатывает без сети, «новее исправленной» — молчит;
  3. elf: заголовки и символы настоящего ELF читаются, защиты считаются.
"""
import struct
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from adkit import cve, deps, elf

FAILED = 0


def check(title: str, ok: bool, detail: str = "") -> None:
    global FAILED
    if not ok:
        FAILED += 1
    print(f"{'ok' if ok else 'FAIL':>4} {title}{(' — ' + detail) if detail else ''}")


SAMPLES = {
    "requirements.txt": "flask==2.0.0\nrequests>=2.25.0,<2.31\n# comment\n-r other.txt\n",
    "go.mod": "module x\n\nrequire (\n\tgithub.com/gin-gonic/gin v1.9.1\n\tgolang.org/x/crypto v0.17.0 // indirect\n)\n",
    "package.json": '{"dependencies": {"lodash": "^4.17.20"}, "devDependencies": {"jest": "~29.0.0"}}',
    "Cargo.toml": '[package]\nname = "x"\n[dependencies]\nserde = "1.0.100"\naxum = { version = "0.7.1", features = [] }\n',
    "pom.xml": "<project><dependencies><dependency><groupId>org.apache.logging.log4j</groupId>"
               "<artifactId>log4j-core</artifactId><version>2.14.1</version></dependency></dependencies></project>",
    "Gemfile.lock": "GEM\n  remote: https://rubygems.org/\n  specs:\n    rack (2.2.3)\n",
    "CMakeLists.txt": "find_package(Boost 1.74 REQUIRED)\n",
    "pyproject.toml": '[tool.poetry.dependencies]\npython = "^3.11"\nflask = "2.0.0"\n',
}


def names(text: str, filename: str):
    return [(item.ecosystem, item.name, item.version) for item in deps.parse(f"/svc/{filename}", text)]


def test_deps() -> None:
    expected = {
        "requirements.txt": [("PyPI", "flask", "2.0.0"), ("PyPI", "requests", "2.25.0")],
        "go.mod": [("Go", "github.com/gin-gonic/gin", "1.9.1"), ("Go", "golang.org/x/crypto", "0.17.0")],
        "package.json": [("npm", "lodash", "4.17.20"), ("npm", "jest", "29.0.0")],
        "Cargo.toml": [("crates.io", "serde", "1.0.100"), ("crates.io", "axum", "0.7.1")],
        "pom.xml": [("Maven", "log4j-core", "2.14.1")],
        "Gemfile.lock": [("RubyGems", "rack", "2.2.3")],
        "CMakeLists.txt": [("native", "Boost", "1.74")],
        "pyproject.toml": [("PyPI", "flask", "2.0.0")],
    }
    for filename, want in expected.items():
        got = names(SAMPLES[filename], filename)
        check(f"deps {filename}", got == want, str(got))

    found = deps.parse_sources({f"/svc/{name}": text for name, text in SAMPLES.items()})
    check("deps: сводка по экосистемам", deps.summary(found).get("PyPI") == 2, str(deps.summary(found)))
    check("deps: без дублей", len(found) == len({item.key for item in found}), f"{len(found)}")


def test_cve() -> None:
    text = "flask==2.0.0\nrequests==2.25.0\npyyaml==5.3\n"
    parsed = deps.parse_sources({"/svc/requirements.txt": text})
    offline = cve.check(parsed, online=False)
    ids = {item["advisory"] for item in offline}
    check("cve: встроенная таблица без сети", {"CVE-2023-30861", "CVE-2020-14343"} <= ids, str(sorted(ids)))
    check("cve: находки привязаны к строке", all(item["line"] > 0 for item in offline))
    check("cve: поле fixed заполнено", all(item["fixed"] for item in offline))

    fresh = deps.parse_sources({"/svc/requirements.txt": "flask==3.1.0\nrequests==2.32.3\n"})
    check("cve: свежие версии молчат", cve.check(fresh, online=False) == [])

    check("cve: сравнение версий", cve.older("1.2.9", "1.2.10") and not cve.older("1.3", "1.2.10"))


def make_elf(time_type: int = 3, exec_stack: bool = False, canary: bool = True) -> bytes:
    """Минимальный 64-битный ELF: заголовок + два сегмента, без секций."""
    header_size = 64
    phentsize = 56
    phnum = 2
    phoff = header_size
    body = b"\0" * 16

    ident = b"\x7fELF" + bytes([2, 1, 1]) + b"\0" * 9
    header = ident + struct.pack("<HHIQQQIHHHHHH",
                                 time_type, 62, 1, 0x400000 + header_size + phentsize * phnum,
                                 phoff, 0, 0, header_size, phentsize, phnum, 64, 0, 0)

    stack_flags = 0x7 if exec_stack else 0x6
    phdrs = struct.pack("<IIQQQQQQ", 1, 0x5, 0, 0x400000, 0x400000, len(body), len(body), 0x1000)
    phdrs += struct.pack("<IIQQQQQQ", 0x6474E551, stack_flags, 0, 0, 0, 0, 0, 0x10)
    return header + phdrs + body


def test_elf(tmp: Path) -> None:
    clean = tmp / "clean.elf"
    clean.write_bytes(make_elf())
    info = elf.parse_file(str(clean))
    check("elf: разобран", info.error == "" and info.class_bits == 64, info.error or "ok")
    check("elf: PIE распознан", info.e_type == elf.ET_DYN)
    check("elf: стек без X", not (info.segment(elf.PT_GNU_STACK)["flags"] & elf.PF_X))
    # У фикстуры нет ни RELRO, ни таблицы символов: защиты считаются по факту,
    # а не по желанию. Проверяем, что PIE и стек не выдуманы.
    clean_rules = {item["rule"] for item in elf.hardening(info)}
    check("elf: чистый бинарник — без PIE и exec-stack",
          "elf-no-pie" not in clean_rules and "elf-exec-stack" not in clean_rules,
          str(sorted(clean_rules)))

    bad = tmp / "bad.elf"
    bad.write_bytes(make_elf(time_type=elf.ET_EXEC, exec_stack=True, canary=False))
    rules = {item["rule"] for item in elf.hardening(elf.parse_file(str(bad)))}
    check("elf: exec-stack найден", "elf-exec-stack" in rules, str(sorted(rules)))
    check("elf: нет PIE — найдено", "elf-no-pie" in rules, str(sorted(rules)))
    check("elf: нет канарейки — найдено", "elf-no-canary" in rules, str(sorted(rules)))
    check("elf: не ELF — пусто", elf.hardening(elf.parse_bytes(b"hello", "x")) == [])


def main() -> int:
    import tempfile

    test_deps()
    test_cve()
    with tempfile.TemporaryDirectory() as tmp:
        test_elf(Path(tmp))
    total = 8 + 5 + 8
    print(f"\n{'пройдено' if FAILED == 0 else 'провалено'}: {total - FAILED}/{total}")
    return 0 if FAILED == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
