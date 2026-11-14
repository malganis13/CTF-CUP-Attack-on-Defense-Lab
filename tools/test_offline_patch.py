"""Регрессия двух входов без SSH и выхода патчем.

1. `scan_target` по zip-архиву сервиса даёт те же находки, что каталог.
2. `patch.unified` собирает diff, который принимает `git apply` на реальном
   файле: номера строк, контекст и замена совпадают.
"""
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from adkit import audit, fixes, patch

VULNERABLE = '''import sqlite3


def note(db, note_id):
    cursor = db.cursor()
    cursor.execute(f"SELECT * FROM notes WHERE id={note_id}")
    return cursor.fetchone()


def other():
    return 42
'''

SOURCE = {
    "src/app.py": VULNERABLE,
    "src/util.py": "def add(a, b):\n    return a + b\n",
}


def check(title: str, ok: bool, detail: str = "") -> int:
    print(f"{'ok' if ok else 'FAIL':>4} {title}{(' — ' + detail) if detail else ''}")
    return 0 if ok else 1


def test_zip() -> int:
    failed = 0
    with tempfile.TemporaryDirectory() as tmp:
        archive = Path(tmp) / "service.zip"
        with zipfile.ZipFile(archive, "w") as handle:
            for name, text in SOURCE.items():
                handle.writestr(name, text)
        result = audit.scan_target(str(archive))
        rules = {item["rule"] for item in result["findings"]}
        failed += check("zip прочитан", len(result["files"]) == 2, f"файлов {len(result['files'])}")
        failed += check("находка в zip найдена", bool(rules), ", ".join(sorted(rules)) or "пусто")
        failed += check("источник записан", result.get("source", "").endswith("service.zip"))

        # Архив, который пытается писать наружу, отклоняется до записи.
        evil = Path(tmp) / "evil.zip"
        with zipfile.ZipFile(evil, "w") as handle:
            handle.writestr("../../escaped.txt", "x")
        try:
            audit.scan_target(str(evil))
            failed += check("выход за каталог отклонён", False, "распаковка прошла")
        except ValueError:
            failed += check("выход за каталог отклонён", True)
        except Exception as error:  # noqa: BLE001
            failed += check("выход за каталог отклонён", False, type(error).__name__)
    return failed


def test_patch() -> int:
    failed = 0
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        target = root / "src" / "app.py"
        target.parent.mkdir()
        target.write_text(VULNERABLE, encoding="utf-8", newline="\n")
        lines = VULNERABLE.splitlines()

        offending = lines[5]
        finding = {
            "file": str(target),
            "line": 6,
            "snippet": offending,
            "context": lines[3:9],
            "context_start": 4,
            "language": "python",
            "rule": "sql-fstring",
        }
        fix = fixes.build_fix("sql-fstring", "python", offending)
        diff = patch.unified(finding, fix, root=str(root))
        failed += check("diff собран", diff.startswith("diff --git a/src/app.py b/src/app.py"), diff.splitlines()[0])

        patch_file = root / "fix.patch"
        patch_file.write_text(diff, encoding="utf-8", newline="\n")
        applied = subprocess.run(
            ["git", "apply", "--check", "-p1", "--whitespace=nowarn", str(patch_file)],
            cwd=tmp, capture_output=True, text=True,
        )
        failed += check("git apply --check принял", applied.returncode == 0,
                        (applied.stderr or "").strip().splitlines()[0] if applied.stderr.strip() else "без ошибок")

        # Применяем по-настоящему и сверяем, что изменилась ровно одна строка.
        real = subprocess.run(
            ["git", "apply", "-p1", "--whitespace=nowarn", str(patch_file)],
            cwd=tmp, capture_output=True, text=True,
        )
        failed += check("патч применён", real.returncode == 0, (real.stderr or "").strip()[:80])
        after = target.read_text(encoding="utf-8").splitlines()
        failed += check("строка заменена", after[5] != offending and len(after) > len(lines) - 1,
                        after[5] if len(after) > 5 else "нет строки")
        failed += check("хвост цел", after[-1] == "    return 42", after[-1] if after else "пусто")
    return failed


def test_exact() -> int:
    """Патч не собирается, если рецепт написан на другом языке."""
    failed = 0
    finding = {"file": "/srv/app/handlers.go", "line": 10, "snippet": "x := 1",
               "context": ["x := 1"], "context_start": 10, "language": "go"}
    same = fixes.build_fix("ssrf", "go", "x := 1")
    failed += check("go-рецепт точен", same.get("exact") is True, same.get("sample_language"))
    failed += check("diff для go собран", bool(patch.unified(finding, same)), "пусто")
    other = fixes.build_fix("upload", "go", "x := 1")
    failed += check("чужой язык помечен", other.get("exact") is False, other.get("sample_language"))
    failed += check("diff для чужого языка пуст", patch.unified(finding, other) == "", "собран")
    return failed


def main() -> int:
    failed = test_zip() + test_patch() + test_exact()
    total = 12
    print(f"\n{'пройдено' if failed == 0 else 'провалено'}: {total - failed}/{total}")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
