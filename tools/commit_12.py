"""Коммит версии 1.2 одной строкой сообщения (без сложных кавычек в оболочке)."""
import subprocess
import sys

MESSAGE = """ad-audit 1.2: russian rule reference, preflight, drill, logs, audit diff

- adkit/ru.py: 55 rules translated (kind_ru, why_ru, patch_ru) + fix hints
- rules tab renamed: scanner rules vs knowledge base, different subjects
- rules table: why / how to fix / fix family with risk, code button expands before-after
- endpoints: /api/rulefix, /api/preflight, /api/logs, /api/drill, /api/drill/run, /api/compare
- preflight: ssh rights, clock skew, disk, load, failed units, checker unit, stacks, key, budget
- drill: eight exploits, one GET each against the lab, marker or 5xx counts as hit
- services: journalctl drawer per row; findings: diff against the previous audit
- round timer in the sidebar; per-finding fix commands (backup, restart, rollback, verify)
- demo rebuilt with kind_ru; smoke 96/96, probe 38/38
"""

subprocess.run(["git", "add", "-A"], check=True)
subprocess.run(
    ["git", "-c", "user.name=III", "-c", "user.email=iii@desk.local", "commit", "-q", "-m", MESSAGE],
    check=True,
)
print(subprocess.run(["git", "log", "--oneline", "-1"], capture_output=True, text=True,
                     encoding="utf-8", errors="replace").stdout.strip())
