"""Коммит версии 1.3."""
import subprocess
import sys

MESSAGE = """ad-audit 1.3: persistent audit history, action log, flag detection, drill target override

- adkit/store.py: history.jsonl and ops.jsonl in state/ (AD_STATE_DIR override), atomic per-line append, capped
- audit history survives restarts: 'what changed since the patch' works across sessions
- action log: audit, probe, drill, liveness, preflight with time and verdict; /api/ops
- probe.py: FLAG_RE detects prefix{...} in any response; summary carries flags count and the first flag
- drill: flag field, target base override (own lab, foreign vulnbox, local copy)
- UI: base input for drills, green flag line with copy button
- README: state dir, ops log, flag detection, drill base
- smoke 100/100, probe 42/42
"""

subprocess.run(["git", "add", "-A"], check=True)
subprocess.run(
    ["git", "-c", "user.name=III", "-c", "user.email=iii@desk.local", "commit", "-q", "-m", MESSAGE],
    check=True,
)
print(subprocess.run(["git", "log", "--oneline", "-1"], capture_output=True, text=True,
                     encoding="utf-8", errors="replace").stdout.strip())
