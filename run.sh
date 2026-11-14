#!/usr/bin/env bash
# AD Audit — launcher for Arch Linux (and any distro with Python 3.10+).
#
#   ./run.sh            start on http://127.0.0.1:8765
#   ./run.sh --demo     fixture audit, no SSH
#   ./run.sh --port 9000
set -euo pipefail

cd "$(dirname "$0")"

DEMO=()
PORT=8765
BIND=127.0.0.1

while [[ $# -gt 0 ]]; do
  case "$1" in
    --demo|-d) DEMO=(--demo); shift ;;
    --port|-p) PORT="$2"; shift 2 ;;
    --bind) BIND="$2"; shift 2 ;;
    -h|--help)
      sed -n '2,7p' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

PYTHON=""
for candidate in python3 python; do
  if command -v "$candidate" >/dev/null 2>&1; then PYTHON="$candidate"; break; fi
done

if [[ -z "$PYTHON" ]]; then
  echo "python3 not found; install it:  sudo pacman -S python" >&2
  exit 1
fi

if ! "$PYTHON" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)'; then
  echo "Python 3.10 or newer is required; found: $("$PYTHON" -V 2>&1)" >&2
  exit 1
fi

if ! "$PYTHON" -c 'import paramiko' >/dev/null 2>&1; then
  echo "note: paramiko missing — falling back to the system ssh client (key auth only)."
  echo "      password auth needs:  $PYTHON -m pip install -r requirements.txt"
fi

echo "AD Audit  ->  http://${BIND}:${PORT}"
[[ ${#DEMO[@]} -gt 0 ]] && echo "demo mode: fixture audit, no SSH"

exec "$PYTHON" app.py --host "$BIND" --port "$PORT" "${DEMO[@]}"
