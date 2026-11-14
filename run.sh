#!/usr/bin/env bash
# Аудит A/D — лаунчер для Arch Linux (и любого дистрибутива с Python 3.10+).
#
#   ./run.sh            поднять на http://127.0.0.1:8765
#   ./run.sh --demo     фикстуры, без SSH
#   ./run.sh --port 9000
#
# Если файл пришёл без права запуска: chmod +x run.sh
set -euo pipefail

cd "$(dirname "$0")"

DEMO=0
PORT=8765
BIND=127.0.0.1

while [[ $# -gt 0 ]]; do
  case "$1" in
    --demo|-d) DEMO=1; shift ;;
    --port|-p) PORT="${2:-}"; shift 2 ;;
    --bind) BIND="${2:-}"; shift 2 ;;
    -h|--help)
      sed -n '2,8p' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *) echo "неизвестный аргумент: $1" >&2; exit 2 ;;
  esac
done

if [[ ! -f app.py ]]; then
  echo "app.py не найден; запускать из каталога ad-audit" >&2
  exit 1
fi

PYTHON=""
for candidate in python3 python; do
  if command -v "$candidate" >/dev/null 2>&1; then PYTHON="$candidate"; break; fi
done

if [[ -z "$PYTHON" ]]; then
  echo "python3 не найден; поставьте:  sudo pacman -S python" >&2
  exit 1
fi

if ! "$PYTHON" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)'; then
  echo "нужен Python 3.10 или новее; найден: $("$PYTHON" -V 2>&1)" >&2
  exit 1
fi

if ! "$PYTHON" -c 'import paramiko' >/dev/null 2>&1; then
  echo "заметка: paramiko нет — используется системный ssh (вход по ключу)."
  echo "         вход по паролю:  $PYTHON -m pip install -r requirements.txt"
fi

# Кириллица в терминале: локаль может быть C/POSIX.
export PYTHONIOENCODING="${PYTHONIOENCODING:-utf-8}"

echo "Аудит A/D  ->  http://${BIND}:${PORT}"
echo "python: $("$PYTHON" -V 2>&1)"
if [[ "$DEMO" -eq 1 ]]; then
  echo "демо-режим: фикстуры, без SSH"
  exec "$PYTHON" app.py --host "$BIND" --port "$PORT" --demo
fi

exec "$PYTHON" app.py --host "$BIND" --port "$PORT"
