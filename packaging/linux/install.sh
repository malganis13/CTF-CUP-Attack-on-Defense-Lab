#!/usr/bin/env bash
# install.sh — ставит AD Audit как обычное приложение в Linux (Arch/Nyarch).
#
#   ./install.sh            # в ~/.local (без root)
#   sudo ./install.sh --system   # в /usr/local для всех пользователей
#
# Ничего не компилирует и не тянет из сети: приложение на stdlib Python 3.10+.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE="$(cd "$HERE/../.." && pwd)"
MODE="user"
[ "${1:-}" = "--system" ] && MODE="system"

if [ "$MODE" = "system" ]; then
  APP_DIR="/usr/local/share/ad-audit"
  BIN_DIR="/usr/local/bin"
  DESKTOP_DIR="/usr/share/applications"
  ICON_DIR="/usr/share/icons/hicolor/scalable/apps"
else
  APP_DIR="$HOME/.local/share/ad-audit"
  BIN_DIR="$HOME/.local/bin"
  DESKTOP_DIR="$HOME/.local/share/applications"
  ICON_DIR="$HOME/.local/share/icons/hicolor/scalable/apps"
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "нужен python3 (pacman -S python)" >&2
  exit 1
fi
PY_OK=$(python3 -c 'import sys; print(1 if sys.version_info >= (3, 10) else 0)')
if [ "$PY_OK" != "1" ]; then
  echo "нужен Python 3.10 или новее, найден $(python3 -V)" >&2
  exit 1
fi

echo "== копирую приложение в $APP_DIR"
rm -rf "$APP_DIR"
mkdir -p "$APP_DIR"
cp -r "$SOURCE/app.py" "$SOURCE/launcher.py" "$SOURCE/adkit" "$SOURCE/web" \
      "$SOURCE/knowledge" "$SOURCE/demo" "$SOURCE/README.md" "$APP_DIR/"

echo "== лаунчер в $BIN_DIR/ad-audit"
mkdir -p "$BIN_DIR"
cat > "$BIN_DIR/ad-audit" <<LAUNCH
#!/bin/sh
# AD Audit — локальное приложение. Аргументы пробрасываются как есть.
exec python3 "$APP_DIR/launcher.py" "\$@"
LAUNCH
chmod 0755 "$BIN_DIR/ad-audit"

echo "== иконка и ярлык"
mkdir -p "$ICON_DIR" "$DESKTOP_DIR"
cp "$HERE/ad-audit.svg" "$ICON_DIR/ad-audit.svg"
sed "s|__APP_DIR__|$APP_DIR|g" "$HERE/ad-audit.desktop" > "$DESKTOP_DIR/ad-audit.desktop"
chmod 0644 "$DESKTOP_DIR/ad-audit.desktop"
command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database "$DESKTOP_DIR" >/dev/null 2>&1 || true
command -v gtk-update-icon-cache >/dev/null 2>&1 && gtk-update-icon-cache -f -t "$(dirname "$(dirname "$ICON_DIR")")" >/dev/null 2>&1 || true

echo
echo "готово."
echo "  запуск из меню: «AD Audit»"
echo "  из терминала:   ad-audit"
echo "  демо-режим:     ad-audit --demo"
echo "  удалить:        $HERE/uninstall.sh"
[ "$MODE" = "user" ] && case ":$PATH:" in *":$BIN_DIR:"*) ;; *) echo "  замечание: $BIN_DIR не в PATH — добавь его в ~/.bashrc" ;; esac
