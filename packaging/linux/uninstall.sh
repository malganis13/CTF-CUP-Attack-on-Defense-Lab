#!/usr/bin/env bash
# uninstall.sh — убирает ярлык, лаунчер и каталог приложения.
set -euo pipefail

MODE="user"
[ "${1:-}" = "--system" ] && MODE="system"

if [ "$MODE" = "system" ]; then
  APP_DIR="/usr/local/share/ad-audit"
  BIN="/usr/local/bin/ad-audit"
  DESKTOP="/usr/share/applications/ad-audit.desktop"
  ICON="/usr/share/icons/hicolor/scalable/apps/ad-audit.svg"
else
  APP_DIR="$HOME/.local/share/ad-audit"
  BIN="$HOME/.local/bin/ad-audit"
  DESKTOP="$HOME/.local/share/applications/ad-audit.desktop"
  ICON="$HOME/.local/share/icons/hicolor/scalable/apps/ad-audit.svg"
fi

rm -f "$BIN" "$DESKTOP" "$ICON"
rm -rf "$APP_DIR"
echo "удалено: $APP_DIR, $BIN, $DESKTOP, $ICON"
