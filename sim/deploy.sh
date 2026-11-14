#!/usr/bin/env bash
# deploy.sh — разворачивает полигон A/D внутри WSL (Kali). Запуск от root.
#
#   AD_SSH_PORT=2222 AD_KEY=/tmp/adlab/id_ed25519.pub bash /tmp/adlab/deploy.sh
#
# Ставит: /srv/notes, /srv/archive, /srv/warehouse, /srv/_checker,
# четыре systemd-юнита, sshd на отдельном порту, пользователя vulnbox.
set -euo pipefail

STAGE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SSH_PORT="${AD_SSH_PORT:-2222}"
PUBKEY="${AD_KEY:-$STAGE/id_ed25519.pub}"
CHECKER_INTERVAL="${AD_CHECKER_INTERVAL:-45}"

say() { printf '%s\n' "$*"; }

say "== staging -> /srv"
install -d -m 0755 /srv/notes /srv/notes/data /srv/notes/uploads /srv/archive /srv/archive/data /srv/warehouse /srv/warehouse/uploads
install -d -m 0700 /srv/_checker

install -m 0644 "$STAGE/vulnbox/notes/app.py" /srv/notes/app.py
install -m 0644 "$STAGE/vulnbox/archive/server.js" /srv/archive/server.js
install -m 0644 "$STAGE/vulnbox/warehouse/index.php" /srv/warehouse/index.php
install -m 0755 "$STAGE/vulnbox/checker/checker.py" /srv/_checker/checker.py

# index.json и readme, если их нет
if [ ! -f /srv/archive/index.json ]; then
  printf '{"files":[{"id":1,"title":"release-notes","name":"release.txt"}]}\n' > /srv/archive/index.json
  printf 'archive service, build 41\n' > /srv/archive/data/release.txt
fi
if [ ! -f /srv/notes/data/readme.txt ]; then
  printf 'notes service\n' > /srv/notes/data/readme.txt
fi

say "== systemd units"
cat > /etc/systemd/system/ad-notes.service <<'UNIT'
[Unit]
Description=AD lab notes (python)
After=network.target

[Service]
Type=simple
WorkingDirectory=/srv/notes
ExecStart=/usr/bin/python3 /srv/notes/app.py
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
UNIT

cat > /etc/systemd/system/ad-archive.service <<'UNIT'
[Unit]
Description=AD lab archive (node)
After=network.target

[Service]
Type=simple
WorkingDirectory=/srv/archive
ExecStart=/usr/bin/node /srv/archive/server.js
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
UNIT

cat > /etc/systemd/system/ad-warehouse.service <<'UNIT'
[Unit]
Description=AD lab warehouse (php)
After=network.target

[Service]
Type=simple
WorkingDirectory=/srv/warehouse
Environment=PHP_CLI_SERVER_WORKERS=4
ExecStart=/usr/bin/php -S 0.0.0.0:8083 -t /srv/warehouse
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
UNIT

cat > /etc/systemd/system/ad-checker.service <<'UNIT'
[Unit]
Description=AD lab checker (rounds)
After=network.target ad-notes.service ad-archive.service ad-warehouse.service

[Service]
Type=simple
WorkingDirectory=/srv/_checker
ExecStart=/usr/bin/python3 /srv/_checker/checker.py --interval __INTERVAL__
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
UNIT
sed -i "s/__INTERVAL__/${CHECKER_INTERVAL}/" /etc/systemd/system/ad-checker.service

systemctl daemon-reload
systemctl enable --now ad-notes.service ad-archive.service ad-warehouse.service
systemctl enable --now ad-checker.service
systemctl restart ad-notes.service ad-archive.service ad-warehouse.service

say "== sshd on ${SSH_PORT}"
ssh-keygen -A >/dev/null 2>&1 || true
cat > /etc/ssh/sshd_config.d/adlab.conf <<SSHD
Port ${SSH_PORT}
PermitRootLogin prohibit-password
PubkeyAuthentication yes
PasswordAuthentication yes
UsePAM yes
SSHD

if [ -f "$PUBKEY" ]; then
  install -d -m 0700 /root/.ssh
  touch /root/.ssh/authorized_keys
  grep -qxF "$(cat "$PUBKEY")" /root/.ssh/authorized_keys || cat "$PUBKEY" >> /root/.ssh/authorized_keys
  chmod 600 /root/.ssh/authorized_keys
fi

id vulnbox >/dev/null 2>&1 || useradd -m -s /bin/bash vulnbox
echo 'vulnbox:vulnbox' | chpasswd
install -d -m 0700 -o vulnbox -g vulnbox /home/vulnbox/.ssh
if [ -f "$PUBKEY" ]; then
  cp "$PUBKEY" /home/vulnbox/.ssh/authorized_keys
  chown vulnbox:vulnbox /home/vulnbox/.ssh/authorized_keys
  chmod 600 /home/vulnbox/.ssh/authorized_keys
fi

systemctl enable ssh >/dev/null 2>&1 || true
systemctl restart ssh

say "== health"
sleep 2
for port in 8081 8082 8083; do
  code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 "http://127.0.0.1:${port}/health" || true)
  say "  :${port} -> ${code}"
done

say "== checker first round"
python3 /srv/_checker/checker.py --once || true
say "== ports"
ss -lntp | awk 'NR==1 || /:(8081|8082|8083|'"${SSH_PORT}"')/'
say "deploy done"
