#!/bin/sh
set -e

# Создаём рабочий конфиг из примера, если его ещё нет — чтобы юнит сразу мог стартануть.
if [ ! -f /etc/microsubsproxy/config.yaml ]; then
    cp /etc/microsubsproxy/config.yaml.example /etc/microsubsproxy/config.yaml
    chmod 644 /etc/microsubsproxy/config.yaml
fi

if [ -d /run/systemd/system ]; then
    systemctl daemon-reload >/dev/null 2>&1 || true
fi

cat <<'EOF'

microsubsproxy установлен.

  Конфиг:    /etc/microsubsproxy/config.yaml (отредактируйте upstreams)
  Бинарник:  /usr/local/bin/microsubsproxy
  Юнит:      /lib/systemd/system/microsubsproxy.service

  sudo systemctl enable --now microsubsproxy
  journalctl -u microsubsproxy -f

EOF
