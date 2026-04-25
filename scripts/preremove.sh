#!/bin/sh
set -e

if [ -d /run/systemd/system ]; then
    systemctl --no-reload disable --now microsubsproxy.service >/dev/null 2>&1 || true
fi
