#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
mkdir -p "$HOME/.config/systemd/user"

cat > "$HOME/.config/systemd/user/local-ai-recon-update.service" <<EOF
[Unit]
Description=Local AI Recon knowledge update

[Service]
Type=oneshot
WorkingDirectory=$ROOT
ExecStart=$ROOT/scripts/update_once.sh
EOF

cat > "$HOME/.config/systemd/user/local-ai-recon-update.timer" <<EOF
[Unit]
Description=Update Local AI Recon knowledge every 6 hours

[Timer]
OnBootSec=5m
OnUnitActiveSec=6h
Persistent=true

[Install]
WantedBy=timers.target
EOF

systemctl --user daemon-reload
systemctl --user enable --now local-ai-recon-update.timer
systemctl --user list-timers | grep local-ai-recon-update || true
