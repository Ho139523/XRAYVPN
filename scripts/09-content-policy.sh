#!/usr/bin/env bash

set -Eeuo pipefail

STATE_DIR="$ROOT_DIR/state"

. "$STATE_DIR/xui.env"
. "$STATE_DIR/secrets.env"

if [[ -f "$ROOT_DIR/config/.env" ]]; then
    . "$ROOT_DIR/config/.env"
fi

POLICY_GATE_ENABLED="${POLICY_GATE_ENABLED:-true}"
POLICY="$ROOT_DIR/policy/vpn_policy.py"
UNIT_NAME="vpn-policy-gate.service"
UNIT_DIR="${SYSTEMD_UNIT_DIR:-/etc/systemd/system}"

echo "=== CONTENT POLICY ==="

echo
echo "Applying porn filter and location zones to Xray..."

python3 "$POLICY" apply

if [[ "$POLICY_GATE_ENABLED" != "true" ]]; then
    echo
    echo "Location gate disabled (POLICY_GATE_ENABLED=$POLICY_GATE_ENABLED)."
    exit 0
fi

if [[ -s "$STATE_DIR/parent-credentials.txt" ]]; then
    echo
    echo "Parent accounts (one per VPN user; every parent can change their own login):"
    awk -F'\t' '{ printf "  user %-18s login: %-24s password: %s\n", $1, $2, $3 }' \
        "$STATE_DIR/parent-credentials.txt"
fi

echo
echo "Installing location gate service..."

if ! command -v systemctl >/dev/null 2>&1 || [[ ! -d /run/systemd/system ]]; then
    echo "WARNING: systemd not available."
    echo "Run this yourself to enable GPS zones:"
    echo "    python3 $POLICY serve"
    exit 0
fi

cat > "$UNIT_DIR/$UNIT_NAME" <<EOF_UNIT
[Unit]
Description=VPN appliance location gate
After=network-online.target docker.service
Wants=network-online.target

[Service]
Type=simple
Environment=ROOT_DIR=$ROOT_DIR
ExecStart=/usr/bin/env python3 $POLICY serve
Restart=always
RestartSec=5
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=$STATE_DIR

[Install]
WantedBy=multi-user.target
EOF_UNIT

systemctl daemon-reload
systemctl enable "$UNIT_NAME" >/dev/null 2>&1
systemctl restart "$UNIT_NAME"

for i in $(seq 1 15); do
    if curl --silent --max-time 2 \
        "http://127.0.0.1:${POLICY_GATE_PORT:-9099}/healthz" >/dev/null 2>&1
    then
        echo "Location gate is running."
        exit 0
    fi
    sleep 1
done

echo "ERROR: location gate did not start."
journalctl -u "$UNIT_NAME" --no-pager -n 20 || true
exit 1
