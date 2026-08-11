#!/usr/bin/env bash

set -Eeuo pipefail

STATE_DIR="$ROOT_DIR/state"

. "$STATE_DIR/inbound.env"

echo "=== NETWORK CONFIGURATION ==="

echo
echo "Checking port ${VPN_PORT}..."

if ! ss -lnt 2>/dev/null | grep -Eq ":${VPN_PORT}[[:space:]]"; then
    echo "WARNING: nothing is listening on port ${VPN_PORT} yet."
else
    echo "Port ${VPN_PORT} is listening."
fi

echo
echo "Checking firewall..."

if command -v ufw >/dev/null 2>&1; then

    UFW_STATUS="$(ufw status 2>/dev/null | head -n 1 || true)"

    if [[ "$UFW_STATUS" == "Status: active" ]]; then
        echo "UFW is active."

        ufw allow "${VPN_PORT}/tcp" >/dev/null

        echo "Allowed ${VPN_PORT}/tcp through UFW."
    else
        echo "UFW is installed but inactive."
    fi

elif command -v firewall-cmd >/dev/null 2>&1; then

    if firewall-cmd --state >/dev/null 2>&1; then
        firewall-cmd --permanent \
            --add-port="${VPN_PORT}/tcp" >/dev/null

        firewall-cmd --reload >/dev/null

        echo "Allowed ${VPN_PORT}/tcp through firewalld."
    else
        echo "firewalld is installed but inactive."
    fi

else
    echo "No supported active firewall manager detected."
    echo "Make sure ${VPN_PORT}/tcp is allowed by your VPS provider firewall."
fi

echo
echo "Network configuration OK."
