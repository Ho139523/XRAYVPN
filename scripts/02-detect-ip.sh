#!/usr/bin/env bash

set -Eeuo pipefail

STATE_DIR="$ROOT_DIR/state"

mkdir -p "$STATE_DIR"

echo "=== PUBLIC IP DETECTION ==="

IP=""

IP_SERVICES=(
    "https://api.ipify.org"
    "https://ifconfig.me/ip"
    "https://icanhazip.com"
)

for URL in "${IP_SERVICES[@]}"; do
    echo "Trying: $URL"

    CANDIDATE="$(
        curl \
            --fail \
            --silent \
            --show-error \
            --max-time 8 \
            "$URL" 2>/dev/null \
        | tr -d '[:space:]'
    )" || true

    if [[ "$CANDIDATE" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        IP="$CANDIDATE"
        break
    fi

    if [[ "$CANDIDATE" =~ ^[0-9a-fA-F:]+$ ]] && [[ "$CANDIDATE" == *:* ]]; then
        IP="$CANDIDATE"
        break
    fi
done

if [[ -z "$IP" ]]; then
    echo
    echo "ERROR: unable to detect public IP."
    exit 1
fi

cat > "$STATE_DIR/server.env" <<ENV
SERVER_PUBLIC_IP=$IP
ENV

echo
echo "Public IP: $IP"
echo
echo "IP detection OK."
