#!/usr/bin/env bash

set -Eeuo pipefail

STATE_DIR="$ROOT_DIR/state"
. "$STATE_DIR/xui.env"

. "$STATE_DIR/server.env"
. "$STATE_DIR/secrets.env"

if [[ -f "$ROOT_DIR/config/.env" ]]; then
    . "$ROOT_DIR/config/.env"
fi

XUI_PANEL_PORT="${XUI_PANEL_PORT:-2053}"
VPN_PORT="${VPN_PORT:-443}"

REALITY_TARGET="${REALITY_TARGET:-www.microsoft.com:443}"
REALITY_SERVER_NAME="${REALITY_SERVER_NAME:-www.microsoft.com}"
REALITY_FINGERPRINT="${REALITY_FINGERPRINT:-chrome}"
REALITY_SPIDERX="${REALITY_SPIDERX:-/}"
REALITY_REMARK="${REALITY_REMARK:-Finance}"

COOKIE_JAR="$STATE_DIR/.xui-cookie"

rm -f "$COOKIE_JAR"

echo "=== CREATE REALITY INBOUND ==="

echo
echo "Checking panel login..."

LOGIN_RESPONSE="$(
    curl \
        --fail \
        --silent \
        --show-error \
        --max-time 10 \
        -c "$COOKIE_JAR" \
        -b "$COOKIE_JAR" \
        -H 'Content-Type: application/json' \
        -X POST \
        "http://127.0.0.1:${XUI_PANEL_PORT}/login" \
        --data "$(python3 - <<PY
import json
print(json.dumps({
    "username": "$PANEL_USERNAME",
    "password": "$PANEL_PASSWORD"
}))
PY
)"
)"

if ! printf '%s' "$LOGIN_RESPONSE" | grep -q '"success":true'; then
    echo
    echo "ERROR: 3X-UI login failed."
    echo "$LOGIN_RESPONSE"
    exit 1
fi

echo "Panel login OK."

echo
echo "Checking whether port ${VPN_PORT} is already occupied..."

if ss -lntp 2>/dev/null | grep -Eq ":${VPN_PORT}[[:space:]]"; then
    echo
    echo "ERROR: port ${VPN_PORT} is already in use."
    echo
    ss -lntp 2>/dev/null | grep -E ":${VPN_PORT}[[:space:]]" || true
    exit 1
fi

python3 - "$STATE_DIR/inbound-payload.json" <<PY
import json
import sys

output = sys.argv[1]

payload = {
    "enable": True,
    "remark": "$REALITY_REMARK",
    "listen": "0.0.0.0",
    "port": int("$VPN_PORT"),
    "protocol": "vless",
    "expiryTime": 0,
    "total": 0,
    "settings": {
        "clients": [],
        "decryption": "none",
        "encryption": "none"
    },
    "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
            "show": True,
            "dest": "$REALITY_TARGET",
            "xver": 0,
            "serverNames": [
                "$REALITY_SERVER_NAME"
            ],
            "privateKey": "$REALITY_PRIVATE_KEY",
            "shortIds": [
                "$REALITY_SHORT_ID"
            ],
            "fingerprint": "$REALITY_FINGERPRINT",
            "serverName": "",
            "spiderX": "$REALITY_SPIDERX"
        },
        "tcpSettings": {
            "acceptProxyProtocol": False,
            "header": {
                "type": "none"
            }
        }
    },
    "sniffing": {
        "enabled": False
    }
}

with open(output, "w") as f:
    json.dump(payload, f, separators=(",", ":"))
PY

echo
echo "Creating VLESS + REALITY inbound..."

RESPONSE="$(
    curl \
        --fail \
        --silent \
        --show-error \
        --max-time 15 \
        -b "$COOKIE_JAR" \
        -H 'Content-Type: application/json' \
        -X POST \
        "http://127.0.0.1:${XUI_PANEL_PORT}/panel/api/inbounds/add" \
        --data-binary "@$STATE_DIR/inbound-payload.json"
)"

echo
echo "API response:"
echo "$RESPONSE"

if ! printf '%s' "$RESPONSE" | grep -q '"success":true'; then
    echo
    echo "ERROR: failed to create Reality inbound."
    exit 1
fi

INBOUND_ID="$(
    printf '%s' "$RESPONSE" |
    python3 -c '
import json,sys
data=json.load(sys.stdin)
obj=data.get("obj") or {}
print(obj.get("id",""))
'
)"

if [[ -z "$INBOUND_ID" ]]; then
    echo "ERROR: inbound ID was not returned."
    exit 1
fi

cat > "$STATE_DIR/inbound.env" <<EOF_INBOUND
INBOUND_ID=$INBOUND_ID
VPN_PORT=$VPN_PORT
REALITY_TARGET=$REALITY_TARGET
REALITY_SERVER_NAME=$REALITY_SERVER_NAME
REALITY_FINGERPRINT=$REALITY_FINGERPRINT
REALITY_SPIDERX=$REALITY_SPIDERX
EOF_INBOUND

chmod 600 "$STATE_DIR/inbound.env"

echo
echo "Reality inbound created successfully."
echo "Inbound ID: $INBOUND_ID"
