#!/usr/bin/env bash

set -Eeuo pipefail

STATE_DIR="$ROOT_DIR/state"
. "$STATE_DIR/xui.env"

. "$STATE_DIR/server.env"
. "$STATE_DIR/secrets.env"
. "$STATE_DIR/inbound.env"

if [[ -f "$ROOT_DIR/config/.env" ]]; then
    . "$ROOT_DIR/config/.env"
fi

XUI_PANEL_PORT="${XUI_PANEL_PORT:-2053}"

CLIENT_EMAIL="${CLIENT_EMAIL:-my-phone}"
CLIENT_COMMENT="${CLIENT_COMMENT:-my-phone}"
CLIENT_LIMIT_IP="${CLIENT_LIMIT_IP:-2}"
CLIENT_FLOW="${CLIENT_FLOW:-xtls-rprx-vision}"

COOKIE_JAR="$STATE_DIR/.xui-cookie"

echo "=== CREATE CLIENT ==="

if [[ ! -f "$COOKIE_JAR" ]]; then
    echo "ERROR: XUI session cookie not found."
    exit 1
fi

python3 - "$STATE_DIR/add-client-payload.json" "$INBOUND_ID" <<PY
import json
import sys

output = sys.argv[1]
inbound_id = int(sys.argv[2])

settings = {
    "clients": [
        {
            "id": "$CLIENT_UUID",
            "email": "$CLIENT_EMAIL",
            "flow": "$CLIENT_FLOW",
            "limitIp": int("$CLIENT_LIMIT_IP"),
            "totalGB": 0,
            "expiryTime": 0,
            "enable": True,
            "comment": "$CLIENT_COMMENT",
            "subId": "",
            "tgId": 0
        }
    ]
}

payload = {
    "id": inbound_id,
    "settings": json.dumps(settings, separators=(",", ":"))
}

with open(output, "w") as f:
    json.dump(payload, f, separators=(",", ":"))
PY

echo
echo "Adding client to inbound ${INBOUND_ID}..."

RESPONSE="$(
    curl \
        --fail \
        --silent \
        --show-error \
        --max-time 15 \
        -b "$COOKIE_JAR" \
        -H 'Content-Type: application/json' \
        -X POST \
        "http://127.0.0.1:${XUI_PANEL_PORT}/panel/api/inbounds/addClient" \
        --data-binary "@$STATE_DIR/add-client-payload.json"
)"

echo
echo "API response:"
echo "$RESPONSE"

if ! printf '%s' "$RESPONSE" | grep -q '"success":true'; then
    echo
    echo "ERROR: failed to create client."
    exit 1
fi

cat > "$STATE_DIR/client.env" <<EOF_CLIENT
CLIENT_UUID=$CLIENT_UUID
CLIENT_EMAIL=$CLIENT_EMAIL
CLIENT_COMMENT=$CLIENT_COMMENT
CLIENT_FLOW=$CLIENT_FLOW
CLIENT_LIMIT_IP=$CLIENT_LIMIT_IP
EOF_CLIENT

chmod 600 "$STATE_DIR/client.env"

echo
echo "Client created successfully."
echo "Client UUID : $CLIENT_UUID"
echo "Client email: $CLIENT_EMAIL"
