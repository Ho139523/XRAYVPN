#!/usr/bin/env bash

set -Eeuo pipefail

STATE_DIR="$ROOT_DIR/state"
. "$STATE_DIR/xui.env"

. "$STATE_DIR/server.env"
. "$STATE_DIR/secrets.env"
. "$STATE_DIR/inbound.env"

. "$ROOT_DIR/scripts/lib/xui-auth.sh"

if [[ -f "$ROOT_DIR/config/.env" ]]; then
    . "$ROOT_DIR/config/.env"
fi

XUI_PANEL_PORT="${XUI_PANEL_PORT:-2053}"

CLIENT_EMAIL="${CLIENT_EMAIL:-my-phone}"
CLIENT_COMMENT="${CLIENT_COMMENT:-my-phone}"
CLIENT_LIMIT_IP="${CLIENT_LIMIT_IP:-2}"
CLIENT_FLOW="${CLIENT_FLOW:-xtls-rprx-vision}"

echo "=== CREATE CLIENT ==="

if [[ ! -f "$XUI_COOKIE_JAR" ]]; then
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

# 3X-UI 3.x manages clients through /panel/api/clients/add
with open(output.replace(".json", "-v3.json"), "w") as f:
    json.dump({
        "client": settings["clients"][0],
        "inboundIds": [inbound_id]
    }, f, separators=(",", ":"))
PY

echo
echo "Adding client to inbound ${INBOUND_ID}..."

post_client() {
    local path="$1" payload="$2"

    HTTP_CODE="$(
        curl \
            --silent \
            --show-error \
            --max-time 15 \
            --output "$STATE_DIR/.client-response" \
            --write-out '%{http_code}' \
            -b "$XUI_COOKIE_JAR" \
            -H "X-CSRF-Token: $(xui_csrf)" \
            -H 'Content-Type: application/json' \
            -X POST \
            "http://127.0.0.1:${XUI_PANEL_PORT}${path}" \
            --data-binary "@$payload"
    )"

    RESPONSE="$(cat "$STATE_DIR/.client-response")"
    rm -f "$STATE_DIR/.client-response"
}

post_client /panel/api/clients/add "$STATE_DIR/add-client-payload-v3.json"

if [[ "$HTTP_CODE" == "404" ]]; then
    post_client /panel/api/inbounds/addClient "$STATE_DIR/add-client-payload.json"
fi

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
