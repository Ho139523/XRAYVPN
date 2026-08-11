#!/usr/bin/env bash

set -Eeuo pipefail

STATE_DIR="$ROOT_DIR/state"
. "$STATE_DIR/xui.env"

. "$STATE_DIR/server.env"
. "$STATE_DIR/secrets.env"
. "$STATE_DIR/inbound.env"
. "$STATE_DIR/client.env"

if [[ -f "$ROOT_DIR/config/.env" ]]; then
    . "$ROOT_DIR/config/.env"
fi

XUI_PANEL_PORT="${XUI_PANEL_PORT:-2053}"

COOKIE_JAR="$STATE_DIR/.xui-cookie"

echo "=== HEALTH CHECK ==="

echo
echo "1. Container"

if ! docker inspect \
    --format '{{.State.Running}}' \
    "$XUI_CONTAINER_NAME" 2>/dev/null |
    grep -q '^true$'
then
    echo "ERROR: 3X-UI container is not running."
    exit 1
fi

echo "OK: container running."

echo
echo "2. Panel"

if ! curl \
    --silent \
    --show-error \
    --max-time 5 \
    "http://127.0.0.1:${XUI_PANEL_PORT}/login" \
    >/dev/null
then
    echo "ERROR: panel is not responding."
    exit 1
fi

echo "OK: panel responding."

echo
echo "3. Inbound API"

RESPONSE="$(
    curl \
        --fail \
        --silent \
        --show-error \
        --max-time 10 \
        -b "$COOKIE_JAR" \
        "http://127.0.0.1:${XUI_PANEL_PORT}/panel/api/inbounds/get/${INBOUND_ID}"
)"

if ! printf '%s' "$RESPONSE" | grep -q '"success":true'; then
    echo "ERROR: inbound lookup failed."
    echo "$RESPONSE"
    exit 1
fi

echo "OK: inbound exists."

echo
echo "4. Client UUID"

if ! printf '%s' "$RESPONSE" | grep -q "$CLIENT_UUID"; then
    echo "ERROR: client UUID not found in inbound."
    exit 1
fi

echo "OK: client exists."

echo
echo "5. TCP listener"

if ! ss -lnt 2>/dev/null | grep -Eq ":${VPN_PORT}[[:space:]]"; then
    echo "ERROR: port ${VPN_PORT} is not listening."
    exit 1
fi

echo "OK: port ${VPN_PORT} is listening."

echo
echo "6. Reality target"

if curl \
    --silent \
    --show-error \
    --max-time 10 \
    --head \
    "https://${REALITY_SERVER_NAME}/" \
    >/dev/null 2>&1
then
    echo "OK: Reality target reachable."
else
    echo "WARNING: Reality target could not be checked."
    echo "This does not necessarily mean the Reality inbound is broken."
fi

echo
echo "Health check PASSED."
