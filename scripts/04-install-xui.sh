#!/usr/bin/env bash

set -Eeuo pipefail

STATE_DIR="$ROOT_DIR/state"

. "$STATE_DIR/server.env"

if [[ -f "$ROOT_DIR/config/.env" ]]; then
    . "$ROOT_DIR/config/.env"
fi

XUI_VERSION="${XUI_VERSION:-latest}"
XUI_IMAGE="${XUI_IMAGE:-ghcr.io/mhsanaei/3x-ui:${XUI_VERSION}}"

XUI_CONTAINER_NAME="${XUI_CONTAINER_NAME:-3xui_app}"
XUI_DATA_DIR="${XUI_DATA_DIR:-/opt/vpn-appliance/data}"
XUI_PANEL_PORT="${XUI_PANEL_PORT:-2053}"
TIMEZONE="${TIMEZONE:-Asia/Tehran}"

mkdir -p "$XUI_DATA_DIR"
chmod 700 "$STATE_DIR"

echo "=== XUI INSTALLATION ==="

echo "Image      : $XUI_IMAGE"
echo "Container  : $XUI_CONTAINER_NAME"
echo "Data       : $XUI_DATA_DIR"
echo "Panel port : $XUI_PANEL_PORT"
echo "Public IP  : $SERVER_PUBLIC_IP"
echo

if docker ps -a --format '{{.Names}}' | grep -qx "$XUI_CONTAINER_NAME"; then
    echo "ERROR: existing container detected: $XUI_CONTAINER_NAME"
    echo
    echo "This installer requires a fresh appliance."
    echo "Remove it manually if this is an intentional reinstall:"
    echo
    echo "    docker rm -f $XUI_CONTAINER_NAME"
    exit 1
fi

cat > "$ROOT_DIR/docker-compose.yml" <<EOF_COMPOSE
services:
  3x-ui:
    image: ${XUI_IMAGE}
    container_name: ${XUI_CONTAINER_NAME}
    restart: unless-stopped
    network_mode: host

    environment:
      TZ: ${TIMEZONE}
      XRAY_VMESS_AEAD_FORCED: "false"
      XUI_ENABLE_FAIL2BAN: "true"

    volumes:
      - ${XUI_DATA_DIR}:/etc/x-ui

    cap_add:
      - NET_ADMIN
      - NET_RAW

    tty: true
EOF_COMPOSE

cat > "$STATE_DIR/xui.env" <<EOF_XUI
XUI_CONTAINER_NAME=$XUI_CONTAINER_NAME
XUI_PANEL_PORT=$XUI_PANEL_PORT
XUI_DATA_DIR=$XUI_DATA_DIR
XUI_IMAGE=$XUI_IMAGE
EOF_XUI

chmod 600 "$STATE_DIR/xui.env"

cd "$ROOT_DIR"

echo "Pulling 3X-UI image..."
docker compose pull

echo
echo "Starting 3X-UI..."
docker compose up -d

echo
echo "Waiting for container..."

for i in $(seq 1 60); do
    if docker inspect \
        --format '{{.State.Running}}' \
        "$XUI_CONTAINER_NAME" 2>/dev/null |
        grep -q '^true$'
    then
        echo "3X-UI container is running."
        break
    fi

    if [[ "$i" -eq 60 ]]; then
        echo "ERROR: 3X-UI container did not start."
        docker logs --tail 100 "$XUI_CONTAINER_NAME" || true
        exit 1
    fi

    sleep 2
done

echo
echo "Waiting for panel on localhost:${XUI_PANEL_PORT}..."

for i in $(seq 1 60); do
    if curl \
        --silent \
        --max-time 3 \
        "http://127.0.0.1:${XUI_PANEL_PORT}/login" \
        >/dev/null 2>&1
    then
        echo "3X-UI panel is responding."
        break
    fi

    if [[ "$i" -eq 60 ]]; then
        echo "ERROR: 3X-UI panel did not become ready."
        docker logs --tail 100 "$XUI_CONTAINER_NAME" || true
        exit 1
    fi

    sleep 2
done

echo
echo "3X-UI installation OK."
