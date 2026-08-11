#!/usr/bin/env bash

set -Eeuo pipefail

STATE_DIR="$ROOT_DIR/state"

. "$STATE_DIR/server.env"
. "$STATE_DIR/secrets.env"
. "$STATE_DIR/inbound.env"
. "$STATE_DIR/client.env"

if [[ -f "$ROOT_DIR/config/.env" ]]; then
    . "$ROOT_DIR/config/.env"
fi

XUI_PANEL_PORT="${XUI_PANEL_PORT:-2053}"

VLESS_LINK="vless://${CLIENT_UUID}@${SERVER_PUBLIC_IP}:${VPN_PORT}?type=tcp&security=reality&pbk=${REALITY_PUBLIC_KEY}&fp=${REALITY_FINGERPRINT}&sni=${REALITY_SERVER_NAME}&sid=${REALITY_SHORT_ID}&spx=%2F&flow=${CLIENT_FLOW}#${CLIENT_EMAIL}"

cat > "$STATE_DIR/client-vless.txt" <<EOF_LINK
$VLESS_LINK
EOF_LINK

cat > "$STATE_DIR/admin-access.txt" <<EOF_ADMIN
3X-UI Panel
URL: http://${SERVER_PUBLIC_IP}:${XUI_PANEL_PORT}

Username: ${PANEL_USERNAME}
Password: ${PANEL_PASSWORD}
EOF_ADMIN

chmod 600 \
    "$STATE_DIR/client-vless.txt" \
    "$STATE_DIR/admin-access.txt"

echo
echo
echo "============================================================"
echo "              VPN APPLIANCE READY"
echo "============================================================"
echo
echo "Server IP:"
echo "  $SERVER_PUBLIC_IP"
echo
echo "VLESS + REALITY:"
echo
echo "  $VLESS_LINK"
echo
echo "------------------------------------------------------------"
echo "3X-UI PANEL"
echo "------------------------------------------------------------"
echo
echo "URL:"
echo "  http://${SERVER_PUBLIC_IP}:${XUI_PANEL_PORT}"
echo
echo "Username:"
echo "  $PANEL_USERNAME"
echo
echo "Password:"
echo "  $PANEL_PASSWORD"
echo
echo "------------------------------------------------------------"
echo "FILES"
echo "------------------------------------------------------------"
echo
echo "VLESS link:"
echo "  $STATE_DIR/client-vless.txt"
echo
echo "Panel credentials:"
echo "  $STATE_DIR/admin-access.txt"
echo
echo "============================================================"
echo
echo "IMPORTANT:"
echo "The private Reality key remains only on this server."
echo "Generated credentials are NOT stored in Git."
echo
