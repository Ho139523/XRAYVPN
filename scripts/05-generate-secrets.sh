#!/usr/bin/env bash

set -Eeuo pipefail

STATE_DIR="$ROOT_DIR/state"

. "$STATE_DIR/xui.env"

if [[ -f "$ROOT_DIR/config/.env" ]]; then
    . "$ROOT_DIR/config/.env"
fi

mkdir -p "$STATE_DIR"
chmod 700 "$STATE_DIR"

echo "=== GENERATING SECRETS ==="

echo
echo "Generating panel credentials..."

PANEL_USERNAME="admin_$(openssl rand -hex 4)"

PANEL_PASSWORD="$(
    openssl rand -base64 48 |
    tr -dc 'A-Za-z0-9' |
    head -c 32
)"

if [[ "${#PANEL_PASSWORD}" -lt 32 ]]; then
    echo "ERROR: failed to generate strong panel password."
    exit 1
fi

echo "Applying credentials to the panel..."

# A fresh 3X-UI container still has its default admin login; without this the
# generated credentials would never match and API login would fail.
if ! docker exec "$XUI_CONTAINER_NAME" /app/x-ui setting \
    -username "$PANEL_USERNAME" \
    -password "$PANEL_PASSWORD" >/dev/null
then
    echo "ERROR: failed to set panel credentials."
    exit 1
fi

echo "Generating client UUID..."

CLIENT_UUID="$(cat /proc/sys/kernel/random/uuid)"

if [[ ! "$CLIENT_UUID" =~ ^[0-9a-fA-F-]{36}$ ]]; then
    echo "ERROR: invalid UUID generated."
    exit 1
fi

echo "Generating Reality short ID..."

REALITY_SHORT_ID="$(openssl rand -hex 8)"

if [[ ! "$REALITY_SHORT_ID" =~ ^[0-9a-fA-F]{16}$ ]]; then
    echo "ERROR: invalid Reality short ID."
    exit 1
fi

echo "Locating Xray binary..."

XRAY_BIN="$(
    docker exec "$XUI_CONTAINER_NAME" sh -c '
        for candidate in \
            /usr/local/bin/xray \
            /app/bin/xray-linux-amd64 \
            /app/bin/xray-linux-arm64 \
            /app/bin/xray-linux-arm \
            /usr/bin/xray \
            /xray
        do
            if [ -x "$candidate" ]; then
                echo "$candidate"
                exit 0
            fi
        done

        command -v xray 2>/dev/null || true
    ' |
    head -n 1
)"

if [[ -z "$XRAY_BIN" ]]; then
    echo "ERROR: unable to locate Xray binary inside container."
    exit 1
fi

echo "Xray binary: $XRAY_BIN"

echo
echo "Generating Reality X25519 keypair..."

X25519_OUTPUT="$(
    docker exec "$XUI_CONTAINER_NAME" "$XRAY_BIN" x25519
)"

PRIVATE_KEY="$(
    printf '%s\n' "$X25519_OUTPUT" |
    sed -n -E 's/^[[:space:]]*(Private key|PrivateKey):[[:space:]]*//p' |
    head -n 1 |
    tr -d '\r'
)"

PUBLIC_KEY="$(
    printf '%s\n' "$X25519_OUTPUT" |
    sed -n -E 's/^[[:space:]]*(Public key|PublicKey|Password \(PublicKey\)):[[:space:]]*//p' |
    head -n 1 |
    tr -d '\r'
)"

if [[ -z "$PRIVATE_KEY" || -z "$PUBLIC_KEY" ]]; then
    echo
    echo "ERROR: failed to generate X25519 keypair."
    echo
    echo "$X25519_OUTPUT"
    exit 1
fi

cat > "$STATE_DIR/secrets.env" <<EOF_SECRETS
PANEL_USERNAME=$PANEL_USERNAME
PANEL_PASSWORD=$PANEL_PASSWORD

CLIENT_UUID=$CLIENT_UUID

REALITY_PRIVATE_KEY=$PRIVATE_KEY
REALITY_PUBLIC_KEY=$PUBLIC_KEY
REALITY_SHORT_ID=$REALITY_SHORT_ID
EOF_SECRETS

chmod 600 "$STATE_DIR/secrets.env"

echo
echo "Secrets generated successfully."

echo
echo "Generated:"
echo "  Panel username : $PANEL_USERNAME"
echo "  Client UUID    : $CLIENT_UUID"
echo "  Reality pubkey : $PUBLIC_KEY"
echo "  Reality shortId: $REALITY_SHORT_ID"

echo
echo "Private credentials stored locally in:"
echo "  $STATE_DIR/secrets.env"
