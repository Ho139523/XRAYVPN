#!/usr/bin/env bash
#
# Removes what install.sh created on this server: the location gate service, the
# 3X-UI container and its data, and the generated state. Use it to start a
# failed install over or to decommission a server. Docker, packages and any
# firewall rule stay. Make a backup first if you want to keep users' policies:
#
#   ./backup.sh && sudo ./uninstall.sh
#
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STATE_DIR="$ROOT_DIR/state"
UNIT_NAME="vpn-policy-gate.service"
UNIT_DIR="${SYSTEMD_UNIT_DIR:-/etc/systemd/system}"

ASSUME_YES=0
[[ "${1:-}" == "--yes" ]] && ASSUME_YES=1

if [[ "${EUID}" -ne 0 ]]; then
    if command -v sudo >/dev/null 2>&1; then
        exec sudo -E bash "$ROOT_DIR/uninstall.sh" "$@"
    fi
    echo "ERROR: run this as root."
    exit 1
fi

XUI_CONTAINER_NAME="3xui_app"
XUI_DATA_DIR="/opt/vpn-appliance/data"

if [[ -f "$STATE_DIR/xui.env" ]]; then
    . "$STATE_DIR/xui.env"
fi

echo "This will remove:"
echo "  - the systemd service $UNIT_NAME"
echo "  - the Docker container $XUI_CONTAINER_NAME and its data in $XUI_DATA_DIR"
echo "    (every VPN user, panel login and Reality key)"
echo "  - generated files in $STATE_DIR and docker-compose.yml"
echo

if [[ "$ASSUME_YES" -ne 1 ]]; then
    read -r -p "Type 'remove' to continue: " answer

    if [[ "$answer" != "remove" ]]; then
        echo "Nothing was changed."
        exit 1
    fi
fi

if command -v systemctl >/dev/null 2>&1; then
    systemctl disable --now "$UNIT_NAME" >/dev/null 2>&1 || true
fi

rm -f "$UNIT_DIR/$UNIT_NAME"

if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || true
fi

if command -v docker >/dev/null 2>&1; then
    docker rm -f "$XUI_CONTAINER_NAME" >/dev/null 2>&1 || true
fi

case "$XUI_DATA_DIR" in
    ""|"/"|"/opt"|"/root"|"/home")
        echo "WARNING: refusing to delete suspicious data directory: '$XUI_DATA_DIR'"
        ;;
    *)
        rm -rf "$XUI_DATA_DIR"
        ;;
esac

rm -f "$ROOT_DIR/docker-compose.yml"

if [[ -d "$STATE_DIR" ]]; then
    find "$STATE_DIR" -mindepth 1 -maxdepth 1 ! -name '.gitkeep' -exec rm -rf {} +
fi

echo
echo "Removed. If the installer opened a firewall port (ufw/firewalld), close it yourself."
