#!/usr/bin/env bash
#
# One-command installer for a fresh Ubuntu/Debian server.
#
#   sudo ./install.sh                     # new install
#   sudo ./install.sh --restore FILE      # new install that keeps users' policies, places and
#                                         # parent accounts from a backup made by ./backup.sh
#
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export ROOT_DIR

if [[ "${EUID}" -ne 0 ]]; then
    if command -v sudo >/dev/null 2>&1; then
        exec sudo -E bash "$ROOT_DIR/install.sh" "$@"
    fi

    echo "ERROR: run this installer as root."
    exit 1
fi

RESTORE_FILE=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --restore)
            if [[ $# -lt 2 || -z "$2" ]]; then
                echo "ERROR: --restore needs a backup file (see --help)"
                exit 1
            fi
            RESTORE_FILE="$2"
            shift 2
            ;;
        -h|--help)
            sed -n '3,8p' "$ROOT_DIR/install.sh" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *)
            echo "ERROR: unknown option: $1 (see --help)"
            exit 1
            ;;
    esac
done

CURRENT_STEP="startup"

on_error() {
    echo
    echo "========================================"
    echo " INSTALLATION FAILED"
    echo " during: $CURRENT_STEP"
    echo "========================================"
    echo
    echo "Fix the problem shown above, then run the installer again."
    echo "If it stopped after the panel container was created, start clean with:"
    echo
    echo "    sudo $ROOT_DIR/uninstall.sh"
    echo
}

echo
echo "========================================"
echo "        VPN APPLIANCE INSTALLER"
echo "========================================"
echo

if [[ -n "$RESTORE_FILE" ]]; then
    bash "$ROOT_DIR/scripts/lib/restore-backup.sh" "$RESTORE_FILE"
fi

trap on_error ERR

run_step() {
    local name="$1"
    local script="$2"

    CURRENT_STEP="$name"

    echo
    echo "[$name]"
    echo "----------------------------------------"

    if [[ ! -f "$ROOT_DIR/$script" ]]; then
        echo "ERROR: script not found:"
        echo "$ROOT_DIR/$script"
        exit 1
    fi

    bash "$ROOT_DIR/$script"
}

run_step "1/12 Preflight"          "scripts/00-preflight.sh"
run_step "2/12 Detect system"      "scripts/01-detect-system.sh"
run_step "3/12 Detect public IP"   "scripts/02-detect-ip.sh"
run_step "4/12 Install Docker"     "scripts/03-install-docker.sh"
run_step "5/12 Install 3X-UI"      "scripts/04-install-xui.sh"
run_step "6/12 Generate secrets"   "scripts/05-generate-secrets.sh"
run_step "7/12 Create Reality"     "scripts/06-create-reality-inbound.sh"
run_step "8/12 Create client"      "scripts/07-create-client.sh"
run_step "9/12 Configure network"  "scripts/08-configure-network.sh"
run_step "10/12 Content policy"    "scripts/09-content-policy.sh"
run_step "11/12 Healthcheck"       "scripts/10-healthcheck.sh"
run_step "12/12 Print result"      "scripts/11-print-result.sh"

trap - ERR

echo
echo "========================================"
echo " INSTALLATION COMPLETED SUCCESSFULLY"
echo "========================================"
