#!/usr/bin/env bash

set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export ROOT_DIR

echo
echo "========================================"
echo "        VPN APPLIANCE INSTALLER"
echo "========================================"
echo

run_step() {
    local name="$1"
    local script="$2"

    echo
    echo "[$name]"
    echo "----------------------------------------"

    if [[ ! -x "$ROOT_DIR/$script" ]]; then
        echo "ERROR: script not executable:"
        echo "$ROOT_DIR/$script"
        exit 1
    fi

    "$ROOT_DIR/$script"
}

run_step "1/11 Preflight"          "scripts/00-preflight.sh"
run_step "2/11 Detect system"      "scripts/01-detect-system.sh"
run_step "3/11 Detect public IP"   "scripts/02-detect-ip.sh"
run_step "4/11 Install Docker"     "scripts/03-install-docker.sh"
run_step "5/11 Install 3X-UI"      "scripts/04-install-xui.sh"
run_step "6/11 Generate secrets"  "scripts/05-generate-secrets.sh"
run_step "7/11 Create Reality"    "scripts/06-create-reality-inbound.sh"
run_step "8/11 Create client"     "scripts/07-create-client.sh"
run_step "9/11 Configure network" "scripts/08-configure-network.sh"
run_step "10/11 Healthcheck"      "scripts/09-healthcheck.sh"
run_step "11/11 Print result"     "scripts/10-print-result.sh"

echo
echo "========================================"
echo " INSTALLATION COMPLETED SUCCESSFULLY"
echo "========================================"
