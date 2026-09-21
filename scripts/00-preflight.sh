#!/usr/bin/env bash

set -Eeuo pipefail

echo "=== PREFLIGHT ==="

if [[ "${EUID}" -ne 0 ]]; then
    echo "ERROR: installer must be run as root."
    exit 1
fi

if [[ -z "${ROOT_DIR:-}" ]]; then
    echo "ERROR: ROOT_DIR is not set."
    exit 1
fi

if [[ ! -f /etc/os-release ]]; then
    echo "ERROR: /etc/os-release not found."
    exit 1
fi

. /etc/os-release

case "${ID:-}" in
    ubuntu|debian)
        ;;
    *)
        echo "ERROR: unsupported OS: ${PRETTY_NAME:-${ID:-unknown}}"
        echo "       This installer supports Ubuntu and Debian."
        exit 1
        ;;
esac

case "$(uname -m)" in
    x86_64|amd64|aarch64|arm64)
        ;;
    *)
        echo "ERROR: unsupported architecture: $(uname -m) (need amd64 or arm64)"
        exit 1
        ;;
esac

# Fresh servers often lack some of these. Install what is missing instead of failing.
declare -A PACKAGE_FOR=(
    [curl]=curl [wget]=wget [openssl]=openssl [python3]=python3 [ss]=iproute2
    [tar]=tar [gzip]=gzip [sha256sum]=coreutils [awk]=gawk [sed]=sed [grep]=grep
)

missing=()

for command in bash awk sed grep curl wget tar gzip sha256sum openssl python3 ss; do
    if ! command -v "$command" >/dev/null 2>&1; then
        missing+=("${PACKAGE_FOR[$command]:-$command}")
    fi
done

if [[ "${#missing[@]}" -gt 0 ]]; then
    echo
    echo "Installing missing tools: ${missing[*]}"

    export DEBIAN_FRONTEND=noninteractive
    export NEEDRESTART_MODE=a

    # A brand-new server is often still running its first unattended upgrade
    # and holds the apt lock for a few minutes.
    apt-get -o DPkg::Lock::Timeout=600 update -qq
    apt-get -o DPkg::Lock::Timeout=600 install -y -qq \
        --no-install-recommends ca-certificates "${missing[@]}"

    for command in curl wget openssl python3 ss; do
        if ! command -v "$command" >/dev/null 2>&1; then
            echo "ERROR: required command still missing after install: $command"
            exit 1
        fi
    done
fi

if ! python3 -c 'import sys; sys.exit(sys.version_info < (3, 8))'; then
    echo "ERROR: Python 3.8 or newer is required (found $(python3 --version 2>&1))."
    exit 1
fi

FREE_KB="$(df --output=avail -k "$ROOT_DIR" | tail -n 1 | tr -d ' ')"

if [[ "$FREE_KB" -lt 2000000 ]]; then
    echo "ERROR: less than 2 GB of free disk space available."
    exit 1
fi

check_host() {
    local url="$1" what="$2" code

    code="$(
        curl --silent --output /dev/null --max-time 10 \
            --write-out '%{http_code}' "$url" 2>/dev/null || true
    )"

    if [[ "$code" == "000" || -z "$code" ]]; then
        echo "ERROR: cannot reach $what ($url)."
        echo "       Check DNS, the firewall and any provider restrictions."
        exit 1
    fi
}

check_host "https://ghcr.io/v2/" "the container registry (ghcr.io)"

if ! command -v docker >/dev/null 2>&1; then
    check_host "https://download.docker.com/linux/${ID}/gpg" "download.docker.com"
fi

if [[ ! -d /run/systemd/system ]]; then
    echo
    echo "WARNING: systemd is not running. The location gate and parent page"
    echo "         cannot be installed as a service on this machine."
fi

# The porn filter hijacks DNS through a family resolver; without a reachable
# one the policy step would refuse to run, so find out now.
if ! python3 "$ROOT_DIR/policy/vpn_policy.py" dns-check; then
    echo
    echo "ERROR: the family DNS resolver is not reachable from this server."
    echo "       Set POLICY_FAMILY_DNS to one that is, or POLICY_BLOCK_PORN=false,"
    echo "       in config/.env (see config/appliance.env.example)."
    exit 1
fi

echo "OS           : ${PRETTY_NAME:-unknown}"
echo "Architecture : $(uname -m)"
echo "Kernel       : $(uname -r)"
echo "Python       : $(python3 --version 2>&1)"
echo "Root         : $ROOT_DIR"

if [[ -f "$ROOT_DIR/config/.env" ]]; then
    echo
    echo "Configuration: config/.env"
else
    echo
    echo "Configuration: using defaults"
fi

echo
echo "Preflight OK."
