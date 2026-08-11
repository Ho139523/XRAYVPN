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

for command in \
    bash \
    awk \
    sed \
    grep \
    curl \
    wget \
    tar \
    gzip \
    sha256sum \
    openssl
do
    if ! command -v "$command" >/dev/null 2>&1; then
        echo "ERROR: required command not found: $command"
        exit 1
    fi
done

if [[ ! -f /etc/os-release ]]; then
    echo "ERROR: /etc/os-release not found."
    exit 1
fi

. /etc/os-release

echo "OS           : ${PRETTY_NAME:-unknown}"
echo "Architecture : $(uname -m)"
echo "Kernel       : $(uname -r)"
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
