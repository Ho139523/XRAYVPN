#!/usr/bin/env bash

set -Eeuo pipefail

STATE_DIR="$ROOT_DIR/state"

mkdir -p "$STATE_DIR"

. /etc/os-release

OS_ID="${ID:-unknown}"
OS_VERSION="${VERSION_ID:-unknown}"
ARCH="$(uname -m)"

case "$ARCH" in
    x86_64|amd64)
        DOCKER_ARCH="amd64"
        ;;
    aarch64|arm64)
        DOCKER_ARCH="arm64"
        ;;
    armv7l|armv7)
        DOCKER_ARCH="arm"
        ;;
    *)
        echo "ERROR: unsupported architecture: $ARCH"
        exit 1
        ;;
esac

case "$OS_ID" in
    ubuntu|debian)
        PACKAGE_MANAGER="apt"
        ;;
    fedora|rhel|centos|rocky|almalinux)
        if command -v dnf >/dev/null 2>&1; then
            PACKAGE_MANAGER="dnf"
        else
            PACKAGE_MANAGER="yum"
        fi
        ;;
    *)
        PACKAGE_MANAGER="unknown"
        ;;
esac

cat > "$STATE_DIR/system.env" <<ENV
OS_ID=$OS_ID
OS_VERSION=$OS_VERSION
ARCH=$ARCH
DOCKER_ARCH=$DOCKER_ARCH
PACKAGE_MANAGER=$PACKAGE_MANAGER
ENV

echo "=== SYSTEM DETECTION ==="
echo "OS              : $OS_ID"
echo "OS version      : $OS_VERSION"
echo "Architecture    : $ARCH"
echo "Docker arch     : $DOCKER_ARCH"
echo "Package manager : $PACKAGE_MANAGER"

echo
echo "System detection OK."
