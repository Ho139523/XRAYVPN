#!/usr/bin/env bash

set -Eeuo pipefail

echo "=== DOCKER INSTALLATION ==="

if command -v docker >/dev/null 2>&1; then
    echo "Docker already installed."

    docker --version

    if docker compose version >/dev/null 2>&1; then
        echo "Docker Compose plugin already installed."
    else
        echo "ERROR: Docker Compose plugin is missing."
        exit 1
    fi

    exit 0
fi

. /etc/os-release

case "${ID:-}" in

    ubuntu|debian)

        echo "Installing Docker using official Docker repository..."

        apt-get update

        apt-get install -y \
            ca-certificates \
            curl \
            gnupg

        install -m 0755 -d /etc/apt/keyrings

        if [[ ! -f /etc/apt/keyrings/docker.asc ]]; then
            curl \
                --fail \
                --silent \
                --show-error \
                --location \
                https://download.docker.com/linux/"${ID}"/gpg \
                -o /etc/apt/keyrings/docker.asc

            chmod a+r /etc/apt/keyrings/docker.asc
        fi

        ARCH="$(dpkg --print-architecture)"

        CODENAME="${VERSION_CODENAME:-}"

        if [[ -z "$CODENAME" ]]; then
            CODENAME="$(. /etc/os-release && echo "$VERSION_CODENAME")"
        fi

        if [[ -z "$CODENAME" ]]; then
            echo "ERROR: unable to determine distribution codename."
            exit 1
        fi

        cat > /etc/apt/sources.list.d/docker.list <<REPO
deb [arch=${ARCH} signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/${ID} ${CODENAME} stable
REPO

        apt-get update

        apt-get install -y \
            docker-ce \
            docker-ce-cli \
            containerd.io \
            docker-buildx-plugin \
            docker-compose-plugin

        systemctl enable docker
        systemctl start docker

        ;;

    *)
        echo "ERROR: automatic Docker installation is currently implemented for:"
        echo "       Ubuntu"
        echo "       Debian"
        echo
        echo "Detected OS: ${ID:-unknown}"
        exit 1
        ;;

esac

echo
echo "=== DOCKER VERSION ==="

docker --version
docker compose version

echo
echo "Docker installation OK."
