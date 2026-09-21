#!/usr/bin/env bash

set -Eeuo pipefail

echo "=== DOCKER INSTALLATION ==="

# Fresh servers may still be running their first unattended upgrade (apt lock)
# and Ubuntu's needrestart would otherwise stop to ask questions.
export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE=a
APT=(apt-get -o DPkg::Lock::Timeout=600 -y -qq)

start_docker() {
    if [[ -d /run/systemd/system ]]; then
        systemctl enable docker >/dev/null 2>&1 || true
        systemctl start docker
    fi

    for _ in $(seq 1 30); do
        if docker info >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done

    echo "ERROR: the Docker daemon is not running."
    exit 1
}

if command -v docker >/dev/null 2>&1; then
    echo "Docker already installed."

    docker --version

    if ! docker compose version >/dev/null 2>&1; then
        echo "Docker Compose plugin is missing; installing it..."

        "${APT[@]}" update
        "${APT[@]}" install docker-compose-plugin ||
            "${APT[@]}" install docker-compose-v2 || true

        if ! docker compose version >/dev/null 2>&1; then
            echo "ERROR: Docker Compose plugin is missing and could not be installed."
            exit 1
        fi
    fi

    echo "Docker Compose plugin present."

    start_docker

    exit 0
fi

. /etc/os-release

case "${ID:-}" in

    ubuntu|debian)

        echo "Installing Docker using official Docker repository..."

        "${APT[@]}" update

        "${APT[@]}" install \
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

        "${APT[@]}" update

        "${APT[@]}" install \
            docker-ce \
            docker-ce-cli \
            containerd.io \
            docker-buildx-plugin \
            docker-compose-plugin

        start_docker

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
