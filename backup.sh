#!/usr/bin/env bash
#
# Saves what makes this server yours: every user's policy and places, the
# parent accounts, the phone tokens and config/.env. Keep the file private.
# Restore it on a new server with:  sudo ./install.sh --restore FILE
#
# Not included (the new server makes its own): the VPN link, panel login,
# Reality keys. VPN users have to import the new link.
#
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="${1:-$PWD/vpn-backup-$(date +%Y%m%d-%H%M).tar.gz}"

FILES=()

for file in \
    config/.env \
    state/policy.json \
    state/parents.json \
    state/gate.secret \
    state/parent-credentials.txt
do
    if [[ -f "$ROOT_DIR/$file" ]]; then
        FILES+=("$file")
    fi
done

if [[ ! -f "$ROOT_DIR/state/policy.json" ]]; then
    echo "ERROR: nothing to back up: state/policy.json does not exist yet."
    exit 1
fi

umask 077
tar -czf "$OUT" -C "$ROOT_DIR" "${FILES[@]}"
chmod 600 "$OUT"

echo "Backup written: $OUT"
echo
echo "Contains:"
printf '  %s\n' "${FILES[@]}"
echo
echo "It holds password hashes and the phone-token key: store it privately."
echo "On the new server:  sudo ./install.sh --restore $(basename "$OUT")"
