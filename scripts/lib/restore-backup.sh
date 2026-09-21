#!/usr/bin/env bash
# Unpacks a backup made by backup.sh into this checkout. Called by install.sh.
set -Eeuo pipefail

FILE="${1:-}"
STATE_DIR="$ROOT_DIR/state"

echo "=== RESTORE BACKUP ==="

if [[ -z "$FILE" || ! -f "$FILE" ]]; then
    echo "ERROR: backup file not found: ${FILE:-<none>}"
    exit 1
fi

# Only known files, only at known places: a backup must not be able to
# overwrite anything else.
while IFS= read -r member; do
    case "$member" in
        config/.env|state/policy.json|state/parents.json|state/gate.secret|state/parent-credentials.txt)
            ;;
        *)
            echo "ERROR: unexpected entry in backup: $member"
            exit 1
            ;;
    esac
done < <(tar -tzf "$FILE")

mkdir -p "$ROOT_DIR/config" "$STATE_DIR"
chmod 700 "$STATE_DIR"

tar -xzf "$FILE" -C "$ROOT_DIR" --no-same-owner

chmod 600 "$STATE_DIR"/policy.json "$STATE_DIR"/parents.json "$STATE_DIR"/gate.secret \
    "$STATE_DIR"/parent-credentials.txt "$ROOT_DIR"/config/.env 2>/dev/null || true

python3 - "$ROOT_DIR" <<'PY'
import json
import re
import sys
from pathlib import Path

root = Path(sys.argv[1])
children = list(json.loads((root / "state" / "policy.json").read_text()).get("children", {}))
env = root / "config" / ".env"
text = env.read_text() if env.exists() else ""

print("Restored policies for: %s" % (", ".join(children) or "(none)"))

if children and not re.search(r"^CLIENT_EMAIL=", text, re.M):
    env.write_text(text + ("\n" if text and not text.endswith("\n") else "")
                   + "CLIENT_EMAIL=%s\n" % children[0])
    env.chmod(0o600)
    print("The first VPN user will be created as %r so it picks up its policy and parents." % children[0])

others = children[1:]
if others:
    print("Also create these users in 3X-UI with exactly these emails, and their")
    print("policies and parents attach automatically: %s" % ", ".join(others))
PY

echo
echo "Backup restored."
