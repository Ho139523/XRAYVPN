#!/usr/bin/env bash
# Shared 3X-UI panel helpers. Source this file; STATE_DIR must be set.
#
# Recent 3X-UI versions reject state-changing requests without a CSRF token
# (served in the login page) and set the session cookie on login. Older ones
# send no token, in which case the header is simply empty.

XUI_COOKIE_JAR="${STATE_DIR}/.xui-cookie"
XUI_CSRF_FILE="${STATE_DIR}/.xui-csrf"

xui_login() {
    local port="$1" username="$2" password="$3"
    local page csrf payload response

    rm -f "$XUI_COOKIE_JAR" "$XUI_CSRF_FILE"

    page="$(
        curl --fail --silent --show-error --max-time 10 \
            -c "$XUI_COOKIE_JAR" \
            "http://127.0.0.1:${port}/"
    )" || return 1

    csrf="$(
        printf '%s' "$page" |
        grep -o 'name="csrf-token" content="[^"]*"' |
        head -n 1 |
        sed 's/.*content="//; s/"$//' || true
    )"

    payload="$(
        python3 -c '
import json, sys
print(json.dumps({"username": sys.argv[1], "password": sys.argv[2]}))
' "$username" "$password"
    )"

    response="$(
        curl --fail --silent --show-error --max-time 10 \
            -c "$XUI_COOKIE_JAR" \
            -b "$XUI_COOKIE_JAR" \
            -H "X-CSRF-Token: ${csrf}" \
            -H 'Content-Type: application/json' \
            -X POST \
            "http://127.0.0.1:${port}/login" \
            --data "$payload"
    )" || return 1

    if ! printf '%s' "$response" | grep -q '"success":true'; then
        echo "$response"
        return 1
    fi

    printf '%s' "$csrf" > "$XUI_CSRF_FILE"
    chmod 600 "$XUI_COOKIE_JAR" "$XUI_CSRF_FILE"
}

xui_csrf() {
    cat "$XUI_CSRF_FILE" 2>/dev/null || true
}
