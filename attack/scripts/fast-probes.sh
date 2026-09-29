#!/bin/bash
TARGET="${1:-http://proxy:80}"

PROBES=(
    "/wp-admin"
    "/wp-login.php"
    "/.env"
    "/.git/config"
    "/admin"
    "/phpmyadmin"
    "/actuator"
    "/wp-content/plugins"
    "/wp-includes"
    "/administrator"
    "/cgi-bin/test.cgi"
    "/server-status"
    "/shell.php"
    "/config.php.bak"
    "/xmlrpc.php"
)

echo "=== fast probes at $TARGET ==="
echo "Starting at $(date --utc +%H:%M:%S)"
echo "Sending ${#PROBES[@]} paths x 4 rounds = $(( ${#PROBES[@]} * 4 )) requests"
echo

for round in 1 2 3 4; do
    for path in "${PROBES[@]}"; do
        curl -s -o /dev/null -w '%{http_code} ' \
            -A "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org)" \
            "$TARGET$path"
    done
    echo "  (round $round done)"
done
echo
echo "=== finished at $(date --utc +%H:%M:%S) ==="