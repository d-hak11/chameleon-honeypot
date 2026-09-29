#!/bin/bash
TARGET="${TARGET:-proxy}"

echo "=== nmap scan of $TARGET ==="
echo "Starting at $(date --utc +%H:%M:%S)"
echo

nmap -sV --version-intensity 3 -p 80,443,8080,8443 \
    --max-rtt-timeout 500ms \
    --max-retries 2 \
    "$TARGET"

echo
echo "=== nmap finished at $(date --utc +%H:%M:%S) ==="