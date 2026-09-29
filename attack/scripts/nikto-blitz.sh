#!/bin/bash
TARGET="${TARGET:-http://proxy:80}"

echo "=== nikto scan of $TARGET ==="
echo "Starting at $(date --utc +%H:%M:%S)"
echo

nikto -h "$TARGET" -ssl 0 -nointeractive -timeout 5 \
    -Tuning 123489 \
    -Format txt \
    -maxtime 60

echo
echo "=== nikto finished at $(date --utc +%H:%M:%S) ==="