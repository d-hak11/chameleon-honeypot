#!/bin/bash
TARGET="${TARGET:-http://proxy:80}"

echo "=== human-like browsing of $TARGET ==="
echo "Starting at $(date --utc +%H:%M:%S)"
echo

UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"

echo "1. Loading homepage..."
curl -s -o /dev/null -w 'Home: %{http_code}\n' -A "$UA" "$TARGET/"
sleep 3

echo "2. Loading login page..."
curl -s -o /dev/null -w 'Login: %{http_code}\n' -A "$UA" "$TARGET/login/index.php"
sleep 2

echo "3. Loading theme CSS..."
curl -s -o /dev/null -w 'Theme CSS: %{http_code}\n' -A "$UA" "$TARGET/static/theme/styles.css"
sleep 1

echo "4. Loading robots.txt..."
curl -s -o /dev/null -w 'Robots: %{http_code}\n' -A "$UA" "$TARGET/robots.txt"
sleep 2

echo "5. Loading sitemap.xml..."
curl -s -o /dev/null -w 'Sitemap: %{http_code}\n' -A "$UA" "$TARGET/sitemap.xml"
sleep 4

echo "6. Revisiting homepage..."
curl -s -o /dev/null -w 'Home2: %{http_code}\n' -A "$UA" "$TARGET/"
sleep 2

echo "7. Visiting a non-existent page (expect 404)..."
curl -s -o /dev/null -w '404: %{http_code}\n' -A "$UA" "$TARGET/course/view.php?id=1"
sleep 3

echo "8. Loading a favicon..."
curl -s -o /dev/null -w 'Favicon: %{http_code}\n' -A "$UA" "$TARGET/favicon.svg"

echo
echo "=== finished at $(date --utc +%H:%M:%S) ==="