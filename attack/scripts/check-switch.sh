#!/bin/bash
echo "=== Current persona (via proxy :8080) ==="
curl -s http://localhost:8080/ | grep -oE '<title>[^<]*</title>'

echo
echo "=== caddy.json upstream on disk ==="
python3 -c "import json;print(json.load(open('proxy/caddy.json'))['apps']['http']['servers']['srv0']['routes'][0]['handle'][2]['upstreams'][0]['dial'])"

echo
echo "=== Last 3 engine evaluation summaries ==="
docker compose logs engine 2>&1 | grep evaluation_summary | tail -3 | while read -r line; do
    echo "$line" | python3 -c "
import sys,json
d=json.loads(sys.stdin.read())
print(f'  session: {d[\"sessions\"]}, scanner: {d[\"scanner\"]}, label: {d[\"labels\"]}, persona: {d[\"persona\"]}, hot: {d[\"hot\"]}, reason: {d[\"reason\"]}')
" 2>/dev/null || echo "$line" | head -c 200
done

echo
echo "=== Last switch event ==="
docker compose logs engine 2>&1 | grep '\"event\":\"switch\"' | tail -1 | while read -r line; do
    echo "$line" | python3 -c "
import sys,json
d=json.loads(sys.stdin.read())
print(f'  {d[\"from_persona\"]} -> {d[\"persona\"]} (reason: {d[\"reason\"]})')
" 2>/dev/null || echo '(no switch event yet)'
done