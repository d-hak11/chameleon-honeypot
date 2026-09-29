#!/usr/bin/env bash
set -u

OUT="${1:?output dir required}"
SAMPLES="${2:?sample count required}"
shift 2

mkdir -p "$OUT"

UA="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"

for url in "$@"; do
    host="$(echo "$url" | sed -E 's#https?://##; s#/.*##')"
    path="$(echo "$url" | sed -E 's#https?://[^/]*##')"
    label="${host}$(echo "${path:-/}" | tr '/' '_')"
    csv="$OUT/${label}.csv"
    echo "url,time_connect,time_appconnect,time_starttransfer,time_total,http_code,server_think" > "$csv"

    echo "observe_timing: $url  (${SAMPLES} samples)"
    for i in $(seq 1 "$SAMPLES"); do
        read -r c ac st tt code < <(curl -s -o /dev/null \
            -A "$UA" \
            --max-time 20 \
            -w '%{time_connect} %{time_appconnect} %{time_starttransfer} %{time_total} %{http_code}' \
            "$url" 2>/dev/null)
        if [ -z "${code:-}" ]; then
            continue
        fi
        think="$(python3 -c "
c, ac, st = ${c:-0}, ${ac:-0}, ${st:-0}
base = ac if ac > 0 else c
print(round(max(st - base, 0.0), 6))
")"
        echo "$url,$c,$ac,$st,$tt,$code,$think" >> "$csv"
        sleep 1
    done
    echo "observe_timing: wrote $csv"
done

echo "observe_timing: done"
