#!/usr/bin/env bash
set -u

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"

PERSONA="${1:-}"
VALID="moodle registry finance research"

case " $VALID " in
    *" $PERSONA "*) : ;;
    *)
        echo "switch: unknown persona '${PERSONA}'; valid: $VALID" >&2
        exit 2
        ;;
esac

PROJECT="$(basename "$REPO_DIR")"
NETWORK="${PROJECT}_default"
STATE_VOLUME="${PROJECT}_engine-state"
RUNTIME_CONFIG="/state/caddy-active.json"
SEED_CONFIG="/seed/caddy.json"

# Edit the runtime config on the engine's volume, never the tracked seed file.
echo "switch: setting persona -> $PERSONA (runtime config on volume $STATE_VOLUME)"
if ! docker run --rm --network "$NETWORK" \
    -v "$SCRIPT_DIR:/tools:ro" \
    -v "$REPO_DIR/proxy:/seed:ro" \
    -v "$STATE_VOLUME:/state" \
    python:3-alpine sh -c "
        [ -f $RUNTIME_CONFIG ] || cp $SEED_CONFIG $RUNTIME_CONFIG
        python /tools/switch_caddy.py set $RUNTIME_CONFIG $PERSONA &&
        python /tools/switch_caddy.py load http://proxy:2019 $RUNTIME_CONFIG
    "; then
    echo "switch: FAIL - could not set/load config via admin API" >&2
    exit 1
fi

# 3. Verify the switch (PROXY_URL: :8080 locally, :80 in production).
PROXY_URL="${PROXY_URL:-http://localhost:8080}"
if python3 "$SCRIPT_DIR/coherence_check.py" "$PROXY_URL" "$PERSONA"; then
    echo "switch: PASS - $PERSONA is now being served at $PROXY_URL"
else
    echo "switch: WARN - coherence check against $PROXY_URL did not fully pass; check manually" >&2
fi
