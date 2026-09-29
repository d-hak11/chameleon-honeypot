#!/usr/bin/env bash
set -u

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_DIR" || exit 2

TARGET="http://localhost:8080"
NO_UP=0

for arg in "$@"; do
    case "$arg" in
        --no-up) NO_UP=1 ;;
        -*)
            echo "check: unknown option '$arg'" >&2
            exit 2
            ;;
        *) TARGET="$arg" ;;
    esac
done

echo "check: persona quality gates"
echo "check: target=$TARGET"

# --- 1. bring the stack up ---
if [ "$NO_UP" -eq 0 ]; then
    echo "check: docker compose up -d"
    if ! docker compose up -d --build; then
        echo "check: FAIL - docker compose up failed (is Docker running?)" >&2
        exit 2
    fi
fi

# --- 2. wait for the proxy to answer ---
echo "check: waiting for $TARGET"
for i in $(seq 1 30); do
    if curl -fsS --max-time 2 -o /dev/null "$TARGET" 2>/dev/null; then
        echo "check: proxy is up after ${i}s"
        break
    fi
    if [ "$i" -eq 30 ]; then
        echo "check: FAIL - $TARGET did not come up in time" >&2
        exit 2
    fi
    sleep 1
done

# --- 2b. stop the engine and pin moodle so our own requests can't rotate it ---
ENGINE_WAS_RUNNING=0
if [ -n "$(docker compose ps -q --status running engine 2>/dev/null)" ]; then
    ENGINE_WAS_RUNNING=1
    echo "check: stopping engine for the duration of the gates"
    docker compose stop engine >/dev/null 2>&1
fi
restore_engine() {
    if [ "$ENGINE_WAS_RUNNING" -eq 1 ]; then
        echo "check: restarting engine"
        docker compose start engine >/dev/null 2>&1
    fi
}
trap restore_engine EXIT

echo "check: pinning persona -> moodle"
if ! "$SCRIPT_DIR/switch_persona.sh" moodle >/dev/null 2>&1; then
    echo "check: FAIL - could not pin moodle via the admin API" >&2
    exit 2
fi

# --- 3. give-away scan (offline, against persona content) ---
echo "=== give-away scan ==="
python3 "$SCRIPT_DIR/give_away_scan.py"
GAW=$?

# --- 4. coherence check: active persona through the proxy ---
echo "=== coherence check (through proxy: moodle) ==="
python3 "$SCRIPT_DIR/coherence_check.py" "$TARGET" moodle
COH=$?

# --- 5. coherence check: every persona container, in-network ---
PROJECT="$(basename "$REPO_DIR")"
NETWORK="${PROJECT}_default"
PERSONAS="moodle registry finance research"
COH_ALL=0
for pers in $PERSONAS; do
    echo "=== coherence check (in-network: $pers) ==="
    if ! docker run --rm --network "$NETWORK" \
        -v "$SCRIPT_DIR:/tools:ro" \
        python:3-alpine python /tools/coherence_check.py "http://$pers:80" "$pers"; then
        COH_ALL=1
    fi
done

echo "---"
echo "give-away scan:               exit $GAW"
echo "coherence check (proxy):      exit $COH"
echo "coherence check (in-network): exit $COH_ALL"

if [ "$GAW" -eq 0 ] && [ "$COH" -eq 0 ] && [ "$COH_ALL" -eq 0 ]; then
    echo "check: PASS all gates"
    exit 0
fi

echo "check: FAIL - see individual gate output above" >&2
exit 1
