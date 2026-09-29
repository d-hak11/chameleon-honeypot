#!/usr/bin/env bash
set -u

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"

BASE="${1:-https://sandbox405.moodledemo.net}"
OUT=""

i=0
for arg in "$@"; do
    i=$((i+1))
    case "$arg" in
        --output)
            i=$((i+1))
            OUT="${!i:-}"
            ;;
    esac
done


if [ -z "$OUT" ]; then
    HOST="$(printf '%s' "$BASE" | sed -E 's#^https?://##; s#[/:].*$##')"
    OUT="$REPO_DIR/evidence/observed/$HOST"
fi

UA="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"
mkdir -p "$OUT"

echo "observe: capturing $BASE -> $OUT"

# 1. Page HTML
if ! curl -fsS --max-time 25 -A "$UA" -o "$OUT/index.html" "$BASE/"; then
    echo "observe: FAILED to fetch $BASE/ (blocked? Cloudflare?)" >&2
    exit 1
fi

# 2. Boost theme stylesheet (first 'styles.php/<theme>' link in the page)
CSS_URL="$(grep -oE 'href="[^"]*theme/styles\.php/[^"]*"' "$OUT/index.html" | head -1 | sed -E 's/^href="//; s/"$//')"
if [ -n "$CSS_URL" ]; then
    case "$CSS_URL" in
        http*) CSS_FULL="$CSS_URL" ;;
        /*)    CSS_FULL="$BASE$CSS_URL" ;;
        *)     CSS_FULL="$BASE/$CSS_URL" ;;
    esac
    curl -fsS --max-time 30 -A "$UA" -o "$OUT/theme.css" "$CSS_FULL" \
        || echo "observe: could not fetch theme css $CSS_FULL" >&2
else
    echo "observe: no boost stylesheet link found in $BASE/"
fi

# 3. Icon usage (font-awesome classes on the page)
grep -oE 'fa fa-[a-z0-9-]+' "$OUT/index.html" \
    | sed 's/fa fa-//' | sort -u > "$OUT/icons.txt"

# 4. Favicon reference
grep -oiE '<link[^>]*rel="shortcut icon"[^>]*>' "$OUT/index.html" \
    | head -1 > "$OUT/favicon_ref.txt" || true

# 5. Reference summary
cat > "$OUT/reference.md" <<EOF
# boost-style page reference (from $BASE)

Gathered $(date -u +%F) by tools/observe.sh. Use this to *build matching* persona
assets. Do not bundle the raw captures; keep the persona brand fictional.

## Page identity observed
$(grep -oE '<title>[^<]*</title>' "$OUT/index.html" | head -1)
$(grep -oE '<meta[^>]*name="keywords"[^>]*>' "$OUT/index.html" | head -1)
- theme: $(grep -oE '"theme":"[a-z]+"' "$OUT/index.html" | head -1)
- iconset: $(grep -oE '"iconsystemmodule":"[^"]*"' "$OUT/index.html" | head -1)

## Favicon
$(cat "$OUT/favicon_ref.txt" 2>/dev/null)

## Boost CSS custom properties (variables)
$(if [ -s "$OUT/theme.css" ]; then grep -oE -- '--[a-z0-9-]+:[^;}]+' "$OUT/theme.css" | sort -u | head -60; fi)

## Icon classes used on the page
$(cat "$OUT/icons.txt" 2>/dev/null | sed 's/^/  /')

## Layout pattern (first navbar + main + footer lines)
$(grep -oE '<nav[^>]*navbar[^>]*>' "$OUT/index.html" | head -1)
$(grep -oE '<footer[^>]*>[^<]{0,80}' "$OUT/index.html" | head -1)
EOF

echo "observe: done -> $OUT/reference.md"
