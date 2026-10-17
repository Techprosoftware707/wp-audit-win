#!/usr/bin/env bash
# Build the installable wp-audit-win Companion plugin ZIP.
# Output: wordpress-plugin/dist/wp-audit-win-companion.zip
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="wp-audit-win-companion"
DIST="${HERE}/dist"

cd "$HERE"
[ -d "$SRC" ] || { echo "plugin source $SRC not found" >&2; exit 1; }

# Lint every PHP file first; never ship a file that doesn't parse.
echo "[build] linting PHP"
find "$SRC" -name '*.php' -print0 | while IFS= read -r -d '' f; do
  php -l "$f" >/dev/null
done

mkdir -p "$DIST"
rm -f "${DIST}/wp-audit-win-companion.zip"

# Zip with the plugin folder as the top-level entry (what WordPress expects).
if command -v zip >/dev/null 2>&1; then
  zip -rq "${DIST}/wp-audit-win-companion.zip" "$SRC" \
    -x '*/.*' -x '*/tests/*'
else
  # Fallback: python's zipfile if the zip binary is unavailable.
  python3 - "$SRC" "${DIST}/wp-audit-win-companion.zip" <<'PY'
import os, sys, zipfile
src, out = sys.argv[1], sys.argv[2]
with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
    for root, _, files in os.walk(src):
        if os.sep + "tests" in os.sep + root:
            continue
        for fn in files:
            p = os.path.join(root, fn)
            z.write(p, p)
PY
fi

echo "[build] wrote ${DIST}/wp-audit-win-companion.zip"
