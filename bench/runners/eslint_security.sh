#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# eslint + eslint-plugin-security (MIT) — JS/TS SAST.
#
# Usage: eslint_security.sh <repo_path> <output_json_path>
#
# Avoids picking up the target repo's own .eslintrc — uses our flat
# config so the security ruleset is exactly the same on every scan.

set -euo pipefail

TARGET_PATH="${1:?path required}"
OUT_JSON="${2:?output json path required}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

write_empty_json() {
  mkdir -p "$(dirname "$OUT_JSON")"
  printf '[]\n' > "$OUT_JSON"
}

# eslint is invoked via npx, which falls back to a global install when
# the repo doesn't ship one. The plugin is required either globally or
# in the working dir.
if ! command -v npx >/dev/null 2>&1; then
  echo "npx not installed; install Node.js" >&2
  write_empty_json
  exit 0
fi

# Skip when no JS/TS sources are present.
if ! find "$TARGET_PATH" \
        -type f \( -name '*.js' -o -name '*.jsx' -o -name '*.ts' -o -name '*.tsx' \) \
        -not -path '*/node_modules/*' \
        -print -quit | grep -q .; then
  write_empty_json
  exit 0
fi

CONFIG_FILE="$SCRIPT_DIR/eslint_security.config.cjs"
if [[ ! -f "$CONFIG_FILE" ]]; then
  echo "missing eslint_security.config.cjs alongside this runner" >&2
  write_empty_json
  exit 0
fi

# --no-eslintrc + --config our pinned file: ignores the target's own
# config so we always run the same security ruleset.
# --resolve-plugins-relative-to: the plugin must be installed where
# this runner can find it (toolchain Docker image, or system-wide).
# -f json: machine-readable.
# --ext: extensions to lint.
# Exit code 1 when findings present; swallow for parser.
npx --no-install eslint \
    --no-eslintrc \
    --config "$CONFIG_FILE" \
    --resolve-plugins-relative-to "$SCRIPT_DIR" \
    --ext .js,.jsx,.ts,.tsx \
    -f json \
    -o "$OUT_JSON" \
    "$TARGET_PATH" 2>/dev/null || true

if [[ ! -s "$OUT_JSON" ]]; then
  write_empty_json
fi
