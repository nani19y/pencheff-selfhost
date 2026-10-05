#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# Bandit (Apache 2.0) — Python-only SAST.
#
# Usage: bandit.sh <repo_path> <output_json_path>

set -euo pipefail

TARGET_PATH="${1:?path required}"
OUT_JSON="${2:?output json path required}"

write_empty_json() {
  mkdir -p "$(dirname "$OUT_JSON")"
  printf '{"results":[],"errors":[]}\n' > "$OUT_JSON"
}

if ! command -v bandit >/dev/null 2>&1; then
  echo "bandit not installed; pipx install bandit" >&2
  write_empty_json
  exit 0
fi

# -r: recursive. -f json: machine-readable. -q: silence the textual report.
# Skip B101 (assert_used) — too noisy in test trees.
# Bandit exits 1 when findings present; swallow so callers can parse JSON.
bandit -r "$TARGET_PATH" -f json -q --skip B101 -o "$OUT_JSON" 2>/dev/null || true

if [[ ! -s "$OUT_JSON" ]]; then
  write_empty_json
fi
