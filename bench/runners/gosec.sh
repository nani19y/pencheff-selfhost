#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# gosec (Apache 2.0) — Go SAST.
#
# Usage: gosec.sh <repo_path> <output_json_path>

set -euo pipefail

TARGET_PATH="${1:?path required}"
OUT_JSON="${2:?output json path required}"

write_empty_json() {
  mkdir -p "$(dirname "$OUT_JSON")"
  printf '{"Issues":[],"Stats":{}}\n' > "$OUT_JSON"
}

if ! command -v gosec >/dev/null 2>&1; then
  echo "gosec not installed; go install github.com/securego/gosec/v2/cmd/gosec@latest" >&2
  write_empty_json
  exit 0
fi

# Skip if no Go files present — gosec hard-errors on empty trees.
if ! find "$TARGET_PATH" -type f -name '*.go' -not -path '*/vendor/*' -print -quit | grep -q .; then
  write_empty_json
  exit 0
fi

# -fmt json: machine-readable. -out: file path.
# -no-fail: exit 0 regardless of findings (caller parses).
# -quiet: suppress the textual summary.
gosec -fmt json -out "$OUT_JSON" -no-fail -quiet "$TARGET_PATH/..." 2>/dev/null || true

if [[ ! -s "$OUT_JSON" ]]; then
  write_empty_json
fi
