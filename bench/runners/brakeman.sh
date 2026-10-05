#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# Brakeman (MIT) — Ruby on Rails SAST.
#
# Usage: brakeman.sh <repo_path> <output_json_path>

set -euo pipefail

TARGET_PATH="${1:?path required}"
OUT_JSON="${2:?output json path required}"

write_empty_json() {
  mkdir -p "$(dirname "$OUT_JSON")"
  printf '{"warnings":[],"errors":[]}\n' > "$OUT_JSON"
}

if ! command -v brakeman >/dev/null 2>&1; then
  echo "brakeman not installed; gem install brakeman" >&2
  write_empty_json
  exit 0
fi

# Brakeman is Rails-specific — bail early for non-Rails Ruby trees so
# we don't pay the startup cost only to log a "not a Rails app" error.
if ! [[ -d "$TARGET_PATH/app" && -d "$TARGET_PATH/config" ]]; then
  write_empty_json
  exit 0
fi

# -f json: machine-readable. --no-progress: silence stderr noise.
# --no-pager: don't try to invoke `less`. Brakeman exits 0 when warnings
# present unless --exit-on-warn is set; we don't, so output JSON is the
# truth source.
brakeman -p "$TARGET_PATH" -f json -o "$OUT_JSON" \
  --no-progress --no-pager 2>/dev/null || true

if [[ ! -s "$OUT_JSON" ]]; then
  write_empty_json
fi
