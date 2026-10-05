#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# YARA malware/pattern runner. Emits NDJSON — one match per line — because
# YARA doesn't ship a native JSON formatter. The normalizer handles both
# shapes (matched-strings-per-rule, printed-strings).
#
# Usage: yara.sh <repo_path> <output_ndjson_path> [rules_path]

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BENCH_ROOT="$(cd "$HERE/.." && pwd)"

TARGET_PATH="${1:?path required}"
OUT_NDJSON="${2:?output path required}"
RULES_PATH="${3:-$BENCH_ROOT/rules/yara}"

command -v yara >/dev/null 2>&1 || {
  echo "yara not installed; see https://yara.readthedocs.io/" >&2
  exit 127
}

: > "$OUT_NDJSON"

# -r recurse, -s print matched strings, -w suppress warnings, -f fast.
# YARA outputs "<rule> <file>" lines — we convert to NDJSON for the
# normalizer to consume uniformly.
yara -r -s -w -f "$RULES_PATH" "$TARGET_PATH" 2>/dev/null | \
  awk -v outfile="$OUT_NDJSON" '
    {
      # First token = rule, rest = file path (may contain spaces).
      rule=$1;
      sub(/^[^ ]+ /, "", $0);
      file=$0;
      printf("{\"rule\":\"%s\",\"file\":\"%s\"}\n", rule, file) >> outfile;
    }
  ' || true
