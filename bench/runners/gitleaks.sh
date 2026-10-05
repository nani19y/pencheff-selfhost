#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# Gitleaks secret-scanner runner.
#
# Usage: gitleaks.sh <repo_path> <output_json_path> [mode]
#
#   mode = "git"    (default) — scan working tree + git history
#   mode = "nogit"           — scan working tree only (no .git/ present)

set -euo pipefail

TARGET_PATH="${1:?path required}"
OUT_JSON="${2:?output json path required}"
MODE="${3:-git}"

command -v gitleaks >/dev/null 2>&1 || {
  echo "gitleaks not installed; see https://github.com/gitleaks/gitleaks" >&2
  exit 127
}

# `detect` scans the working tree plus the last N commits. With --no-git
# it only scans the working tree as a plain directory (needed when .git
# was stripped or the input is a local non-git tree). Exit code 1 means
# findings were reported; we swallow it so callers can parse the JSON.
GITLEAKS_ARGS=(
  detect
  --source "$TARGET_PATH"
  --report-format json
  --report-path "$OUT_JSON"
  --no-banner
  --exit-code 0
)
if [[ "$MODE" == "nogit" ]]; then
  GITLEAKS_ARGS+=(--no-git)
fi

gitleaks "${GITLEAKS_ARGS[@]}" || true
