#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# Mend.io CLI baseline — stub. Requires WS_APIKEY/WS_USERKEY/WS_PROJECTTOKEN and
# network access to saas.mend.io. Normalises output into the standard findings CSV.
#
# Usage: mend_cli.sh <repo_path> <target_name>

set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./common.sh
source "$HERE/common.sh"

TARGET_PATH="${1:?path required}"
TARGET_NAME="${2:?target name required}"

OUT_CSV="$(result_path mend "$TARGET_NAME")"
ensure_findings_file "$OUT_CSV"

if [[ -z "${WS_APIKEY:-}" ]]; then
  log "mend skipped — set WS_APIKEY / WS_USERKEY / WS_PROJECTTOKEN"
  exit 0
fi

log "mend → $TARGET_PATH (stub — wire in unified_agent if needed)"
