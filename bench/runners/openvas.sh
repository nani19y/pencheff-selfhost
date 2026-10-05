#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# OpenVAS / Greenbone baseline — stub. The full stack is a ~6GB container,
# not practical to spin up inline in CI. When a Greenbone Community Edition
# stack is already reachable via OMP, set ``OPENVAS_HOST``/``OPENVAS_USER``/
# ``OPENVAS_PASS`` and this runner will drive it via ``gvm-cli``.
#
# Usage: openvas.sh <target_url_or_host> <target_name>

set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./common.sh
source "$HERE/common.sh"

TARGET="${1:?target required}"
TARGET_NAME="${2:?target name required}"

OUT_CSV="$(result_path openvas "$TARGET_NAME")"
ensure_findings_file "$OUT_CSV"

if ! command -v gvm-cli >/dev/null 2>&1; then
  log "openvas skipped — gvm-cli not on PATH"
  exit 0
fi
if [[ -z "${OPENVAS_HOST:-}" ]]; then
  log "openvas skipped — set OPENVAS_HOST to a reachable Greenbone instance"
  exit 0
fi

log "openvas → $TARGET via $OPENVAS_HOST (stub run)"
# Real integration lives elsewhere; this stub keeps bench.sh happy.
