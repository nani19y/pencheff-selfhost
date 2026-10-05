#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# Trivy image/filesystem scan — feeds the ``supply-chain`` comparison row.
#
# Usage: trivy.sh <target_url_or_path> <target_name>
#
# If the target looks like a URL we skip (trivy is filesystem/image-only);
# if it's a path, run ``trivy fs``; if it's an image ref, run ``trivy image``.

set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./common.sh
source "$HERE/common.sh"

TARGET="${1:?target required}"
TARGET_NAME="${2:?target name required}"
TRIVY_IMAGE="${TRIVY_IMAGE:-aquasec/trivy:latest}"

require_cmd docker

OUT_CSV="$(result_path trivy "$TARGET_NAME")"
OUT_RAW="$(result_path trivy "$TARGET_NAME" json)"
ensure_findings_file "$OUT_CSV"

if [[ "$TARGET" =~ ^https?:// ]]; then
  log "trivy does not scan URLs — emitting empty result for $TARGET_NAME"
  exit 0
fi

log "trivy → $TARGET"
start_ts=$(date +%s)

MOUNT_FLAG=""
SCAN_CMD=("image" "$TARGET")
if [[ -d "$TARGET" ]]; then
  MOUNT_FLAG="-v $(cd "$TARGET" && pwd):/work"
  SCAN_CMD=("fs" "/work")
fi

# shellcheck disable=SC2086
docker run --rm $MOUNT_FLAG "$TRIVY_IMAGE" "${SCAN_CMD[@]}" \
  --quiet --format json --scanners vuln,secret,misconfig > "$OUT_RAW" || true

python3 "$HERE/../score/normalize_findings.py" --from trivy --input "$OUT_RAW" --output "$OUT_CSV"

end_ts=$(date +%s)
log "trivy done in $((end_ts - start_ts))s → $OUT_CSV"
