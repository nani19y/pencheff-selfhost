#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# Checkov IaC baseline scan (Terraform + Kubernetes + Dockerfile).
#
# Usage: checkov.sh <iac_path> <target_name>

set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./common.sh
source "$HERE/common.sh"

TARGET_PATH="${1:?path required}"
TARGET_NAME="${2:?target name required}"
CHECKOV_IMAGE="${CHECKOV_IMAGE:-bridgecrew/checkov:latest}"

require_cmd docker

OUT_CSV="$(result_path checkov "$TARGET_NAME")"
OUT_RAW="$(result_path checkov "$TARGET_NAME" json)"
ensure_findings_file "$OUT_CSV"

log "checkov → $TARGET_PATH"
start_ts=$(date +%s)

docker run --rm -v "$(cd "$TARGET_PATH" && pwd):/tf" "$CHECKOV_IMAGE" \
  -d /tf --framework terraform,kubernetes,dockerfile -o json --quiet --compact > "$OUT_RAW" || true

python3 "$HERE/../score/normalize_findings.py" --from checkov --input "$OUT_RAW" --output "$OUT_CSV"

end_ts=$(date +%s)
log "checkov done in $((end_ts - start_ts))s → $OUT_CSV"
