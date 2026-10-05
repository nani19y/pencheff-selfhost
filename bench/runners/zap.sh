#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# OWASP ZAP baseline scan via the official Docker image.
#   https://www.zaproxy.org/docs/docker/baseline-scan/
#
# Usage: zap.sh <target_url> <target_name>

set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./common.sh
source "$HERE/common.sh"

TARGET_URL="${1:?target URL required}"
TARGET_NAME="${2:?target name required}"
ZAP_IMAGE="${ZAP_IMAGE:-ghcr.io/zaproxy/zaproxy:stable}"
ZAP_TIMEOUT="${ZAP_TIMEOUT:-2400}"   # seconds for the full baseline sweep

require_cmd docker

DOCKER_URL="$(docker_reachable_url "$TARGET_URL")"
OUT_CSV="$(result_path zap "$TARGET_NAME")"
OUT_RAW="$(result_path zap "$TARGET_NAME" json)"
ensure_findings_file "$OUT_CSV"

log "zap baseline → $DOCKER_URL (timeout ${ZAP_TIMEOUT}s)"
start_ts=$(date +%s)

# zap-baseline.py writes the JSON report to /zap/wrk/<path> inside the
# container. We bind-mount the bench results dir so the output lands
# where we expect.
docker run --rm \
  -v "$RESULTS_DIR:/zap/wrk:rw" \
  --add-host=host.docker.internal:host-gateway \
  -t "$ZAP_IMAGE" \
  zap-baseline.py -t "$DOCKER_URL" \
    -J "zap-${TARGET_NAME}-${TODAY}.json" \
    -m 10 \
    -T "$ZAP_TIMEOUT" \
  || true   # zap exits 2 when it reports warnings — normal

duration=$(( $(date +%s) - start_ts ))

# Docker wrote the JSON inside RESULTS_DIR; adjust path
mv "$RESULTS_DIR/zap-${TARGET_NAME}-${TODAY}.json" "$OUT_RAW" 2>/dev/null || true

if [[ -s "$OUT_RAW" ]]; then
  python3 "$HERE/../score/normalize_findings.py" \
    --scanner zap --target "$TARGET_NAME" \
    --format zap < "$OUT_RAW" >> "$OUT_CSV"
  findings_total="$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(sum(len(s.get("alerts",[])) for s in d.get("site",[])))' "$OUT_RAW")"
else
  log "no JSON output produced by ZAP — check the container logs"
  findings_total=0
fi

log "zap done in ${duration}s · findings: $findings_total"

meta_csv="$RESULTS_DIR/_meta-$TODAY.csv"
[[ -f "$meta_csv" ]] || echo 'scanner,target,status,duration_s,findings_total,findings_kept' > "$meta_csv"
echo "zap,$TARGET_NAME,done,$duration,$findings_total,$findings_total" >> "$meta_csv"
