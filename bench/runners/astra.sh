#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# Astra Security — STUB RUNNER.
#
# Astra's pentest platform (https://www.getastra.com) does not expose a
# public programmatic API for commissioning scans at the individual-
# account tier, so we can't automate it end-to-end the way we do ZAP /
# Pencheff. What we CAN do is:
#
#   1. Run the scan manually in the Astra dashboard against a public URL
#      that mirrors the bench target (e.g. ngrok-expose juice-shop).
#   2. Export the report as CSV or JSON from the dashboard.
#   3. Drop the file next to this script as  astra-<target>-<date>.raw.*
#   4. Re-run this script with ASTRA_RAW=<path> to normalise it.
#
# Usage:
#   ASTRA_RAW=/path/to/astra-juice-shop.csv ./astra.sh <target_url> juice-shop

set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./common.sh
source "$HERE/common.sh"

TARGET_URL="${1:?target URL required}"
TARGET_NAME="${2:?target name required}"

if [[ -z "${ASTRA_RAW:-}" ]]; then
  cat >&2 <<EOF
[astra] Astra has no public commissioning API — automation isn't possible.

To score Astra on this target:

  1. Expose $TARGET_URL publicly (ngrok / Cloudflare Tunnel).
  2. In the Astra dashboard, add the public URL as a target and start a
     scan. Wait for it to finish.
  3. Export the report (CSV preferred, JSON works).
  4. Re-run:
       ASTRA_RAW=/path/to/export.csv  $0 $TARGET_URL $TARGET_NAME

Skipping Astra for now; the summary will show '-' for its row.
EOF
  exit 0
fi

[[ -f "$ASTRA_RAW" ]] || { log "$ASTRA_RAW not found"; exit 1; }

OUT_CSV="$(result_path astra "$TARGET_NAME")"
ensure_findings_file "$OUT_CSV"

python3 "$HERE/../score/normalize_findings.py" \
  --scanner astra --target "$TARGET_NAME" \
  --format astra < "$ASTRA_RAW" >> "$OUT_CSV"

findings_total="$(( $(wc -l < "$OUT_CSV") - 1 ))"
log "astra ingested from $ASTRA_RAW · findings: $findings_total"

meta_csv="$RESULTS_DIR/_meta-$TODAY.csv"
[[ -f "$meta_csv" ]] || echo 'scanner,target,status,duration_s,findings_total,findings_kept' > "$meta_csv"
echo "astra,$TARGET_NAME,done,,${findings_total},${findings_total}" >> "$meta_csv"
