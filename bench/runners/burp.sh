#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# Burp Suite — STUB RUNNER.
#
# Burp Suite Professional does not ship a CLI / REST API for driving
# active scans. Burp Suite Enterprise Edition does expose a REST API
# (https://portswigger.net/burp/documentation/enterprise/rest-api),
# but it's a paid product with a server component to install.
#
# If you have Burp Enterprise, point BURP_API_URL at your deployment
# and supply BURP_API_KEY. Otherwise run the scan by hand in Burp Pro,
# export findings as JSON, and feed them in via BURP_RAW like the
# astra.sh pattern.
#
# Usage (Enterprise):
#   BURP_API_URL=https://burp.internal/api BURP_API_KEY=xxx ./burp.sh <target_url> <target_name>
#
# Usage (manual export):
#   BURP_RAW=/path/to/burp-export.xml ./burp.sh <target_url> <target_name>

set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./common.sh
source "$HERE/common.sh"

TARGET_URL="${1:?target URL required}"
TARGET_NAME="${2:?target name required}"

if [[ -n "${BURP_RAW:-}" ]]; then
  [[ -f "$BURP_RAW" ]] || { log "$BURP_RAW not found"; exit 1; }
  OUT_CSV="$(result_path burp "$TARGET_NAME")"
  ensure_findings_file "$OUT_CSV"
  python3 "$HERE/../score/normalize_findings.py" \
    --scanner burp --target "$TARGET_NAME" \
    --format burp < "$BURP_RAW" >> "$OUT_CSV"
  findings_total="$(( $(wc -l < "$OUT_CSV") - 1 ))"
  log "burp ingested from $BURP_RAW · findings: $findings_total"
  exit 0
fi

if [[ -z "${BURP_API_URL:-}" || -z "${BURP_API_KEY:-}" ]]; then
  cat >&2 <<EOF
[burp] Burp Pro has no public scan API; Burp Enterprise does but needs
a licensed server. Either:
  • Run the scan by hand in Burp Pro, export the issue report as
    XML/JSON, then re-run:
       BURP_RAW=/path/to/export.xml  $0 $TARGET_URL $TARGET_NAME
  • Supply BURP_API_URL + BURP_API_KEY for Burp Enterprise and this
    script will drive a scan.

Skipping Burp for now.
EOF
  exit 0
fi

# Placeholder: Burp Enterprise scan orchestration lives here.
log "Burp Enterprise automation not yet implemented — PRs welcome."
exit 0
