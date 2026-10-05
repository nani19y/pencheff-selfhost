#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# Commission a Pencheff scan via its HTTP API, poll until done, then
# export the findings as a normalised CSV for scoring.
#
# Usage:
#   pencheff.sh <target_url> <target_name>           # new scan
#   pencheff.sh --resume <scan_id> <target_name>     # pick up a running / finished scan
#
# ``--resume`` is what you want when your Clerk session token expired
# mid-poll: refresh the token and point the script at the existing scan
# id, and it skips creation, polls to completion, then exports.
#
# Env:
#   PENCHEFF_API_URL    default http://localhost:8000
#   PENCHEFF_API_TOKEN  required — Clerk session JWT (DevTools → Application → Cookies → __session
#                       or `await window.Clerk.session.getToken()` in the browser console)
#   PENCHEFF_PROFILE    quick | standard | deep   (default standard)

set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./common.sh
source "$HERE/common.sh"

RESUME=""
if [[ "${1:-}" == "--resume" ]]; then
  RESUME="${2:?scan_id required after --resume}"
  TARGET_NAME="${3:?target name required}"
  TARGET_URL=""  # not needed for resume
  shift 3
else
  TARGET_URL="${1:?target URL required (or use --resume <scan_id>)}"
  TARGET_NAME="${2:?target name required}"
fi
API="${PENCHEFF_API_URL:-http://localhost:8000}"
PROFILE="${PENCHEFF_PROFILE:-standard}"

: "${PENCHEFF_API_TOKEN:?Set PENCHEFF_API_TOKEN to a valid Clerk session JWT}"

require_cmd curl
require_cmd jq

AUTH=(-H "Authorization: Bearer $PENCHEFF_API_TOKEN")
CT=(-H "Content-Type: application/json")

OUT_CSV="$(result_path pencheff "$TARGET_NAME")"
OUT_RAW="$(result_path pencheff "$TARGET_NAME" json)"
ensure_findings_file "$OUT_CSV"

if [[ -n "$RESUME" ]]; then
  scan_id="$RESUME"
  log "pencheff resume → scan $scan_id"
else
  log "pencheff → $TARGET_URL ($PROFILE)"

  # ---- 1. Create or fetch the target --------------------------------------
  TARGET_JSON=$(jq -n --arg name "$TARGET_NAME" --arg url "$TARGET_URL" \
    '{name:$name, base_url:$url}')
  target_id="$(curl -sS "${AUTH[@]}" "${CT[@]}" "$API/targets" -d "$TARGET_JSON" | jq -r '.id // empty')"
  if [[ -z "$target_id" ]]; then
    log "failed to create target — does it already exist?"
    existing="$(curl -sS "${AUTH[@]}" "$API/targets" | jq --arg n "$TARGET_NAME" '.[] | select(.name==$n) | .id' -r | head -n1)"
    if [[ -n "$existing" ]]; then
      target_id="$existing"
      log "reusing existing target $target_id"
    else
      log "unable to create or locate target for '$TARGET_NAME'"
      exit 1
    fi
  fi
  log "target id: $target_id"

  # ---- 2. Kick off a scan -------------------------------------------------
  scan_id="$(curl -sS "${AUTH[@]}" "${CT[@]}" "$API/scans" \
    -d "$(jq -n --arg tid "$target_id" --arg p "$PROFILE" '{target_id:$tid, profile:$p}')" \
    | jq -r '.id')"
  [[ -n "$scan_id" && "$scan_id" != "null" ]] || { log "scan creation failed"; exit 1; }
  log "scan id: $scan_id"
fi

# ---- 3. Poll until status ∈ {done, failed} --------------------------------
# Handles the common failure mode where the Clerk session token expires
# mid-scan (default TTL is 60 seconds!): on 401 we stop polling and tell
# the user exactly how to resume with a fresh token. The scan keeps
# running on the backend, so resuming just means querying it directly.
start_ts=$(date +%s)
auth_fail_count=0
while :; do
  tmp="$(mktemp)"
  http_code=$(curl -sS -o "$tmp" -w '%{http_code}' "${AUTH[@]}" "$API/scans/$scan_id" || echo 000)
  body="$(cat "$tmp")"
  rm -f "$tmp"

  if [[ "$http_code" == "401" ]]; then
    auth_fail_count=$((auth_fail_count + 1))
    # One retry in case of a transient JWKS hiccup; then give up.
    if (( auth_fail_count >= 2 )); then
      echo >&2
      log "API returned 401 twice — your Clerk session token has expired"
      log "Clerk default TTL is 60 s; for long bench runs use a JWT Template"
      log "(see bench/GETTING_TOKEN.md, Option B)."
      log ""
      log "The scan is still running on the backend. To resume:"
      log "  export PENCHEFF_API_TOKEN='<fresh-token>'"
      log "  curl -sH \"Authorization: Bearer \$PENCHEFF_API_TOKEN\" \\"
      log "       $API/scans/$scan_id | jq '{status, grade, summary}'"
      exit 1
    fi
    sleep 5
    continue
  fi

  if [[ "$http_code" != "200" ]]; then
    echo >&2
    log "unexpected HTTP $http_code from /scans/$scan_id"
    log "body: ${body:0:400}"
    exit 1
  fi

  auth_fail_count=0
  status="$(printf '%s' "$body" | jq -r '.status // empty')"
  # jq may emit the literal string "null" for a missing field without `// empty`.
  [[ "$status" == "null" ]] && status=""

  elapsed=$(( $(date +%s) - start_ts ))
  progress="$(printf '%s' "$body" | jq -r '.progress_pct // 0')"
  stage="$(printf '%s' "$body" | jq -r '.current_stage // ""')"
  printf '[%d:%02d] status=%-10s progress=%3s%% stage=%-40s\r' \
    $((elapsed/60)) $((elapsed%60)) "${status:-?}" "$progress" "${stage:0:40}" >&2

  case "$status" in
    done|failed) echo >&2; break ;;
    "") log ""; log "no status field in response — aborting"; exit 1 ;;
  esac
  sleep 5
done
duration=$(( $(date +%s) - start_ts ))

# Prefer the scan's own started_at/finished_at (survives --resume after
# the token has expired midway). Fall back to wall-clock if the API
# response doesn't carry timestamps.
if [[ -n "${body:-}" ]]; then
  api_duration=$(printf '%s' "$body" | python3 -c '
import json, sys, datetime as dt
try:
    s = json.load(sys.stdin)
    a = dt.datetime.fromisoformat(s["started_at"].replace("Z", "+00:00"))
    b = dt.datetime.fromisoformat(s["finished_at"].replace("Z", "+00:00"))
    print(int((b - a).total_seconds()))
except Exception:
    print("")
' 2>/dev/null || echo "")
  if [[ -n "$api_duration" && "$api_duration" != "0" ]]; then
    duration="$api_duration"
  fi
fi
log "scan $status in ${duration}s"

# ---- 4. Fetch findings ----------------------------------------------------
findings_json="$(curl -sS "${AUTH[@]}" "$API/findings?scan_id=$scan_id")"
echo "$findings_json" > "$OUT_RAW"

# Normalise → CSV
python3 "$HERE/../score/normalize_findings.py" \
  --scanner pencheff --target "$TARGET_NAME" \
  --format pencheff < "$OUT_RAW" >> "$OUT_CSV"

findings_count="$(jq 'length' <<<"$findings_json")"
verified_count="$(jq '[.[] | select(.verification_status=="true_positive" or .suppressed==false)] | length' <<<"$findings_json")"
log "findings: $findings_count total / $verified_count kept"
log "raw → $OUT_RAW"
log "csv → $OUT_CSV"

# ---- 5. Emit a one-line meta row for the orchestrator ---------------------
meta_csv="$RESULTS_DIR/_meta-$TODAY.csv"
[[ -f "$meta_csv" ]] || echo 'scanner,target,status,duration_s,findings_total,findings_kept' > "$meta_csv"
echo "pencheff,$TARGET_NAME,$status,$duration,$findings_count,$verified_count" >> "$meta_csv"
