#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Common helpers sourced by every runner script.
# shellcheck disable=SC2034   # vars are used by scripts that source this

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BENCH_ROOT="$(cd "$HERE/.." && pwd)"
RESULTS_DIR="$BENCH_ROOT/results"
mkdir -p "$RESULTS_DIR"

TODAY="$(date -u +%Y-%m-%d)"

log() {
  printf '[%s] %s\n' "$(date -u +%H:%M:%S)" "$*" >&2
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    log "missing required command: $1"
    exit 1
  }
}

# Expand a host-visible URL so a Docker-based scanner can reach it.
# Usage: docker_reachable_url "$TARGET_URL"
#   localhost:3001   →  host.docker.internal:3001
#   127.0.0.1:8888   →  host.docker.internal:8888
#   anything else    →  unchanged
docker_reachable_url() {
  local url="$1"
  case "$url" in
    *localhost*|*127.0.0.1*)
      echo "${url//localhost/host.docker.internal}" \
        | sed 's#127.0.0.1#host.docker.internal#'
      ;;
    *) echo "$url" ;;
  esac
}

# Build a results path like results/pencheff-juice-shop-2026-04-19.csv
result_path() {
  local scanner="$1"; local target="$2"; local ext="${3:-csv}"
  echo "$RESULTS_DIR/${scanner}-${target}-${TODAY}.${ext}"
}

# Minimal CSV header shared by every runner so the scorers can
# consume a single schema.
FINDINGS_CSV_HEADER='scanner,target,severity,cwe,title,url,confidence,verified'

# Append a finding row (escapes commas / quotes minimally).
append_finding() {
  local out="$1"; local scanner="$2"; local target="$3"
  local severity="$4"; local cwe="$5"; local title="$6"
  local url="$7"; local confidence="${8:-}"; local verified="${9:-false}"
  # Strip CR/LF and quotes from free-text fields.
  title="$(printf '%s' "$title" | tr -d '\r\n"' | tr ',' ' ')"
  url="$(printf '%s' "$url" | tr -d '\r\n"' | tr ',' ' ')"
  printf '%s,%s,%s,%s,%s,%s,%s,%s\n' \
    "$scanner" "$target" "$severity" "$cwe" "$title" "$url" "$confidence" "$verified" \
    >> "$out"
}

ensure_findings_file() {
  local path="$1"
  [[ -f "$path" ]] && return 0
  echo "$FINDINGS_CSV_HEADER" > "$path"
}
