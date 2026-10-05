#!/usr/bin/env bash
#
# Orchestrator: boot the benchmark targets, run each scanner against a
# chosen target, then invoke the scorer. Produces a dated summary CSV
# under results/.
#
# Usage:
#   ./run_all.sh juice-shop          # Juice Shop only
#   ./run_all.sh owasp-benchmark     # OWASP Benchmark only
#   ./run_all.sh wavsep              # WAVSEP only
#   ./run_all.sh all                 # every target (slowest)
#
# Env:
#   SCANNERS   comma-separated runner names (default: pencheff,zap)
#   SKIP_BOOT  set to any value to skip `docker compose up`
#   PENCHEFF_API_TOKEN / PENCHEFF_API_URL — see runners/pencheff.sh

set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

TARGET="${1:-all}"
SCANNERS="${SCANNERS:-pencheff,zap}"

# Fail fast if Pencheff is in the scanner list but the token is missing
# or expired — better to find out now than 20 minutes into a scan.
if [[ ",$SCANNERS," == *,pencheff,* ]]; then
  "$HERE/runners/check_token.sh" || {
    echo "Run ./runners/check_token.sh after exporting PENCHEFF_API_TOKEN." >&2
    echo "Token instructions: $HERE/GETTING_TOKEN.md" >&2
    exit 1
  }
fi

log() { printf '[%s] %s\n' "$(date -u +%H:%M:%S)" "$*" >&2; }

boot_targets() {
  [[ -n "${SKIP_BOOT:-}" ]] && { log "SKIP_BOOT set — assuming targets are up"; return; }
  log "booting targets via docker compose"
  docker compose -f docker-compose.targets.yml up -d
}

wait_for_url() {
  local url="$1"; local name="$2"; local max="${3:-60}"
  for _ in $(seq 1 "$max"); do
    if curl -kfsS "$url" >/dev/null 2>&1; then
      log "$name is up → $url"
      return 0
    fi
    sleep 2
  done
  log "$name did not respond at $url within ${max}× 2 s — aborting"
  return 1
}

run_scanners_against() {
  local target_url="$1"; local target_name="$2"
  local IFS=','
  for scanner in $SCANNERS; do
    local runner="$HERE/runners/${scanner}.sh"
    if [[ ! -x "$runner" ]]; then
      log "skipping $scanner — no runner script at $runner"
      continue
    fi
    log "=== $scanner vs $target_name ==="
    "$runner" "$target_url" "$target_name" || log "$scanner exited non-zero (continuing)"
  done
}

target_juice_shop() {
  boot_targets
  wait_for_url "http://localhost:3001/" juice-shop 60 || exit 1

  # For scanners running inside Docker the host must be resolvable from
  # inside the container network.
  local url_for_scanners="http://host.docker.internal:3001"
  run_scanners_against "$url_for_scanners" juice-shop

  log "scoring Juice Shop"
  python3 score/juice_shop_score.py --read-only
}

target_owasp_benchmark() {
  if ! curl -kfsS https://localhost:8443/benchmark/ >/dev/null 2>&1; then
    log "OWASP Benchmark is not up — run targets/owasp-benchmark/setup.sh first"
    return 1
  fi
  run_scanners_against "https://host.docker.internal:8443/benchmark/" owasp-benchmark
  log "scoring OWASP Benchmark"
  python3 score/owasp_benchmark_score.py
}

target_wavsep() {
  local url="${TARGET_URL_WAVSEP:-http://localhost:8888/wavsep/}"
  if ! curl -fsS "$url" >/dev/null 2>&1; then
    cat >&2 <<EOF
WAVSEP is not running at $url.

WAVSEP is NOT booted by docker-compose.targets.yml because there is no
actively-maintained public image. Stand it up yourself and re-run:

  # See bench/targets/wavsep/README.md for three options
  TARGET_URL_WAVSEP=http://your-host:8888/wavsep/ ./run_all.sh wavsep

Skipping WAVSEP.
EOF
    return 0
  fi
  local docker_url
  docker_url="$(echo "$url" | sed 's#localhost#host.docker.internal#; s#127.0.0.1#host.docker.internal#')"
  run_scanners_against "$docker_url" wavsep
  log "WAVSEP scoring is not yet implemented — see targets/wavsep/README.md"
}

case "$TARGET" in
  juice-shop)       target_juice_shop ;;
  owasp-benchmark)  target_owasp_benchmark ;;
  wavsep)           target_wavsep ;;
  all)
    target_juice_shop
    target_wavsep
    target_owasp_benchmark || true
    ;;
  *)
    echo "unknown target: $TARGET (choose: juice-shop, owasp-benchmark, wavsep, all)" >&2
    exit 2
    ;;
esac

log "done — see $HERE/results/"
