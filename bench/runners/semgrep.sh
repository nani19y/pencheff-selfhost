#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# Semgrep OSS runner — primary SAST engine after the CodeQL removal.
#
# Usage: semgrep.sh <repo_path> <output_json_path>
#
# Requires `semgrep` on PATH. Runs against an explicit allowlist of OSS
# Semgrep Registry packs — never `--config=auto` — so the rule corpus
# is fully license-clean (no Semgrep Pro rules pulled).
#
# Override the pack list with the env var PENCHEFF_SEMGREP_PACKS
# (comma-separated). Defaults to a conservative OWASP / CWE-Top-25 set.

set -euo pipefail

TARGET_PATH="${1:?path required}"
OUT_JSON="${2:?output json path required}"

write_empty_json() {
  mkdir -p "$(dirname "$OUT_JSON")"
  printf '{"results":[],"errors":[]}\n' > "$OUT_JSON"
}

if ! command -v semgrep >/dev/null 2>&1; then
  echo "semgrep not installed; see https://semgrep.dev/docs/getting-started/" >&2
  write_empty_json
  exit 0
fi

# Permissively-licensed Semgrep Registry packs only. None of these are
# Semgrep Pro packs. See semgrep.dev/p for the catalogue.
DEFAULT_PACKS="p/owasp-top-ten,p/security-audit,p/cwe-top-25,p/secrets,p/jwt,p/django,p/flask,p/express,p/nodejs,p/golang,p/r2c-security-audit"
PACKS="${PENCHEFF_SEMGREP_PACKS:-$DEFAULT_PACKS}"

# Build the --config args once per pack so a single typo in PENCHEFF_SEMGREP_PACKS
# fails one rule load instead of the whole run.
CONFIG_ARGS=()
IFS=',' read -ra PACK_ARRAY <<< "$PACKS"
for pack in "${PACK_ARRAY[@]}"; do
  trimmed="${pack//[[:space:]]/}"
  [[ -z "$trimmed" ]] && continue
  CONFIG_ARGS+=(--config "$trimmed")
done

if [[ ${#CONFIG_ARGS[@]} -eq 0 ]]; then
  echo "semgrep: no packs configured; emitting empty result." >&2
  write_empty_json
  exit 0
fi

# --error 0 means "exit 0 even when findings present" — caller parses the JSON.
# --timeout 30s caps per-rule runtime so a pathological rule can't hang the scan.
if ! semgrep \
      "${CONFIG_ARGS[@]}" \
      --json \
      --quiet \
      --timeout 30 \
      --metrics off \
      --output "$OUT_JSON" \
      "$TARGET_PATH" 2>&1 | tail -200 >&2; then
  echo "semgrep: scan exited non-zero; preserving any partial output." >&2
fi

# Sanity-check — semgrep can exit 0 but leave the output empty when
# every pack failed to load (offline registry, network blocked).
if [[ ! -s "$OUT_JSON" ]]; then
  write_empty_json
fi
