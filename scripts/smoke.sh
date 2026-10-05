#!/usr/bin/env bash
# scripts/smoke.sh — verify the CE boots with no auth and serves the app.
set -euo pipefail
cd "$(dirname "$0")/.."

docker compose up -d --build
echo "waiting for API health..."
for i in $(seq 1 60); do
  if curl -sf http://localhost:8000/targets >/dev/null; then break; fi
  sleep 3
done

code_targets=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8000/targets)
code_dash=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:3000/dashboard)

echo "GET /targets (no token) -> $code_targets"
echo "GET /dashboard         -> $code_dash"
[ "$code_targets" = "200" ] || { echo "FAIL: targets not 200"; exit 1; }
[ "$code_dash" = "200" ] || { echo "FAIL: dashboard not 200"; exit 1; }
echo "SMOKE OK"
