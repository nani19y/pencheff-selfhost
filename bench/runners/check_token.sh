#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# Verify the PENCHEFF_API_TOKEN env var and print a clear error if it's
# missing / expired / points at the wrong instance. Useful to run
# before a long bench session so you find out inside 2 seconds rather
# than 5 minutes into a scan.
#
# Usage: ./check_token.sh   (exits 0 if valid, non-zero otherwise)

set -euo pipefail

API="${PENCHEFF_API_URL:-http://localhost:8000}"
TOKEN="${PENCHEFF_API_TOKEN:-}"

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
yellow(){ printf '\033[33m%s\033[0m\n' "$*"; }

if [[ -z "$TOKEN" ]]; then
  red "✗ PENCHEFF_API_TOKEN is not set."
  echo
  echo "Get one from the browser console (see bench/GETTING_TOKEN.md):"
  echo "  1. Sign in at $API replaced by http://localhost:3000"
  echo "  2. Open DevTools → Console and paste:"
  echo
  echo "     (async () => { const t = await window.Clerk.session.getToken();"
  echo "       console.log(t); await navigator.clipboard.writeText(t); })()"
  echo
  echo "  3. export PENCHEFF_API_TOKEN=\"<paste>\""
  exit 1
fi

# Basic JWT shape check (three base64url-ish segments separated by dots).
if [[ "$TOKEN" != *"."*"."* ]]; then
  red "✗ PENCHEFF_API_TOKEN doesn't look like a JWT (expected three dot-separated segments)."
  echo "  You probably copied something other than the token."
  exit 1
fi

# Probe the API.
code=$(curl -s -o /tmp/pencheff-probe.$$ -w "%{http_code}" \
  -H "Authorization: Bearer $TOKEN" \
  "$API/targets") || code="000"
body=$(cat /tmp/pencheff-probe.$$ 2>/dev/null || true)
rm -f /tmp/pencheff-probe.$$

case "$code" in
  200)
    count=$(printf '%s' "$body" | python3 -c 'import json,sys;print(len(json.load(sys.stdin)))' 2>/dev/null || echo '?')
    green "✓ token is valid — API reachable at $API"
    echo "  (${count} targets on file for this account)"
    ;;
  401)
    red "✗ API rejected the token (401)."
    echo "  Most likely expired (Clerk session tokens TTL = 60 s by default)."
    echo "  Re-copy from the browser console, or create a JWT Template in"
    echo "  the Clerk dashboard for a longer TTL — see bench/GETTING_TOKEN.md."
    exit 1
    ;;
  402)
    yellow "⚠ token is valid but your account is on the Free tier (scan quota blocked)."
    echo "  Upgrade to Pro in the Pencheff billing page before running the bench,"
    echo "  or sign in with a different account that's on Pro."
    exit 2
    ;;
  000)
    red "✗ could not reach $API — is the Pencheff API container running?"
    echo "  docker compose ps api    # check"
    echo "  docker compose up -d api # start"
    exit 1
    ;;
  *)
    red "✗ unexpected status $code from $API/targets"
    echo "  body: ${body:0:400}"
    exit 1
    ;;
esac
