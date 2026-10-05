#!/usr/bin/env bash
# Deploy the static frontend to the two Cloudflare Pages projects.
#
# Builds apps/web once, then deploys the SAME build to both projects with
# project-specific `_redirects` that implement subdomain routing (which a single
# shared _redirects can't do, and which we do here instead of zone Redirect Rules
# so deploys are self-contained and need only the Cloudflare Pages token scope).
#
#   - pencheff-marketing  → pencheff.com      (app paths 302 → app.pencheff.com)
#   - pencheff-app        → app.pencheff.com  (/ → /dashboard; marketing 302 → apex)
#
# Both also ship the base public/_redirects (dynamic-route shell rewrites +
# stub/canonical redirects).
#
# Required env:
#   NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY   pk_live_… (baked into the build)
#   CLOUDFLARE_API_TOKEN                token with Cloudflare Pages: Edit
#   CLOUDFLARE_ACCOUNT_ID
# Run from apps/web:  ./deploy.sh
set -euo pipefail
cd "$(dirname "$0")"

: "${NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY:?set NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY (pk_live_…)}"
: "${CLOUDFLARE_API_TOKEN:?set CLOUDFLARE_API_TOKEN}"
: "${CLOUDFLARE_ACCOUNT_ID:?set CLOUDFLARE_ACCOUNT_ID}"

export NEXT_PUBLIC_API_URL="${NEXT_PUBLIC_API_URL:-https://api.pencheff.com}"
export NEXT_PUBLIC_LANDING_URL="${NEXT_PUBLIC_LANDING_URL:-https://pencheff.com}"
export NEXT_PUBLIC_APP_URL="${NEXT_PUBLIC_APP_URL:-https://app.pencheff.com}"
export NEXT_PUBLIC_DOCS_URL="${NEXT_PUBLIC_DOCS_URL:-https://docs.pencheff.com}"

APP_PATHS=(dashboard targets scans findings billing schedules assets integrations \
  sbom dependencies repos settings compliance search observability advisories \
  engagements onboarding org workspaces invite)
MKT_PREFIXES=(pricing company solutions support platform resources capabilities ai-security)

echo "▶ building static export…"
npx next build >/dev/null
test -d out || { echo "build produced no out/"; exit 1; }

BASE=$(mktemp); cp out/_redirects "$BASE"
restore() { cp "$BASE" out/_redirects; rm -f "$BASE"; }
trap restore EXIT

# --- marketing project: app paths → app subdomain (prepended; first match wins) ---
{
  echo "# --- subdomain routing (pencheff.com → app) ---"
  for p in "${APP_PATHS[@]}"; do
    printf '/%s        https://app.pencheff.com/%s         302\n' "$p" "$p"
    printf '/%s/*      https://app.pencheff.com/%s/:splat  302\n' "$p" "$p"
  done
  cat "$BASE"
} > out/_redirects
echo "▶ deploying pencheff-marketing…"
npx wrangler pages deploy out --project-name=pencheff-marketing --branch=main --commit-dirty=true

# --- app project: / → /dashboard, marketing paths → apex ---
{
  echo "# --- subdomain routing (app.pencheff.com) ---"
  echo "/                /dashboard                          302"
  for p in "${MKT_PREFIXES[@]}"; do
    printf '/%s        https://pencheff.com/%s              302\n' "$p" "$p"
    printf '/%s/*      https://pencheff.com/%s/:splat       302\n' "$p" "$p"
  done
  cat "$BASE"
} > out/_redirects
echo "▶ deploying pencheff-app…"
npx wrangler pages deploy out --project-name=pencheff-app --branch=main --commit-dirty=true

echo "✓ deployed both projects."
