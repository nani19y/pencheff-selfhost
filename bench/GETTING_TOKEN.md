# Getting a `PENCHEFF_API_TOKEN`

The bench runners authenticate against Pencheff's API the same way a
logged-in browser does — by sending a **Clerk session JWT** in the
`Authorization: Bearer …` header. This document walks through every
way to obtain one.

> **TL;DR**: sign in at http://localhost:3000, open DevTools, paste
> `await window.Clerk.session.getToken()` into the console, copy the
> returned string, export it as `PENCHEFF_API_TOKEN`.

---

## Prerequisites

1. Pencheff is running locally (`docker compose up -d`).
2. You can sign in at `http://localhost:3000/login` with your Clerk
   account (the Google sign-in button or your email/password).
3. The account you sign in with is on the **Pro** tier (so the bench
   scan doesn't hit the free tier's 1-scan/month quota).

---

## Method 1 — Browser console (fastest, ~15 s)

1. Open http://localhost:3000 in Chrome / Firefox / Safari and sign in.
2. Once you're on the dashboard, open DevTools:
   - Chrome / Edge: `⌘⌥I` (macOS) or `Ctrl+Shift+I` (Windows / Linux)
   - Safari: enable Develop menu → `⌘⌥I`
3. Go to the **Console** tab.
4. Paste this one-liner and press Enter:

   ```js
   (async () => { const t = await window.Clerk.session.getToken(); console.log(t); await navigator.clipboard.writeText(t); console.log("copied to clipboard"); })()
   ```

   The console prints the JWT and also copies it to your clipboard.
5. Export it in the shell where you'll run the bench:

   ```bash
   export PENCHEFF_API_TOKEN='eyJhbGciOiJSUzI1NiIs…'   # paste here
   export PENCHEFF_API_URL=http://localhost:8000
   ```

That's it. `./run_all.sh juice-shop` will now work.

### Verify it works

```bash
curl -H "Authorization: Bearer $PENCHEFF_API_TOKEN" \
     http://localhost:8000/targets | jq '.[0:3]'
```

If you get back a JSON array (possibly empty) the token is valid. A
`401 {"detail":"invalid or expired token"}` means either the token has
aged out (see the expiry section below) or you copied something other
than the JWT.

---

## Method 2 — Inspect a network request (no console access)

Useful when the `window.Clerk` object isn't exposed (stricter CSP
setups, weird browser extensions) or you just prefer reading
headers.

1. Sign in at http://localhost:3000.
2. Open DevTools → **Network** tab.
3. Navigate around the app (e.g. click Dashboard). Watch the requests
   to `http://localhost:8000/*`.
4. Click any one of them (e.g. `GET /targets`).
5. In **Headers → Request Headers**, find `Authorization: Bearer
   eyJ…`. Copy the part after `Bearer`.
6. Export it:

   ```bash
   export PENCHEFF_API_TOKEN='eyJ…'
   ```

---

## The expiry problem (read this before a long run)

Clerk's default session token TTL is **60 seconds**. Between the moment
you copy it and the moment the bench finishes, the token will almost
certainly expire — which is fine for a one-scan test, but a full
`./run_all.sh all` run can take 45 minutes.

You have two good options.

### Option A — refresh helper

Re-run the paste every time you kick off a new scanner:

```bash
# In the browser console, after sign-in:
await window.Clerk.session.getToken()
# …then in the terminal:
export PENCHEFF_API_TOKEN='<paste>'
./runners/pencheff.sh http://host.docker.internal:3001 juice-shop
```

Tedious but it works.

### Option B — Clerk JWT Template with longer TTL (recommended)

Clerk lets you define a custom JWT template with a longer lifetime
(up to the session's duration — hours).

1. Go to https://dashboard.clerk.com → your Pencheff instance.
2. **Configure → JWT Templates → + New template**.
3. Name it `pencheff-bench` and set:
   - **Token lifetime**: `3600` seconds (1 hour), or up to the
     session lifetime.
   - **Claims**: leave the defaults. The Pencheff backend only cares
     about `sub` (user id) and `pla` (plan), both of which the
     default template already includes.
4. Save.
5. Back in the browser console:

   ```js
   (async () => { const t = await window.Clerk.session.getToken({ template: "pencheff-bench" }); console.log(t); await navigator.clipboard.writeText(t); })()
   ```

6. Export that token — it will stay valid for the full hour.

The Pencheff backend already treats any valid Clerk-issued RS256 JWT
as good, regardless of template, so you don't have to change
server-side code.

---

## Method 3 — Programmatic mint (for CI / cron)

If you want to run the bench in CI without a browser at all, use
Clerk's Backend API to mint a "sign-in token" for a dedicated service
user, then exchange it for a session.

This is more involved and **requires a service account** (an extra
Pencheff user with Pro plan, whose credentials you keep only in your
CI secret store).

```bash
# 1. Mint a one-shot sign-in token for the service user
SIGNIN_TOKEN=$(curl -sS -X POST \
  https://api.clerk.com/v1/sign_in_tokens \
  -H "Authorization: Bearer $CLERK_SECRET_KEY" \
  -H "Content-Type: application/json" \
  -d "{\"user_id\":\"$CLERK_SERVICE_USER_ID\", \"expires_in_seconds\":600}" \
  | jq -r '.token')

# 2. Exchange it for a session token via Clerk's FAPI
SESSION_JSON=$(curl -sS -X POST \
  "https://${CLERK_FRONTEND_API_HOST}/v1/client/sign_ins?__clerk_api_version=2024-10-01" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "strategy=ticket&ticket=${SIGNIN_TOKEN}")

# 3. `current_session_id` is inside the response; fetch a fresh JWT
#    from /v1/client/sessions/<sid>/tokens
# …full recipe in Clerk's "Sign-in tokens" docs.
```

Honestly, for a hobby bench this is overkill. If you're running the
bench more often than once a week, ping me and I'll add a proper
API-key auth path to Pencheff (a small table + a `pencheff-api-key`
header on top of the current Clerk check).

---

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `401 invalid or expired token` after a few minutes | Token TTL reached. Re-copy with Method 1, or use the JWT template from Option B for a longer TTL. |
| `401 invalid or expired token` immediately after paste | You probably copied something other than the JWT. It should start with `eyJ` and have exactly two dots. Run the console one-liner again; don't copy from any tab that re-renders. |
| `402 scan limit 1/month reached for plan 'free'` | The Clerk account you signed in with isn't on the Pro plan. Upgrade it in the Pencheff billing page (which uses Clerk's pricing table), or sign in with a different account that is. |
| `window.Clerk is undefined` | You're on a page that isn't wrapped in `ClerkProvider` (usually because you're at `/` before signing in). Sign in first, navigate to `/dashboard`, then retry. |
| `CORS error` when calling `localhost:8000` from the browser console | `http://localhost:3000` is on the `ALLOWED_ORIGINS` list. The console request doesn't need CORS — it's just for show. Use `curl` from the terminal for the verification step. |

---

## Helper script

A tiny bash wrapper that reads the token from a file and re-loads it
when it expires:

```bash
cat > ~/bin/pencheff-token <<'SH'
#!/usr/bin/env bash
# Usage: eval "$(pencheff-token)"
TOKEN_FILE="${PENCHEFF_TOKEN_FILE:-$HOME/.pencheff-token}"
if [[ ! -f "$TOKEN_FILE" ]]; then
  echo "echo 'paste your Clerk JWT into $TOKEN_FILE first' >&2; return 1"
  exit 1
fi
TOKEN="$(<"$TOKEN_FILE")"
# sanity check: must be a JWT
if [[ "$TOKEN" != *"."*"."* ]]; then
  echo "echo '$TOKEN_FILE does not contain a JWT' >&2; return 1"
  exit 1
fi
echo "export PENCHEFF_API_TOKEN='$TOKEN'"
echo "export PENCHEFF_API_URL='${PENCHEFF_API_URL:-http://localhost:8000}'"
SH
chmod +x ~/bin/pencheff-token
```

Paste the token into `~/.pencheff-token` each time you start a bench
session, then:

```bash
eval "$(pencheff-token)"
cd bench && ./run_all.sh juice-shop
```
