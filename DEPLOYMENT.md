# Pencheff deployment guide

---

## Current architecture (updated 2026-06) — Cloudflare Pages + Docker API

### Architecture overview

The frontend is a **pure static export** (`next build` → `out/`) served by Cloudflare Pages. The FastAPI backend stays in Docker and is reachable publicly at `api.pencheff.com`. Browsers and the desktop app call the API directly over CORS — there is no Next.js reverse-proxy in front of it.

```
Browser / Desktop
  │
  ├─► pencheff.com   (Cloudflare Pages — pencheff-marketing project)
  ├─► app.pencheff.com  (Cloudflare Pages — pencheff-app project)
  └─► api.pencheff.com  (Docker: uvicorn, Cloudflare Proxied CNAME/Tunnel)
```

Both Pages projects serve **the same static build** of `apps/web`. Subdomain routing (which URLs belong on which host) is enforced by Cloudflare zone-level Redirect Rules (see below), not by Next.js middleware.

### DNS

| Type    | Name               | Content                             | Proxy      | SSL           |
| ------- | ------------------ | ----------------------------------- | ---------- | ------------- |
| `CNAME` | `@` (pencheff.com) | Cloudflare Pages apex               | ✅ Proxied | Full (strict) |
| `CNAME` | `app`              | Cloudflare Pages                    | ✅ Proxied | Full (strict) |
| `CNAME` | `api`              | Docker host CNAME / Tunnel hostname | ✅ Proxied | Full (strict) |

`api.pencheff.com` must point at the host running Docker (either a CNAME to the public hostname, or a Cloudflare Tunnel). Keep it **Proxied** so Cloudflare terminates TLS.

### Two Cloudflare Pages projects

Both projects build from the same repo root with the same settings:

| Setting          | Value                       |
| ---------------- | --------------------------- |
| Root directory   | `apps/web`                  |
| Build command    | `npm run build`             |
| Output directory | `out` (i.e. `apps/web/out`) |
| Node version     | 20                          |

**Required environment variables (both projects):**

| Variable                            | Value                       |
| ----------------------------------- | --------------------------- |
| `NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY` | production `pk_live_…` key  |
| `NEXT_PUBLIC_API_URL`               | `https://api.pencheff.com`  |
| `NEXT_PUBLIC_LANDING_URL`           | `https://pencheff.com`      |
| `NEXT_PUBLIC_APP_URL`               | `https://app.pencheff.com`  |
| `NEXT_PUBLIC_DOCS_URL`              | `https://docs.pencheff.com` |

`CLERK_SECRET_KEY` is **no longer needed by the frontend** — middleware was removed as part of the static-export migration. Remove it from both Pages project env configs. It remains in the Docker API's env.

### Cloudflare zone Redirect Rules (replace the deleted middleware `subdomainRouter`)

These are **zone-level** rules (Cloudflare dashboard → Rules → Redirect Rules), not per-project `_redirects`. A per-project `_redirects` cannot be host-conditional, and both projects ship the same file.

**Rule 1 — on `pencheff.com`, send app paths to `app.pencheff.com`:**

When: `http.host eq "pencheff.com"` AND URI path matches one of:
`/dashboard*`, `/targets*`, `/scans*`, `/findings*`, `/billing*`, `/schedules*`, `/assets*`, `/integrations*`, `/sbom*`, `/dependencies*`, `/repos*`, `/settings*`, `/compliance*`, `/search*`, `/observability*`, `/advisories*`, `/engagements*`, `/onboarding*`, `/org*`, `/workspaces*`

Then: redirect (302) to `https://app.pencheff.com${http.request.uri.path}`

**Rule 2 — on `app.pencheff.com`, redirect `/` to `/dashboard`:**

When: `http.host eq "app.pencheff.com"` AND URI path eq `/`

Then: redirect (302) to `https://app.pencheff.com/dashboard`

**Rule 3 — on `app.pencheff.com`, send marketing paths back to `pencheff.com`:**

When: `http.host eq "app.pencheff.com"` AND URI path matches `/pricing*`, `/company/*`, `/solutions/*`, `/support/*`, `/blog*`, `/terms*`, `/privacy*`
(Exclude `/login`, `/signup` — those render on both hosts.)

Then: redirect (302) to `https://pencheff.com${http.request.uri.path}`

### Backend CORS

The API's production `.env` (or the `docker-compose.yml` `ALLOWED_ORIGINS` override) must list both frontend origins:

```
ALLOWED_ORIGINS=["https://pencheff.com","https://app.pencheff.com"]
```

This is already present in `apps/api/.env.example`.

### Exposing `api.pencheff.com`

The Docker `api` service (port 8000) must be reachable from the internet. Two options:

- **Cloudflare Tunnel:** run `cloudflared tunnel` on the VM, map `api.pencheff.com` → `http://localhost:8000`. No public inbound ports needed.
- **Direct proxy:** nginx/Caddy on the VM listens on 443, proxies to `localhost:8000`; set DNS `api` CNAME/A to the VM's public IP (Proxied).

### Local development

The `web` service has been removed from `docker-compose.yml`. For local frontend dev:

```bash
cd apps/web
npm run dev
# → http://localhost:3000 (hot-reload, talks to localhost:8000)
```

Backend services (api, worker, postgres, redis) still run via `docker compose up -d`.

---

> **SUPERSEDED (pre-2026-06):** The sections below describe the previous architecture where `apps/web` ran inside Docker with Next.js middleware doing subdomain routing, and the API was proxied through `/api/*` Next.js rewrites. That approach required `CLERK_SECRET_KEY` in the frontend and a `web:` service in `docker-compose.yml`. Both have been replaced by the Cloudflare Pages static-export setup above.

---

Pencheff is a multi-app product split across three origins:

| Origin              | App                     | What it hosts                                                                                                                              |
| ------------------- | ----------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| `pencheff.com`      | `apps/web`              | Marketing landing + `/login` + `/signup` + pricing                                                                                         |
| `app.pencheff.com`  | `apps/web` (same build) | Authenticated dashboard (`/dashboard`, `/targets`, `/scans`, `/schedules`, `/assets`, `/integrations`, `/sbom`, `/dependencies`, `/repos`) |
| `docs.pencheff.com` | `apps/docs`             | Nextra-backed documentation                                                                                                                |

The landing and app subdomains are **the same Next.js build** — subdomain-aware middleware at `apps/web/middleware.ts` redirects marketing paths to the landing origin and app paths to the app origin. This keeps a single codebase, a single Clerk session, and avoids duplicating layouts.

The docs site is a separate app (`apps/docs`) that can be deployed on a different hosting tier (e.g. Cloudflare Pages with SSR disabled for a static build).

---

## Architecture

```
                                          ┌───────────────────────────┐
   Internet (Cloudflare DNS + proxy) ───► │  pencheff.com             │
                                          │  (A/AAAA → apps/web)      │
                                          │                           │
                                          │  ├─ /               → marketing
                                          │  ├─ /login          → marketing
                                          │  ├─ /signup         → marketing
                                          │  └─ (anything else) → 302 to app
                                          └───────────────────────────┘

                                          ┌───────────────────────────┐
   Internet ─────────────────────────────► │  app.pencheff.com         │
                                          │  (A/AAAA → apps/web)      │
                                          │                           │
                                          │  ├─ /               → 302 /dashboard
                                          │  ├─ /dashboard      → dashboard
                                          │  └─ /login /signup  → Clerk (session scoped to .pencheff.com)
                                          └───────────────────────────┘

                                          ┌───────────────────────────┐
   Internet ─────────────────────────────► │  docs.pencheff.com        │
                                          │  (A/AAAA → apps/docs)     │
                                          │                           │
                                          │  Static MDX on any CDN    │
                                          └───────────────────────────┘
```

API (`apps/api`, FastAPI) lives behind `app.pencheff.com/api/*` via a Next.js rewrite — no public API subdomain needed.

---

## Cloudflare DNS setup

You already own `pencheff.com` at Cloudflare. Add three records:

| Type | Name               | Content              | Proxy      | TTL  |
| ---- | ------------------ | -------------------- | ---------- | ---- |
| `A`  | `@` (pencheff.com) | <web-host-IPv4>      | ✅ Proxied | Auto |
| `A`  | `app`              | <same web-host-IPv4> | ✅ Proxied | Auto |
| `A`  | `docs`             | <docs-host-IPv4>     | ✅ Proxied | Auto |

Or `CNAME` records if you're fronting with a platform that issues hostnames (Vercel, Fly.io, Railway, Cloudflare Pages):

| Type    | Name       | Content                                                                     |
| ------- | ---------- | --------------------------------------------------------------------------- |
| `CNAME` | `@` (apex) | `your-web-app.vercel.app` (Cloudflare supports `CNAME` flattening for apex) |
| `CNAME` | `app`      | `your-web-app.vercel.app`                                                   |
| `CNAME` | `docs`     | `your-docs-app.pages.dev`                                                   |

### SSL / TLS mode

In **SSL/TLS → Overview**, set **Full (strict)**. Cloudflare will terminate TLS on your behalf and present a pencheff.com cert at the edge; make sure your origin also serves a valid cert (platforms like Vercel / Fly / Railway handle this automatically).

### HSTS

Enable **Edge Certificates → HSTS** with `max-age ≥ 31536000`, `includeSubDomains`, and `preload`. Pencheff already sets the app-level HSTS header too, but Cloudflare edge coverage protects your marketing site as well.

---

## Choosing a host

Any of these work. Pick whichever matches your team's current stack — the Next.js builds are standard.

### Option A — Cloudflare Pages (recommended for docs)

Good fit for `docs.pencheff.com` since it's static-friendly. In `apps/docs/next.config.mjs` uncomment:

```js
output: 'export',
trailingSlash: true,
```

then:

```
cd apps/docs
npm install
npm run build
wrangler pages deploy out --project-name pencheff-docs
```

Add the `docs.pencheff.com` custom domain in Pages project settings.

For the app, Cloudflare Pages works too but requires `@cloudflare/next-on-pages` for SSR — feasible but more moving parts than Vercel or a VM.

### Option B — Vercel (recommended for web + app)

One project per app:

```bash
vercel link     # apps/web
vercel env add NEXT_PUBLIC_LANDING_URL=https://pencheff.com
vercel env add NEXT_PUBLIC_APP_URL=https://app.pencheff.com
vercel env add NEXT_PUBLIC_DOCS_URL=https://docs.pencheff.com
# … Clerk + API URL env vars
vercel --prod
```

In Vercel → Project Settings → Domains, add both `pencheff.com` and `app.pencheff.com` to the **same** project. Vercel serves identical output on both; the middleware does the routing.

### Option C — self-hosted Docker (VM + Cloudflare Tunnel)

Run `docker compose up -d` on a Linux VM. Expose ports `3000` (web) and `3001` (docs) via a Cloudflare Tunnel (`cloudflared tunnel`), then map hostnames:

```yaml
# ~/.cloudflared/config.yml
ingress:
  - hostname: pencheff.com
    service: http://localhost:3000
  - hostname: app.pencheff.com
    service: http://localhost:3000
  - hostname: docs.pencheff.com
    service: http://localhost:3001
  - service: http_status:404
```

`cloudflared tunnel run` and that's it — no public ports, TLS at the edge.

---

## Clerk cross-subdomain cookies

Pencheff relies on the **same Clerk session** across the apex (`pencheff.com`) and the app subdomain (`app.pencheff.com`). This requires a Clerk **Production instance** (not the `clerk.accounts.dev` dev instance).

In the Clerk dashboard:

1. **Instances → Create Production Instance**.
2. **Domains → Apex domain:** `pencheff.com` (Clerk scopes session cookies to `.pencheff.com`).
3. **Domains → Add subdomain:** `app.pencheff.com`.
4. Copy the production publishable key and secret into `.env`:
   ```
   NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY=pk_live_…
   CLERK_SECRET_KEY=sk_live_…
   ```
5. Redeploy the web app.

After login on `pencheff.com/login`, Clerk redirects to `app.pencheff.com/dashboard` (controlled by `afterSignInUrl` in `apps/web/app/layout.tsx`). The `__session` cookie is scoped to `.pencheff.com` so the app subdomain reads it seamlessly.

---

## Local development

Three ways to work locally:

### 1. Single origin (default, simplest)

```
docker compose up -d
# → web:  http://localhost:3000
# → docs: http://localhost:3001
# → api:  http://localhost:8000
```

All marketing + app routes live on `localhost:3000`. The middleware skips subdomain routing when it sees a local host. Clerk dev instance handles auth.

### 2. Multi-subdomain via \*.localhost

Modern browsers route `*.localhost` to `127.0.0.1` without any `/etc/hosts` edits. Use them to exercise the production subdomain split locally:

```bash
cp .env.example .env
cat >>.env <<'ENV'
NEXT_PUBLIC_LANDING_URL=http://localhost:3000
NEXT_PUBLIC_APP_URL=http://app.localhost:3000
NEXT_PUBLIC_DOCS_URL=http://docs.localhost:3001
NEXT_PUBLIC_APP_HOST_LOCAL=app.localhost:3000
NEXT_PUBLIC_DOCS_HOST_LOCAL=docs.localhost:3000
ENV

docker compose up -d --build
```

Then browse:

- `http://localhost:3000` → marketing
- `http://app.localhost:3000` → dashboard (requires Clerk dev session)
- `http://docs.localhost:3001` → docs (served by `apps/docs`)

Safari does **not** route `*.localhost` by default — use `/etc/hosts` entries instead:

```
# /etc/hosts
127.0.0.1 localhost
127.0.0.1 app.localhost
127.0.0.1 docs.localhost
```

### 3. Running only the docs app

```bash
cd apps/docs
npm install
npm run dev
# → http://localhost:3001
```

---

## Health checks

After deploying, verify:

```bash
# Apex → marketing 200
curl -I https://pencheff.com

# Apex → app path 302 to app.pencheff.com
curl -I https://pencheff.com/dashboard

# App host → /dashboard 200 (after login)
curl -I https://app.pencheff.com/dashboard

# App host → / 302 /dashboard
curl -I https://app.pencheff.com

# Docs 200
curl -I https://docs.pencheff.com
```

---

## Backups & ops

- **Postgres** — your API's database. Snapshot nightly; include point-in-time recovery if you're on a managed service (Supabase / RDS / Neon).
- **CVE feed cache** (`~/.pencheff/cve_cache.db`) — regenerates from upstream on `refresh_cve_feed`, but cache it between deploys to keep SCA fast.
- **Reports volume** (`reports:` in compose) — rotate after 90 days or ship to object storage (S3 / R2).

---

## Observability

Recommended:

- **Sentry** on both web apps — `SENTRY_DSN` in `.env`.
- **Cloudflare Analytics** (free) for edge traffic.
- **Grafana / Prometheus** scraping Celery + Postgres.
- **Structured logs** — FastAPI logs JSON to stdout; pipe to Loki / Datadog / New Relic.

---

## GitHub App (repo scanning)

Pencheff's `/repos` feature is powered by a **GitHub App** you own. Create one
at <https://github.com/settings/apps/new> (or in an organisation's settings)
with:

- **Homepage URL:** `https://app.pencheff.com/repos`
- **Callback URL:** `https://app.pencheff.com/api/repos/callback` (add
  `http://localhost:8000/repos/callback` for local dev too)
- **Webhook URL:** `https://app.pencheff.com/api/webhooks/github`
- **Webhook secret:** any high-entropy string — stash it in
  `GITHUB_APP_WEBHOOK_SECRET`
- **Repository permissions**
  - Contents: _read+write_
  - Metadata: _read_
  - Pull requests: _read+write_
  - Dependabot alerts: _read_
  - Security events: _read_
  - Actions: _read_
- **Subscribe to events:** `installation`, `installation_repositories`,
  `push`, `dependabot_alert`
- **Where can this GitHub App be installed?** any account

After creation, generate a private key and paste the numeric app ID, the
URL slug, the private-key PEM, and the webhook secret into your `.env`:

```
GITHUB_APP_ID=123456
GITHUB_APP_SLUG=pencheff
GITHUB_APP_WEBHOOK_SECRET=<random>
GITHUB_APP_PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----\n...\n-----END RSA PRIVATE KEY-----"
```

The PEM may be pasted with literal `\n` escapes; the server normalises both
forms before signing the JWT.

---

## Security reminders

- Rotate `FERNET_KEY` every 90 days (re-encrypt credentials blob with the new key; the API tolerates a grace-period key).
- `CLERK_SECRET_KEY` never leaves the backend; never inline it into `NEXT_PUBLIC_*` env vars.
- Strict CSP is set in `apps/web/app/layout.tsx` — update if you add third-party scripts.
- Cloudflare WAF rules: enable managed rule groups **OWASP Core** and **Cloudflare Managed** on all three hostnames.
