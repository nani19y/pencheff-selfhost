# Static-SPA Frontend on Cloudflare + Dockerized API

**Date:** 2026-05-31
**Status:** Spike-validated; implementation plan pending
**Branch:** frontend-cdn

## Goal

Separate the frontend from the backend. Convert `apps/web` (Next.js 15 App
Router) into a **pure static export** (`output: 'export'`) hosted on Cloudflare
Pages. The FastAPI backend (`apps/api`) stays in its Docker image and is exposed
at a new public origin, `api.pencheff.com`. The browser and the desktop app call
the API directly over CORS.

## Why this is viable (spike-confirmed)

The frontend's data layer is already 100% client-side, and a throwaway spike ran
a real `next build` with `output: 'export'` to prove the foundation:

- `lib/api.ts` is `"use client"`; it calls the backend with a Clerk JWT bearer
  token, either via the `/api/*` rewrite proxy or directly over CORS
  (`NEXT_PUBLIC_API_DIRECT_URL`, already supported by the backend's
  `ALLOWED_ORIGINS`).
- **Zero** server components fetch backend data or use `cookies()`/`headers()`
  at request/build time (grep over every non-`"use client"` file in `app/`).
- **Spike result:** with `output: 'export'`, no `middleware.ts`, a hash-routed
  `<SignIn>`, and a path-reading detail page, the build **compiled and
  type-checked successfully**.
- **CORRECTION (found during execution, Task 2):** `@clerk/nextjs` v7's
  `<ClerkProvider>` is NOT statically exportable — it unconditionally references
  a server action (`invalidateCacheAction`), which `output: 'export'` rejects
  ("Server Actions are not supported with static export"). The spike _also_ hit
  this but it was misattributed; in Task 1 it was masked by an earlier build
  error. **Fix:** migrate the 11 files importing `@clerk/nextjs` to the
  framework-agnostic `@clerk/clerk-react` SDK (identical hook/component APIs:
  `useAuth`, `useUser`, `useClerk`, `UserButton`, `SignIn`, `SignUp`,
  `ClerkProvider`; no `@clerk/nextjs/server` helpers are used). Same publishable
  key + `.pencheff.com` session — no Clerk dashboard change.
- **`AuthGuard` already exists** (`components/auth-guard.tsx`) and is already
  wired into ~17 authenticated section layouts. It does the `/login` redirect
  _and_ org-onboarding gating. Middleware `auth.protect()` was redundant
  server-side belt-and-suspenders — which is why deleting middleware is safe.

## Dynamic-route strategy: shell + CDN rewrite (chosen)

Pure static export cannot pre-render unbounded user-data routes (`scans/[id]`,
etc.), and `generateStaticParams` can't enumerate them. Rather than flatten URLs
into query params (which would churn ~158 internal links and break external
deep-links), we keep the existing pretty URLs and use a **placeholder shell +
Cloudflare rewrite**:

1. Each dynamic page gets `generateStaticParams()` returning a single
   placeholder, e.g. `[{ id: "_" }]`, so the export emits exactly one shell file
   (e.g. `out/scans/_/…`).
2. The page reads its identifier from `usePathname()` (the real browser URL)
   instead of the `params` prop. Data fetching is already client-side, so the
   prerendered shell hydrates against the real id at runtime.
3. Cloudflare Pages `_redirects` **rewrites** (HTTP 200, URL preserved) map every
   real id onto the shell, e.g. `/scans/:id  /scans/_/  200`.

This touches the ~24 dynamic page files but **zero** of the ~158 link sites, and
preserves all existing and external URLs (including desktop-generated
`/invite/{token}` links).

### Path-segment convention

A tiny helper (`lib/route-params.ts`) extracts segments from `usePathname()`:

```ts
export function pathSegment(pathname: string, index: number): string {
  return pathname.split("/")[index] ?? "";
}
```

Index per route (parts of `"/a/b/c".split("/")` = `["", "a", "b", "c"]`):

| Route                                                                                 | id source | nested source |
| ------------------------------------------------------------------------------------- | --------- | ------------- |
| `/advisories/:id`                                                                     | index 2   | —             |
| `/findings/:id`                                                                       | index 2   | —             |
| `/targets/:id`, `/targets/:id/edit`                                                   | index 2   | —             |
| `/sbom/:scanId`                                                                       | index 2   | —             |
| `/dependencies/:scanId`                                                               | index 2   | —             |
| `/workspaces/:id/branding`                                                            | index 2   | —             |
| `/invite/:token`                                                                      | index 2   | —             |
| `/repos/:repoId`, `/repos/:repoId/{dashboard,edit}`                                   | index 2   | —             |
| `/engagements/:id/{threat-model,api-discovery}`                                       | index 2   | —             |
| `/observability/traces/:scanId`                                                       | index 3   | —             |
| `/repos/scans/:scanId`, `/repos/scans/:scanId/{compliance,dashboard}`                 | index 3   | —             |
| `/scans/:id`, `/scans/:id/{dashboard,compliance,threat-model,recommended-guardrails}` | index 2   | —             |
| `/scans/:id/findings/:fid`                                                            | index 2   | fid index 4   |

## Export-blockers found by the spike (full catalog)

Every item below blocked the export build and must be fixed:

| Blocker                                                                                                                                                        | Fix                                                                                                                                                                                            |
| -------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `app/opengraph-image.tsx` + `app/twitter-image.tsx` use `runtime = "edge"` (dynamic OG generation)                                                             | Pre-generate the PNG once, ship as a static file, reference via static `metadata.openGraph.images` / `metadata.twitter.images`.                                                                |
| `app/robots.ts`, `app/sitemap.ts`, `app/manifest.ts`                                                                                                           | Add `export const dynamic = "force-static"` (they use no request data).                                                                                                                        |
| `app/audience/[slug]/page.tsx` and `app/subscriptions/[slug]/page.tsx` are **server `redirect()` stub pages** (and lack `generateStaticParams`)                | Delete the routes; replicate the redirects as Cloudflare redirect rules. (`subscriptions/[slug]` → `/pricing`; `audience/[slug]` → `/solutions/overview`.)                                     |
| A server-action runtime is pulled into the build (no `"use server"` anywhere in app code → almost certainly the `react@19.0.0-rc` + `next@15.0.3` interaction) | Resolve in **Task 1** (green build): pin/upgrade React + Next to a stable pair, or isolate the trigger by binary-search route removal. Do not proceed past Task 1 until `next build` is green. |

The other 7 marketing `[slug]` routes (`ai-security`, `capabilities`,
`company`, `platform`, `resources`, `solutions`, `support`) already have
`generateStaticParams` and stay SSG — no change.

## Target architecture

```
                    ┌─────────────────────────── Cloudflare ───────────────────────────┐
Browser ──────────► │  pencheff.com        → Pages project "pencheff-marketing"         │
                    │  app.pencheff.com    → Pages project "pencheff-app"               │
                    │     (both serve the SAME static `out/` export)                    │
                    │  _redirects: subdomain routing + dynamic-route rewrites           │
                    └───────────────────────────────────────────────────────────────────┘
                                          │  XHR/fetch + SSE (Clerk JWT, CORS)
                                          ▼
                    ┌──────────────────────────────────────────────┐
Browser & Desktop ► │  api.pencheff.com  (CNAME → Docker host,       │
                    │  Cloudflare-proxied)  ──► FastAPI container     │  ← unchanged backend
                    └──────────────────────────────────────────────┘
```

## Frontend changes (`apps/web`)

| #   | Change                                                                 | Detail                                                                                                                                                                                                                                                                                                                                            |
| --- | ---------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| A   | `next.config.js`                                                       | Add `output: 'export'` + `images: { unoptimized: true }`. Delete `rewrites()` (the `/api/*` proxy) and `redirects()` (both move to Cloudflare).                                                                                                                                                                                                   |
| B   | **Delete `middleware.ts`**                                             | Auth → client guard (D); subdomain routing → Cloudflare. Drop `CLERK_SECRET_KEY` from the frontend entirely.                                                                                                                                                                                                                                      |
| C   | **Delete route handler** `app/api/llm/proxy/agentic/messages/route.ts` | The backend endpoint already exists in `routers/llm_proxy_agentic.py`; with no Next server there is no rewrite-timeout to bypass.                                                                                                                                                                                                                 |
| D   | **Client auth guard**                                                  | New `components/auth-guard.tsx` (`useAuth()`; renders a loader until Clerk loads, then redirects unauth'd users → `/login`). Injected into the per-section `layout.tsx` of every authenticated path (the old middleware `APP_PATHS`). Not a security regression — FastAPI validates the JWT; middleware was only UX redirect.                     |
| E   | **Clerk auth pages**                                                   | `login/[[...rest]]` & `signup/[[...rest]]` → `routing="hash"`, collapse the catch-alls to `login/page.tsx` / `signup/page.tsx`. The `oauth/desktop-bridge` page already uses `routing="hash"` — proven pattern.                                                                                                                                   |
| F   | **Dynamic app-data routes → shell + CDN rewrite**                      | Per the strategy above: `generateStaticParams` placeholder + `usePathname()` reader, no link changes. Covers the ~24 page files across `advisories`, `dependencies`, `engagements`, `findings`, `observability/traces`, `repos`, `repos/scans`, `sbom`, `scans` (incl. nested `findings/[fid]`), `targets`, `workspaces/[id]/branding`, `invite`. |
| G   | **Export-blocker fixes**                                               | OG images → static; `robots`/`sitemap`/`manifest` → `force-static`; redirect-stub slug routes deleted (moved to Cloudflare). See catalog.                                                                                                                                                                                                         |
| H   | `lib/api.ts`                                                           | **No code change.** Behavior shifts via env: `NEXT_PUBLIC_API_URL=https://api.pencheff.com`.                                                                                                                                                                                                                                                      |
| I   | `components/auth-guard.tsx`, `lib/route-params.ts`                     | New shared helpers (D and F).                                                                                                                                                                                                                                                                                                                     |

## Backend changes (`apps/api`) — minimal

- `ALLOWED_ORIGINS` must include `https://pencheff.com` and
  `https://app.pencheff.com` so direct CORS calls + SSE work. Verify/extend only.
- **No new endpoint** — `/llm/proxy/agentic/messages` already lives in
  `routers/llm_proxy_agentic.py`.

## Desktop changes (`pencheff-studio`)

- `Networking/APIBaseURL.swift`: `https://app.pencheff.com/api` →
  `https://api.pencheff.com` (one line + the explanatory comment above it).
- **No invite-link change** — the shell+rewrite strategy preserves
  `/invite/{token}`, so `InvitesTab.swift` and `WebBaseURL.swift` are untouched.

## Cloudflare / infra

- **DNS:** add `api.pencheff.com` CNAME → Docker host, **Proxied**, SSL
  **Full (strict)**.
- **Two Pages projects** (`pencheff-marketing`, `pencheff-app`): both build
  `next build` → output dir `out/`, both fed the same `NEXT_PUBLIC_*` env
  (API URL, Clerk publishable key, landing/app/docs URLs). Same artifact, two
  custom domains.
- **`_redirects`** (committed to `apps/web/public/_redirects`, shipped in `out/`):
  - **Dynamic-route rewrites (200, most-specific first):** one rule per dynamic
    page, e.g. `/scans/:id/findings/:fid  /scans/_/findings/_/  200`,
    `/scans/:id/dashboard  /scans/_/dashboard/  200`, `/scans/:id  /scans/_/  200`,
    and the equivalents for every route in the segment table. Exact target form
    (trailing slash vs `.html`) is matched to the emitted `out/` layout, confirmed
    in Task 1.
  - **Redirect-stub replacements (301/302):** `/subscriptions/*` → `/pricing`;
    `/audience/*` → `/solutions/overview`.
  - **Canonical (301):** `/support/case-studies` → `/company/case-studies`;
    `/company/contact-us` → `/company/contact`.
  - **Subdomain routing** (replaces `middleware.ts` `subdomainRouter`) is set as
    **Cloudflare Redirect Rules** at the zone level (cross-host redirects can't
    live in a per-project `_redirects`): on `pencheff.com` the `APP_PATHS` →
    `app.pencheff.com`; on `app.pencheff.com` `/` → `/dashboard` and marketing
    paths → `pencheff.com`.
- **`docker-compose.yml`:** remove the `web` service from the production stack
  (frontend leaves Docker). Local dev still uses `next dev` (the dev server keeps
  rewrites, so local development is unchanged).

## Implementation sequencing

1. **Green build first.** Task 1 reproduces a clean `next build` → `out/`
   (resolve the React/server-action blocker, OG images, robots/sitemap/manifest,
   delete redirect-stub routes, `output: 'export'`). This locks the cutover
   target empirically before the bulk route work.
2. Convert the ~24 dynamic pages to the shell+rewrite pattern (each independently
   builds green).
3. Auth guard + Clerk hash pages + delete middleware/route handler.
4. Backend CORS, desktop one-liner.
5. Cloudflare projects, DNS, `_redirects`, Redirect Rules, docker-compose.

## Verification / success criteria

1. `next build` exits 0, emits `out/` with **zero** server functions; grep
   confirms no `middleware.ts`, no `route.ts`, no `cookies()`/`headers()`, no
   `runtime = "edge"`.
2. Serve `out/` locally with the `_redirects` honored (e.g. `wrangler pages dev
out`) → click-through: marketing pages render; `/login` (hash) → sign in →
   `/dashboard`; open `/scans/<real-id>` (served via shell rewrite) and confirm
   it loads the right scan; cold-load `/dashboard` while signed out redirects to
   login.
3. CORS preflight from `pencheff.com`/`app.pencheff.com` to `api.pencheff.com`
   succeeds; SSE streams live.
4. Desktop smoke test against `api.pencheff.com` (agentic fix + a scan).

## Risks / trade-offs

- **Protected-route flash:** the guard renders a loader (nothing leaks) until
  Clerk resolves.
- **Placeholder-param hack:** dynamic pages prerender with id `"_"`; correctness
  depends on the Cloudflare rewrite being present and the page reading
  `usePathname()` at runtime. Mitigation: the verification step exercises a real
  id end-to-end through `wrangler pages dev`.
- **React RC blocker:** Task 1 must resolve the server-action runtime issue; if
  pinning React/Next proves disruptive, fall back to flattening only the few
  routes that trigger it. Gated at Task 1 — no downstream work until green.
- **SEO:** marketing stays SSG (unaffected); the app is `noindex` already.
- **Two deploy targets** now (frontend Pages + backend Docker) instead of one
  compose stack — documented in `DEPLOYMENT.md`.

## Out of scope

- `apps/docs` and `apps/blog` (separate apps, separate hosting; not raised).
- Any backend refactor beyond CORS origins.
- Migrating Clerk instance configuration (production instance + `.pencheff.com`
  session scope already in place).
