# Static-SPA Frontend on Cloudflare + Dockerized API — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Convert `apps/web` (Next.js 15) to a pure static export (`output: 'export'`) hosted on two Cloudflare Pages projects, with the FastAPI backend staying in Docker behind a new `api.pencheff.com` origin reached over CORS.

**Architecture:** No Next.js server. Marketing pages stay SSG. Unbounded user-data routes keep their pretty URLs via a placeholder-shell (`generateStaticParams` → `_`) plus a Cloudflare `_redirects` 200-rewrite, and read their id from the live URL client-side. Clerk runs client-only (`<AuthGuard>` replaces middleware `auth.protect()`). Subdomain routing moves to Cloudflare Redirect Rules.

**Tech Stack:** Next.js 15 (App Router) static export, React 19, `@clerk/nextjs` v7 (client-only), Cloudflare Pages + `wrangler`, FastAPI (unchanged), Swift desktop (one-line change).

**Spec:** `docs/superpowers/specs/2026-05-31-static-spa-cloudflare-design.md`

**Branch:** work on `frontend-cdn`.

---

## Conventions used throughout

- **Build command (with required env)** — every "run the build" step uses:
  ```bash
  cd apps/web
  NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY="pk_test_Y2xlcmsuc3Bpa2UuZGV2JA" \
  NEXT_PUBLIC_API_URL="https://api.pencheff.com" \
  NEXT_PUBLIC_LANDING_URL="https://pencheff.com" \
  NEXT_PUBLIC_APP_URL="https://app.pencheff.com" \
  NEXT_PUBLIC_DOCS_URL="https://docs.pencheff.com" \
  npx next build
  ```
  (The `pk_test_…` key is a throwaway dev key for build-time only. Swap to the real production key in Cloudflare Pages env.)
- **Verification is build + serve, not unit tests** — `apps/web` has no test harness (`package.json` has only `dev/build/start/lint`). The honest verification loop here is: `next build` exits 0, grep assertions on `out/`, and a `wrangler pages dev out` click-through.
- **VERIFICATION CONTRACT (revised after Task 1 execution).** A fully green `out/` is only reachable after the API route handler + `middleware.ts` are deleted AND all ~23 dynamic routes + the two Clerk catch-alls are converted. Therefore **"build green" is NOT a per-task gate.** Each task verifies `✓ Compiled successfully` plus its own routes/assertions, and tolerates _expected-pending_ errors from not-yet-converted routes. There is **one** final green-build gate (after Task 3 + Task 5 + Task 6). When dispatching a conversion implementer, explicitly tell them which errors are expected (e.g. `missing generateStaticParams` on sibling routes not yet converted) so they don't chase an impossible green build.
- **`generateStaticParams` + `"use client"` cannot coexist in one file** (Next 15 build error). Every dynamic _page_ is a client component, so the placeholder `generateStaticParams` MUST live in a sibling Server Component `layout.tsx` — this is mandatory, not a fallback. Confirmed empirically in Task 1.
- **No React/Next version pin needed.** Task 1 proved the baseline (`next@15.0.3` + `react@19.0.0-rc`) compiles clean with no server-action error. The original Task 1 Step 5 is moot — do not pin.

---

## Task 1: Build-config blockers — DONE (commit `1dd2e5d`)

> **Status: completed.** Scope corrected during execution: this task resolved the build-_config_ blockers only. A green `out/` is not reachable in isolation — it also needs the API-route + middleware deletions (Task 6, pulled forward to run next) and the dynamic-route conversions (Tasks 2–3) and catch-all flattening (Task 5). The green-build verification moved to the final gate (see Verification Contract above).

What shipped in `1dd2e5d`: `next.config.js` → `output: 'export'` + `images.unoptimized`; `force-static` on `robots.ts`/`sitemap.ts`/`manifest.ts`; deleted `audience/[slug]` + `subscriptions/[slug]` redirect stubs; static `public/og.png` replacing the edge OG generators; `og.png` wired into `layout.tsx` metadata. No version pin (not needed).

### Original Task 1 steps (historical — the green-build/`out/` assertions in Steps 6–7 are superseded by the final gate)

**Files:**

- Modify: `apps/web/next.config.js`
- Modify: `apps/web/app/robots.ts`, `apps/web/app/sitemap.ts`, `apps/web/app/manifest.ts`
- Modify: `apps/web/package.json` (only if React/Next pin needed — see Step 5)
- Delete: `apps/web/app/audience/[slug]/`, `apps/web/app/subscriptions/[slug]/`
- Replace: `apps/web/app/opengraph-image.tsx`, `apps/web/app/twitter-image.tsx` (dynamic → static)

- [ ] **Step 1: Switch next.config.js to static export**

Replace the whole file with:

```js
/** @type {import('next').NextConfig} */
const nextConfig = {
  output: "export",
  images: { unoptimized: true },
};

module.exports = nextConfig;
```

(The old `rewrites()`/`redirects()` move to Cloudflare in Task 9. `images.unoptimized` is required — the export has no image optimizer; only 2 files use `next/image`.)

- [ ] **Step 2: Make the metadata routes static**

Append to each of `app/robots.ts`, `app/sitemap.ts`, `app/manifest.ts`:

```ts
export const dynamic = "force-static";
```

- [ ] **Step 3: Delete the two server-`redirect()` stub routes**

These render via server-side `redirect()` and can't be exported; their behavior moves to Cloudflare in Task 9.

```bash
cd apps/web
git rm -r "app/audience/[slug]" "app/subscriptions/[slug]"
```

Verify nothing else imports them:

```bash
grep -rn "audience/\[slug\]\|subscriptions/\[slug\]" app components lib --include="*.ts" --include="*.tsx"
```

Expected: no results.

- [ ] **Step 4: Replace dynamic OG images with static PNGs**

Generate the PNG once from the existing design, then reference it statically.

4a. Temporarily render the current `app/opengraph-image.tsx` to a file. Quickest path: keep the existing JSX but capture its output. Practical approach — create `apps/web/public/og.png` (1200×630). If no design tooling is handy, screenshot the rendered route on the current server build, or export the JSX via a one-off `@vercel/og` node script. Save as `apps/web/public/og.png`.

4b. Delete the dynamic generators:

```bash
cd apps/web
git rm app/opengraph-image.tsx app/twitter-image.tsx
```

4c. Reference the static image in root metadata. In `app/layout.tsx`, find the `export const metadata` object and add (inside it):

```ts
  openGraph: {
    images: [{ url: "/og.png", width: 1200, height: 630 }],
  },
  twitter: {
    card: "summary_large_image",
    images: ["/og.png"],
  },
```

(If `openGraph`/`twitter` keys already exist in that metadata object, merge the `images` field into them instead of duplicating.)

- [ ] **Step 5: Resolve the server-action runtime blocker**

Run the build (Conventions block). If it fails with `Server Actions are not supported with static export` and `grep -rn "use server" app components lib` is empty, it's the `react@19.0.0-rc` + `next@15.0.3` interaction.

Fix by pinning to a stable, mutually-compatible pair. In `apps/web/package.json` set:

```json
    "next": "15.1.6",
    "react": "19.0.0",
    "react-dom": "19.0.0",
```

Then:

```bash
cd apps/web && npm install
```

If the error persists after the pin, isolate the trigger empirically: temporarily move half the top-level route folders out of `app/`, rebuild, and bisect until the offending route is identified; report it before changing app logic. Do **not** invent a `"use server"` removal — there is none in app code.

- [ ] **Step 6: Run the build — must be green**

Run the build command from the Conventions block.
Expected: `✓ Compiled successfully`, page data collected, and an `out/` directory produced. Exit code 0.

- [ ] **Step 7: Assert the export has no server functions**

```bash
cd apps/web
test -d out && echo "OUT_OK"
ls out/index.html && echo "MARKETING_OK"
# no server-only artifacts leaked into the export:
! find out -name "*.rsc" -path "*api*" 2>/dev/null | grep . && echo "NO_API_ROUTES"
```

Expected: `OUT_OK`, `MARKETING_OK`, `NO_API_ROUTES`.

- [ ] **Step 8: Commit**

```bash
cd /Users/balasriharsha/BalaSriharsha/pencheff
git add apps/web/next.config.js apps/web/app/robots.ts apps/web/app/sitemap.ts apps/web/app/manifest.ts apps/web/app/layout.tsx apps/web/public/og.png apps/web/package.json apps/web/package-lock.json
git add -A apps/web/app
git commit -m "build(web): green static export — fix OG images, metadata routes, redirect stubs, react pin"
```

---

## Task 1b: Delete the Next server surface (PULLED FORWARD from Task 6)

The export build cannot produce `out/` while the route handler exists (`force-dynamic` POST handler is incompatible with `output: export`), and `middleware.ts` is meaningless under static export. Deleting both now is build-safe (the export needs no runtime API/auth) and unblocks Tasks 2–3. The remaining Task 6 work (API-origin env, no version pin) folds in here.

**Files:**

- Delete: `apps/web/middleware.ts`, `apps/web/app/api/llm/proxy/agentic/messages/route.ts` (and the now-empty `app/api` tree)
- Modify: `apps/web/.env.local.example`

- [ ] **Step 1: Preserve `APP_PATHS` before deleting middleware.** Confirm the authenticated-section list in the spec (`docs/superpowers/specs/2026-05-31-static-spa-cloudflare-design.md`) matches `grep -oE '"/[a-z]+"' apps/web/middleware.ts`. Tasks 4 and 9 depend on it.
- [ ] **Step 2:** `cd apps/web && git rm middleware.ts && git rm -r app/api`
- [ ] **Step 3:** In `apps/web/.env.local.example` set `NEXT_PUBLIC_API_URL=https://api.pencheff.com` (no code change to `lib/api.ts`).
- [ ] **Step 4: Build — expect `✓ Compiled successfully`.** Page-data collection will still error on the unconverted dynamic routes (`missing generateStaticParams`) and the Clerk catch-alls — **that is expected-pending**, not a failure of this task. Assert: `test ! -f apps/web/middleware.ts && test ! -d apps/web/app/api && echo SERVER_SURFACE_GONE`.
- [ ] **Step 5: Commit.** `git add -A apps/web && git reset apps/web/public/bg_videos && git commit -m "feat(web): remove middleware + route handler; API via api.pencheff.com over CORS"`

---

## Task 2: Prove the dynamic-route shell pattern on ONE route

Lock the exact runtime behavior (does the page read the _real_ id under the `_` shell rewrite, with no hydration mismatch?) before touching 22 more files. Uses `scans/[id]` because it's the heaviest-trafficked route (71 link sites).

**The `generateStaticParams` placeholder MUST go in a sibling Server Component `layout.tsx`** — it cannot live in the `"use client"` page (Next 15 forbids both in one file; confirmed in Task 1). This layout-split is the canonical pattern for Task 3, not an optional fallback.

**Early-green checkpoint:** after converting `scans/[id]`, temporarily stash the still-unconverted dynamic route dirs + the `login/[[...rest]]`/`signup/[[...rest]]` catch-alls out of `app/` (like the original spike), build, and confirm a clean `out/` IS produced (proving no other hidden blockers), then restore. This is what "green build first" was for.

**Files:**

- Create: `apps/web/lib/route-params.ts`
- Modify: `apps/web/app/scans/[id]/page.tsx`
- Create: `apps/web/app/scans/[id]/layout.tsx` (holds `generateStaticParams`)
- Create: `apps/web/public/_redirects` (first rule only; full set in Task 9)

- [ ] **Step 1: Create the path-segment helper**

`apps/web/lib/route-params.ts`:

```ts
"use client";

/**
 * Read a single path segment from a pathname produced by usePathname().
 * Under static export, dynamic pages are pre-rendered as a "_" placeholder
 * shell and served for the real URL via a Cloudflare 200-rewrite, so the
 * identifier must be read from the live URL at runtime — never from the
 * build-time `params` prop (which is "_").
 *
 * Index is the position in "/a/b/c".split("/") === ["", "a", "b", "c"].
 */
export function pathSegment(pathname: string, index: number): string {
  return pathname.split("/")[index] ?? "";
}
```

- [ ] **Step 2: Convert `scans/[id]/page.tsx` to read the live URL**

Current (line ~145):

```tsx
export default function ScanDetailPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
```

Replace with:

```tsx
export default function ScanDetailPage() {
  const id = pathSegment(usePathname(), 2);
```

Add the imports near the top (the file already imports from `next/navigation` and `react`):

```tsx
import { usePathname } from "next/navigation";
import { pathSegment } from "@/lib/route-params";
```

Remove now-unused `use` from the `react` import if `use(...)` is no longer referenced anywhere in the file (check with `grep -n "use(" app/scans/[id]/page.tsx`).

Add `generateStaticParams` so the export emits exactly one shell. Append to the file:

```tsx
export function generateStaticParams() {
  return [{ id: "_" }];
}
```

> Note: `generateStaticParams` cannot live in a `"use client"` module in some Next versions. If the build rejects it, move it into a sibling Server Component segment file: create `app/scans/[id]/layout.tsx` containing only:
>
> ```tsx
> export function generateStaticParams() {
>   return [{ id: "_" }];
> }
> export default function Layout({ children }: { children: React.ReactNode }) {
>   return children;
> }
> ```
>
> Use whichever the build accepts; record the working location for Task 3.

- [ ] **Step 3: Add the first rewrite rule**

`apps/web/public/_redirects` (Cloudflare serves files in `public/` from the export root, and honors `_redirects`):

```
/scans/:id/findings/:fid   /scans/_/findings/_/   200
/scans/:id/dashboard       /scans/_/dashboard/    200
/scans/:id/compliance      /scans/_/compliance/   200
/scans/:id/threat-model    /scans/_/threat-model/ 200
/scans/:id/recommended-guardrails  /scans/_/recommended-guardrails/  200
/scans/:id                 /scans/_/              200
```

(Most-specific first; `:id` matches a single segment so children aren't shadowed.)

- [ ] **Step 4: Build and confirm the shell emitted**

Run the build (Conventions block). Then:

```bash
cd apps/web
find out/scans -maxdepth 2 -name "*.html" | head
```

Expected: a file for the placeholder, e.g. `out/scans/_/index.html` (or `out/scans/_.html`). **Record the exact form** — it determines the `_redirects` target (`/scans/_/` vs `/scans/_`). If it's `_.html`, the target is `/scans/_` and child targets are `/scans/_/dashboard` etc.; adjust Step 3 to match and rebuild.

- [ ] **Step 5: Serve via wrangler and verify a REAL id loads the right scan**

```bash
cd apps/web
npx wrangler pages dev out --port 8788
```

In a browser (signed in, or with the AuthGuard not yet added this just reaches the fetch): open `http://localhost:8788/scans/<a-real-scan-id>`.
Expected: the shell is served (200, URL stays `/scans/<id>`), and the page fetches and renders that scan — **not** a `_` scan. Open devtools console: **no hydration mismatch error**.

If a hydration mismatch appears (server rendered `_`, client rendered the real id in visible JSX), guard the first paint so the identifier isn't in the server-rendered output:

```tsx
const [mounted, setMounted] = useState(false);
useEffect(() => setMounted(true), []);
const id = mounted ? pathSegment(usePathname(), 2) : "";
```

Confirm the loading state renders identically for `id === ""`. Re-verify. **This decides the canonical pattern for Task 3** — record whether the `mounted` guard is needed.

- [ ] **Step 6: Commit**

```bash
cd /Users/balasriharsha/BalaSriharsha/pencheff
git add apps/web/lib/route-params.ts "apps/web/app/scans/[id]" apps/web/public/_redirects
git commit -m "feat(web): prove dynamic-route shell+rewrite pattern on scans/[id]"
```

---

## Task 2c: Migrate Clerk to `@clerk/clerk-react` (BLOCKS Task 3 — tracker #10)

**Why:** `@clerk/nextjs` v7's `<ClerkProvider>` unconditionally references a server action (`invalidateCacheAction`), which `output: 'export'` rejects app-wide ("Server Actions are not supported with static export"). The framework-agnostic `@clerk/clerk-react` SDK has no server actions and the same client hook/component APIs.

**Surface (verified):** 11 files import `@clerk/nextjs`, using only `useAuth`, `useUser`, `useClerk`, `UserButton`, `SignIn`, `SignUp`, `ClerkProvider`. Zero `@clerk/nextjs/server` usage. Files: `app/layout.tsx` (the provider), `app/billing/page.tsx`, `app/invite/[token]/page.tsx`, `app/login/[[...rest]]/page.tsx`, `app/signup/[[...rest]]/page.tsx`, `app/oauth/desktop-bridge/page.tsx`, `app/onboarding/page.tsx`, `components/auth-guard.tsx`, `components/landing-nav.tsx`, `components/nav.tsx`, `lib/workspace-context.tsx`.

- [ ] **Step 1:** `cd apps/web && npm install @clerk/clerk-react` (pin to a version matching the installed `@clerk/react` internal — check `node_modules/@clerk/react/package.json`; install the matching `@clerk/clerk-react` major).
- [ ] **Step 2:** In the 10 non-layout files, change `from "@clerk/nextjs"` → `from "@clerk/clerk-react"`. Symbols are unchanged. (`components/auth-guard.tsx` keeps its existing logic — only the import line changes.)
- [ ] **Step 3:** In `app/layout.tsx`, replace the `@clerk/nextjs` `<ClerkProvider>` with `@clerk/clerk-react`'s. `@clerk/clerk-react`'s provider is client-only and needs SPA navigation wired: pass `routerPush`/`routerReplace`. Since `layout.tsx` is a Server Component, extract a small `"use client"` wrapper component `components/clerk-provider.tsx`:
  ```tsx
  "use client";
  import { ClerkProvider } from "@clerk/clerk-react";
  import { useRouter } from "next/navigation";
  export function AppClerkProvider({
    children,
    ...props
  }: { children: React.ReactNode } & Record<string, unknown>) {
    const router = useRouter();
    return (
      <ClerkProvider
        publishableKey={process.env.NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY!}
        routerPush={(to) => router.push(to)}
        routerReplace={(to) => router.replace(to)}
        signInUrl="/login"
        {...props}
      >
        {children}
      </ClerkProvider>
    );
  }
  ```
  Preserve every prop the current `app/layout.tsx` `<ClerkProvider>` passes (appearance, signInUrl, fallback redirect URLs, etc.) — read the current usage and carry them over. Then render `<AppClerkProvider>` in `layout.tsx` in place of the old provider. Drop `CLERK_SECRET_KEY`/server-only Clerk env from frontend (unused).
- [ ] **Step 4: Build — the server-action error MUST be gone.** Run the build (Conventions block). `✓ Compiled successfully` AND no "Server Actions are not supported" error. Remaining `missing generateStaticParams` errors on unconverted routes are expected-pending.
- [ ] **Step 5: Re-run the early-green checkpoint.** Stash the unconverted dynamic dirs + catch-alls (as Task 2 did), rebuild, and confirm a clean `out/` IS now produced (this is the green build Task 2 couldn't reach). **Record the exact emitted shell path form** (`out/scans/_/index.html` vs `out/scans/_.html`) — this finalizes the `_redirects` target form for Tasks 3 & 9. Restore the stash; confirm via `git status`.
- [ ] **Step 6: Commit.** `git add -A apps/web && git reset apps/web/public/bg_videos && git commit -m "feat(web): migrate Clerk to @clerk/clerk-react for static export"`

---

## Task 3: Convert the remaining 22 dynamic pages

Apply the **exact pattern locked in Task 2** to every remaining dynamic page. Two source patterns exist; both end at `const <name> = pathSegment(usePathname(), <index>)` (plus the `mounted` guard if Task 2 required it), and each route gets the `generateStaticParams` placeholder in the location Task 2 validated.

**Pattern A — pages currently using `use(params)`** (drop the prop + Promise type, read from pathname):

- Before: `function X({ params }: { params: Promise<{ id: string }> }) { const { id } = use(params);`
- After: `function X() { const id = pathSegment(usePathname(), <index>);`
- Add imports `usePathname` (from `next/navigation`) and `pathSegment` (from `@/lib/route-params`); drop unused `use`.

**Pattern B — pages currently using `useParams()`** (swap the hook):

- Before: `const { scanId } = useParams<{ scanId: string }>();`
- After: `const scanId = pathSegment(usePathname(), <index>);`
- Swap the `useParams` import for `usePathname`; add `pathSegment`.

> Pattern B note: `useParams()` _may_ already return the real id at runtime under the rewrite (Next's client router matches `window.location` against the `[id]` route pattern). Task 2 settles this. If Task 2 confirmed `useParams()` returns the real value with no mismatch, Pattern B pages may be left **unchanged** except for adding `generateStaticParams`. Use Task 2's recorded finding; default to the explicit `pathSegment` swap if unsure.

For every page, append the placeholder (file or sibling `layout.tsx` per Task 2):

```tsx
export function generateStaticParams() { return [{ <PARAM>: "_" }]; }
```

where `<PARAM>` is the route's segment name. For the double-dynamic findings route: `return [{ id: "_", fid: "_" }];`.

**Per-file table** (param name, source pattern, segment index, current id-line):

| File                                         | param               | pattern | index | current line                                |
| -------------------------------------------- | ------------------- | ------- | ----- | ------------------------------------------- |
| `advisories/[id]/page.tsx`                   | id                  | A       | 2     | `const { id } = use(params);`               |
| `dependencies/[scanId]/page.tsx`             | scanId              | B       | 2     | `const { scanId } = useParams…`             |
| `engagements/[id]/threat-model/page.tsx`     | id (`engagementId`) | A       | 2     | `const { id: engagementId } = use(params);` |
| `engagements/[id]/api-discovery/page.tsx`    | id                  | A       | 2     | `const { id } = use(params);`               |
| `findings/[id]/page.tsx`                     | id                  | A       | 2     | `const { id } = use(params);`               |
| `observability/traces/[scanId]/page.tsx`     | scanId              | A       | 3     | `const { scanId } = use(params);`           |
| `repos/[repoId]/page.tsx`                    | repoId              | B       | 2     | `const { repoId } = useParams…`             |
| `repos/[repoId]/dashboard/page.tsx`          | repoId              | B       | 2     | `const { repoId } = useParams…`             |
| `repos/[repoId]/edit/page.tsx`               | repoId              | B       | 2     | `const { repoId } = useParams…`             |
| `repos/scans/[scanId]/page.tsx`              | scanId              | B       | 3     | `const { scanId } = useParams…`             |
| `repos/scans/[scanId]/compliance/page.tsx`   | scanId              | B       | 3     | `const { scanId } = useParams…`             |
| `repos/scans/[scanId]/dashboard/page.tsx`    | scanId              | B       | 3     | `const { scanId } = useParams…`             |
| `sbom/[scanId]/page.tsx`                     | scanId              | B       | 2     | `const { scanId } = useParams…`             |
| `scans/[id]/recommended-guardrails/page.tsx` | id (`scanId`)       | A       | 2     | `const { id: scanId } = use(params);`       |
| `scans/[id]/threat-model/page.tsx`           | id (`scanId`)       | A       | 2     | `const { id: scanId } = use(params);`       |
| `scans/[id]/compliance/page.tsx`             | id (`scanId`)       | A       | 2     | `const { id: scanId } = use(params);`       |
| `scans/[id]/dashboard/page.tsx`              | id                  | A       | 2     | `const { id } = use(params);`               |
| `scans/[id]/findings/[fid]/page.tsx`         | id, fid             | A       | 2, 4  | `const { id, fid } = use(params);`          |
| `targets/[id]/page.tsx`                      | id                  | A       | 2     | `const { id } = use(params);`               |
| `targets/[id]/edit/page.tsx`                 | id                  | A       | 2     | `const { id } = use(params);`               |
| `workspaces/[id]/branding/page.tsx`          | id                  | B       | 2     | `const params = useParams…; params.id`      |
| `invite/[token]/page.tsx`                    | token               | B       | 2     | `const params = useParams…; params?.token`  |

> `workspaces/[id]/branding/page.tsx` and `invite/[token]/page.tsx` use `params.id`/`params?.token` later in the file — replace those references with the local `id`/`token` variable.

- [ ] **Step 1: Convert all Pattern A pages** (the `use(params)` ones), applying the transformation + placeholder per the table.

- [ ] **Step 2: Convert all Pattern B pages** per Task 2's finding (swap hook + placeholder, or placeholder-only if `useParams` proven safe).

- [ ] **Step 3: Build green**

Run the build (Conventions block). Expected: exit 0, `out/` emitted. Then confirm a shell exists for each prefix:

```bash
cd apps/web
for p in advisories dependencies engagements findings observability/traces repos repos/scans sbom scans targets workspaces invite; do
  find "out/$p" -name "*.html" 2>/dev/null | grep -q "_" && echo "OK   $p" || echo "MISS $p"
done
```

Expected: `OK` for every prefix.

- [ ] **Step 4: Assert no residual `use(params)` / server param typing in app data routes**

```bash
cd apps/web
grep -rn "Promise<{ *id\|Promise<{ *scanId\|Promise<{ *repoId\|Promise<{ *token\|Promise<{ *fid" app && echo "FOUND_RESIDUAL" || echo "CLEAN"
```

Expected: `CLEAN`.

- [ ] **Step 5: Commit**

```bash
cd /Users/balasriharsha/BalaSriharsha/pencheff
git add -A apps/web/app
git commit -m "feat(web): convert all dynamic user-data routes to shell+pathname pattern"
```

---

## Task 4: Verify AuthGuard coverage on authenticated sections (guard already exists)

**REVISED:** `components/auth-guard.tsx` **already exists** (committed in `c9ca162`) and already does the `/login` redirect + org-onboarding gating via `useWorkspace`. It is **already wired** into ~17 section layouts: `settings`, `repos`, `targets`, `sbom`, `scans`, `schedules`, `dependencies`, `compliance`, `search`, `workspaces/[id]/branding`, `integrations`, `findings`, `dashboard`, `assets`, `billing`, plus `org/settings` and `workspaces/new` pages. So this task is **verify + fill gaps**, NOT create.

(Note: `invite` is token-gated, not Clerk-gated — keep it **unguarded** so invitees without an account can accept.)

- [ ] **Step 1: Audit coverage against APP_PATHS.** The authenticated sections are: `dashboard`, `targets`, `scans`, `findings`, `billing`, `schedules`, `assets`, `integrations`, `sbom`, `dependencies`, `repos`, `proxy`, `settings`, `compliance`, `search`, `observability`, `advisories`, `engagements`, `onboarding`, `org`, `workspaces`. For each, check whether the section (or its pages) is already inside an `<AuthGuard>` (via `app/<section>/layout.tsx` or an ancestor). List which are covered and which are NOT.

- [ ] **Step 2: Add a guard layout only to UNCOVERED sections.** Likely gaps (confirm in Step 1): `observability`, `advisories`, `engagements`, `proxy` (if present). For each genuinely-uncovered section that has no `layout.tsx`, create `app/<section>/layout.tsx`:

  ```tsx
  import { AuthGuard } from "@/components/auth-guard";
  export default function Layout({ children }: { children: React.ReactNode }) {
    return <AuthGuard>{children}</AuthGuard>;
  }
  ```

  If a section already has a `layout.tsx` that does NOT wrap in `<AuthGuard>`, wrap its returned content. Do NOT touch sections already covered. Do NOT modify the guard's logic. `onboarding` is intentionally reachable while org-less (the guard already exempts `/onboarding`) — do not block it.

  > Caution: some of these sections are dynamic routes that received a `generateStaticParams` `layout.tsx` in Task 2/3. If a section's `layout.tsx` already exists for `generateStaticParams`, ADD the `<AuthGuard>` wrap to that same layout's default export rather than creating a second layout. A `generateStaticParams` export and an `<AuthGuard>`-wrapping default export can coexist in one Server Component layout — but `AuthGuard` is a client component, so importing it into the layout is fine (it's rendered, not made the layout itself a client module).

- [ ] **Step 3: Build — compiles + no new errors.** Run the build (Conventions block). Expect `✓ Compiled successfully`; remaining errors only the expected-pending ones for routes not yet converted (should be none if Task 3 is done). Commit:
  ```bash
  cd /Users/balasriharsha/BalaSriharsha/pencheff
  git add -A apps/web/app && git reset apps/web/public/bg_videos
  git commit -m "feat(web): AuthGuard coverage on remaining authenticated sections"
  ```
  (If Step 1 finds full coverage already, this task is a no-op verification — record that and skip the commit.)

---

## Task 5: Clerk auth pages → hash routing (last build-blocker → enables fully green build)

**Two changes, not one:** (a) flatten the `[[...rest]]` catch-alls (hash routing means no path catch-all is needed, and a catch-all needs `generateStaticParams` under export); (b) the pages currently import `SignIn`/`SignUp` directly, but `@clerk/react`'s `SignIn`/`SignUp` ship WITHOUT a `"use client"` directive — so a Server Component page that imports them fails at prerender with `createContext is not a function` (confirmed in Task 2c). The pages also export `metadata` (server-only), so they MUST stay Server Components. Resolution: keep each page a Server Component (metadata + marketing chrome) and extract the Clerk widget into a small `"use client"` child component.

**Files:**

- Delete: `apps/web/app/login/[[...rest]]/`, `apps/web/app/signup/[[...rest]]/`
- Create: `apps/web/app/login/page.tsx`, `apps/web/app/signup/page.tsx`
- Create: `apps/web/components/sign-in-box.tsx`, `apps/web/components/sign-up-box.tsx` (`"use client"` wrappers)

- [ ] **Step 1: Client wrappers for the Clerk widgets.** `components/sign-in-box.tsx`:

  ```tsx
  "use client";
  import { SignIn } from "@clerk/react";
  export function SignInBox() {
    return (
      <SignIn
        routing="hash"
        signUpUrl="/signup"
        fallbackRedirectUrl="/dashboard"
      />
    );
  }
  ```

  `components/sign-up-box.tsx`:

  ```tsx
  "use client";
  import { SignUp } from "@clerk/react";
  export function SignUpBox() {
    return (
      <SignUp
        routing="hash"
        signInUrl="/login"
        fallbackRedirectUrl="/dashboard"
      />
    );
  }
  ```

- [ ] **Step 2: Flatten login.** Read `app/login/[[...rest]]/page.tsx`, recreate it at `app/login/page.tsx` IDENTICALLY (keep `export const metadata = authRouteMetadata(...)`, `LandingNav`, `LandingEffects`, all copy, and the page as a Server Component — NO `"use client"`), but replace the inline `<SignIn ... />` with `<SignInBox />` and drop the now-unused `SignIn`/`@clerk/react` import from the page. Then `cd apps/web && git rm -r "app/login/[[...rest]]"`.

- [ ] **Step 3: Flatten signup** — same, at `app/signup/page.tsx`, using `<SignUpBox />`. Then `cd apps/web && git rm -r "app/signup/[[...rest]]"`.

- [ ] **Step 4: FULLY GREEN BUILD (the final gate's build half).** Run the build (Conventions block). This is the first point a fully green `out/` should be produced with NOTHING stashed. Expected: exit 0, `out/` emitted, zero page-data errors. Assert: `test -d apps/web/out && ls apps/web/out/login.html apps/web/out/signup.html && echo LOGIN_SIGNUP_OK`. If any error remains, it's a real blocker — resolve or report.

- [ ] **Step 4: Commit**

```bash
cd /Users/balasriharsha/BalaSriharsha/pencheff
git add -A apps/web/app/login apps/web/app/signup
git commit -m "feat(web): hash-routed login/signup for static export"
```

---

## Task 6: Delete the Next server surface + point API at the public origin

**Files:**

- Delete: `apps/web/middleware.ts`, `apps/web/app/api/llm/proxy/agentic/messages/route.ts` (and empty `app/api` tree)
- Modify: `apps/web/.env.local.example`, `docker-compose.yml` web build args

- [ ] **Step 1: Delete middleware and the route handler**

```bash
cd apps/web
git rm middleware.ts
git rm -r app/api
```

- [ ] **Step 2: Set the API origin for production builds**

In `apps/web/.env.local.example`, set the documented value:

```
NEXT_PUBLIC_API_URL=https://api.pencheff.com
```

(No code change to `lib/api.ts` — it already reads `NEXT_PUBLIC_API_URL`.) The real value is injected per-project in Cloudflare Pages (Task 9).

- [ ] **Step 3: Build green — confirm no server surface remains**

Run the build. Then:

```bash
cd apps/web
test ! -f middleware.ts && echo "NO_MIDDLEWARE"
test ! -d app/api && echo "NO_ROUTE_HANDLERS"
grep -rn "next/headers\|from \"next/server\"" app && echo "FOUND_SERVER_IMPORTS" || echo "CLEAN_SERVER_IMPORTS"
```

Expected: `NO_MIDDLEWARE`, `NO_ROUTE_HANDLERS`, `CLEAN_SERVER_IMPORTS`.

- [ ] **Step 4: Commit**

```bash
cd /Users/balasriharsha/BalaSriharsha/pencheff
git add -A apps/web docker-compose.yml
git commit -m "feat(web): remove middleware + route handler; API via api.pencheff.com over CORS"
```

---

## Task 7: Backend CORS origins

**Files:**

- Modify: `apps/api/.env.example` (and document for prod `.env`); verify `pencheff_api/main.py` reads `settings.allowed_origins`.

- [ ] **Step 1: Confirm how origins are configured**

```bash
cd /Users/balasriharsha/BalaSriharsha/pencheff
grep -rn "allowed_origins\|ALLOWED_ORIGINS" apps/api/pencheff_api/config*.py apps/api/pencheff_api/settings*.py apps/api/.env.example 2>/dev/null
```

Identify the env var name (e.g. `ALLOWED_ORIGINS`) and format (JSON list vs CSV).

- [ ] **Step 2: Add the production origins**

In `apps/api/.env.example`, ensure the allowed-origins value includes both:

```
ALLOWED_ORIGINS=["https://pencheff.com","https://app.pencheff.com"]
```

(Match the existing format exactly — the codebase already parses this; do not change the parser.) Note in `DEPLOYMENT.md` that prod `.env` must set the same.

- [ ] **Step 3: Verify locally**

Start the API (per existing run instructions / `docker compose up api`) and check the preflight:

```bash
curl -s -i -X OPTIONS "http://localhost:8000/scans" \
  -H "Origin: https://app.pencheff.com" \
  -H "Access-Control-Request-Method: GET" | grep -i "access-control-allow-origin"
```

Expected: `access-control-allow-origin: https://app.pencheff.com`.

- [ ] **Step 4: Commit**

```bash
git add apps/api/.env.example DEPLOYMENT.md
git commit -m "feat(api): allow pencheff.com + app.pencheff.com CORS origins"
```

---

## Task 8: Desktop API base origin (one line)

**Files:**

- Modify: `pencheff-studio/pencheff-studio/Networking/APIBaseURL.swift`

- [ ] **Step 1: Repoint the base URL**

Current:

```swift
// No standalone api.pencheff.com subdomain — all API traffic goes through
// the Next.js rewrite at app.pencheff.com/api/* (see apps/web/next.config.js).
return URL(string: "https://app.pencheff.com/api")!
```

Replace with:

```swift
// API is served directly at api.pencheff.com (Cloudflare-proxied → Docker).
// The web frontend is a static export with no /api/* rewrite.
return URL(string: "https://api.pencheff.com")!
```

- [ ] **Step 2: Confirm no other desktop file hardcodes `app.pencheff.com/api`**

```bash
cd /Users/balasriharsha/BalaSriharsha/pencheff
grep -rn "app.pencheff.com/api\|/api/llm" pencheff-studio --include="*.swift"
```

Expected: no results (the agentic proxy path is now reached via the base URL).

- [ ] **Step 3: Commit**

```bash
git add pencheff-studio/pencheff-studio/Networking/APIBaseURL.swift
git commit -m "feat(desktop): call api.pencheff.com directly (no Next rewrite)"
```

---

## Task 9: Cloudflare deploy config + docs

**Files:**

- Modify: `apps/web/public/_redirects` (complete the rule set)
- Modify: `docker-compose.yml` (remove prod `web` service)
- Modify: `DEPLOYMENT.md`

- [ ] **Step 1: Complete the `_redirects` rule set**

Extend `apps/web/public/_redirects` (started in Task 2) with every dynamic-route rewrite + the redirect-stub + canonical redirects. Use the target form recorded in Task 2 Step 4. Most-specific first **within each prefix**:

```
# --- dynamic user-data route rewrites (serve placeholder shell, keep URL) ---
/scans/:id/findings/:fid            /scans/_/findings/_/            200
/scans/:id/dashboard                /scans/_/dashboard/            200
/scans/:id/compliance               /scans/_/compliance/           200
/scans/:id/threat-model             /scans/_/threat-model/         200
/scans/:id/recommended-guardrails   /scans/_/recommended-guardrails/ 200
/scans/:id                          /scans/_/                      200
/repos/scans/:scanId/compliance     /repos/scans/_/compliance/     200
/repos/scans/:scanId/dashboard      /repos/scans/_/dashboard/      200
/repos/scans/:scanId                /repos/scans/_/                200
/repos/:repoId/dashboard            /repos/_/dashboard/            200
/repos/:repoId/edit                 /repos/_/edit/                 200
/repos/:repoId                      /repos/_/                      200
/engagements/:id/threat-model       /engagements/_/threat-model/   200
/engagements/:id/api-discovery      /engagements/_/api-discovery/  200
/observability/traces/:scanId       /observability/traces/_/       200
/workspaces/:id/branding            /workspaces/_/branding/        200
/advisories/:id                     /advisories/_/                 200
/findings/:id                       /findings/_/                   200
/dependencies/:scanId               /dependencies/_/               200
/sbom/:scanId                       /sbom/_/                       200
/targets/:id/edit                   /targets/_/edit/               200
/targets/:id                        /targets/_/                    200
/invite/:token                      /invite/_/                     200
# --- redirect-stub replacements (deleted server routes) ---
/subscriptions/*   /pricing             301
/audience/*        /solutions/overview  301
# --- canonical de-dup (from old next.config.js) ---
/support/case-studies   /company/case-studies   301
/company/contact-us     /company/contact        301
```

> Note: cross-host subdomain routing is **not** here — it's set as zone-level Redirect Rules in Step 4 (a per-project `_redirects` cannot redirect to a different hostname reliably).

- [ ] **Step 2: Verify rewrites locally with wrangler**

```bash
cd apps/web && npx wrangler pages dev out --port 8788
```

Check (signed in): `/scans/<real-id>` loads that scan; `/targets/<real-id>/edit` loads the editor; `/subscriptions/anything` 301s to `/pricing`. No 404s on real ids.

- [ ] **Step 3: Remove the prod `web` service from docker-compose**

In `docker-compose.yml`, delete the `web:` service block (lines ~184–229) — the frontend no longer ships in Docker. Leave `api`, `docs`, `blog`, workers. Add a comment where it was:

```yaml
# web/ is now a Cloudflare Pages static export (apps/web → `next build` → out/).
# See DEPLOYMENT.md. Local dev: `cd apps/web && npm run dev`.
```

Verify the compose file still parses:

```bash
cd /Users/balasriharsha/BalaSriharsha/pencheff && docker compose config >/dev/null && echo "COMPOSE_OK"
```

Expected: `COMPOSE_OK`.

- [ ] **Step 4: Document the Cloudflare setup in DEPLOYMENT.md**

Add a section covering:

- **DNS:** `api.pencheff.com` CNAME → Docker host, Proxied, SSL Full (strict).
- **Two Pages projects** `pencheff-marketing` (domain `pencheff.com`) and `pencheff-app` (domain `app.pencheff.com`). Both: build cmd `npm run build`, build output dir `apps/web/out`, root dir `apps/web`, and env vars: `NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY` (prod key), `NEXT_PUBLIC_API_URL=https://api.pencheff.com`, `NEXT_PUBLIC_LANDING_URL`, `NEXT_PUBLIC_APP_URL`, `NEXT_PUBLIC_DOCS_URL`.
- **Redirect Rules (zone-level, replaces middleware `subdomainRouter`):**
  - On `pencheff.com`, requests to APP_PATHS (`/dashboard/*`, `/targets/*`, `/scans/*`, `/findings/*`, `/billing/*`, `/schedules/*`, `/assets/*`, `/integrations/*`, `/sbom/*`, `/dependencies/*`, `/repos/*`, `/proxy/*`, `/settings/*`, `/compliance/*`, `/search/*`, `/observability/*`, `/advisories/*`, `/engagements/*`, `/onboarding/*`, `/org/*`, `/workspaces/*`) → `https://app.pencheff.com/$1` (302).
  - On `app.pencheff.com`, `/` → `https://app.pencheff.com/dashboard` (302); marketing paths (`/pricing`, etc., except `/login`,`/signup`) → `https://pencheff.com/$1` (302).
- **Clerk:** production instance, session scoped to `.pencheff.com` (already configured — see existing Clerk section). Drop `CLERK_SECRET_KEY` from frontend env (no longer used).

- [ ] **Step 5: Commit**

```bash
cd /Users/balasriharsha/BalaSriharsha/pencheff
git add apps/web/public/_redirects docker-compose.yml DEPLOYMENT.md
git commit -m "chore: Cloudflare Pages config, _redirects, drop web from compose, deploy docs"
```

---

## Final verification (whole-spec acceptance)

- [ ] `next build` exits 0 and `out/` has no server functions (Task 1 Step 7, Task 6 Step 3 assertions all pass).
- [ ] `wrangler pages dev out`: marketing renders; `/login` (hash) signs in → `/dashboard`; `/scans/<real-id>` and a nested route (`/scans/<id>/findings/<fid>`) load the correct records via the shell rewrite with no hydration error; cold-loading `/dashboard` signed-out redirects to `/login`.
- [ ] CORS preflight from `https://app.pencheff.com` to `api.pencheff.com` returns the allow-origin header; an SSE stream ticks live (not buffered).
- [ ] Desktop build points at `api.pencheff.com`; an agentic-fix call and a scan succeed.
- [ ] `docker compose config` parses without the `web` service.

---

## Spec coverage map

| Spec item                                                                                         | Task                              |
| ------------------------------------------------------------------------------------------------- | --------------------------------- |
| `output: 'export'` + images.unoptimized                                                           | 1                                 |
| OG images static / robots-sitemap-manifest force-static / redirect-stub routes / React-RC blocker | 1                                 |
| Dynamic routes → shell + CDN rewrite + `usePathname`                                              | 2 (prove), 3 (fan-out), 9 (rules) |
| Client `<AuthGuard>` on APP_PATHS layouts                                                         | 4                                 |
| Clerk hash login/signup                                                                           | 5                                 |
| Delete middleware + route handler; `NEXT_PUBLIC_API_URL`                                          | 6                                 |
| Backend CORS origins                                                                              | 7                                 |
| Desktop `APIBaseURL.swift`                                                                        | 8                                 |
| `_redirects`, Pages projects, DNS, Redirect Rules, docker-compose, DEPLOYMENT.md                  | 9                                 |
