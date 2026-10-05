# Pencheff Community Edition (CE) — Design

**Date:** 2026-06-23
**Status:** Approved for planning
**Author:** brainstorming session

## 1. Goal

Produce an open-source **community edition** of Pencheff: a faithful, self-hostable
version of the full security/pentesting platform with **no login, no users, no
multi-tenancy, and no billing**. A single person runs it (e.g. `docker compose up`)
and lands directly on the app as one implicit user.

The **full product surface** is in scope:

- **Core scanning** — targets, scans, findings, dashboard, reports.
- **Repo / code (SAST)** — git repo scanning, dependencies, SBOM, fix proposals.
- **DAST / web testing** — live scanning, intruder, repeater, proxy/traffic capture.
- **AI features** — agentic fix, AI triage, threat model, advisory AI (bring-your-own LLM key; degrade gracefully when absent).

What is **removed** is purely the SaaS layer: Clerk auth, login/signup, billing,
orgs, workspaces (multi), invites, onboarding, white-label branding, and the
enterprise integrations that require paid/external backends.

## 2. Approach (decision)

**Single-tenant shim** (chosen over a deep rip-out).

Keep the existing multi-tenant data model (`Org` / `Workspace` / `User` tables and
the `org_id` / `workspace_id` columns woven through ~82 files), but seed exactly
**one** default Org + Workspace + User at startup, and rewrite the ~6 auth
dependency functions to always return that default principal/workspace with all
scopes granted. The 39 routers and all their tenancy-scoped queries are left
**unchanged** — they resolve against the single seeded tenant.

**Rationale:** tiny blast radius, faithful behavior, low regression risk, real
product on day one. Trade-off accepted: vestigial tenant columns remain in the
schema (invisible to users); they can be dropped later if ever warranted.

Rejected alternatives:

- **Deep rip-out** — physically remove `Org`/`Workspace`/`User` and rewrite every
  query + migration. Clean schema but touches all 82 tenancy files with high
  regression risk; disproportionate for "no login."
- **In-place env gate** — single codebase toggled by env. Rejected because we want
  a clean, separate OSS repo.

## 3. Location

A new sibling repository **`pencheff-ce/`** beside `pencheff/`, seeded from a copy
of `pencheff/` (excluding `.git`, `node_modules`, `.venv`, `.next`, `out`, build
caches, `.env`), then `git init` fresh. Upstream `pencheff/` is untouched. New
top-level `LICENSE` (**Apache-2.0**), `README.md`, and `NOTICE` for the community
edition. The planning phase must verify Apache-2.0 compatibility with bundled
deps/tools (carry over `THIRD_PARTY_NOTICES.md`).

## 4. Backend design

### 4.1 Single-tenant shim

New module `pencheff_api/auth/single_tenant.py` plus a startup hook.

1. **Seed-on-boot** — on app startup, idempotently ensure one `Org`
   (`plan="self_hosted"`), one `Workspace`, and one `User` exist; cache their IDs.
   Creates only if absent; safe to run every boot.
2. **Rewrite auth dependencies** in `pencheff_api/auth/deps.py` to ignore tokens
   and return the seeded principal/workspace:
   - `get_current_user` → default `User`
   - `get_active_workspace` / `_resolve_active_workspace` → default `Workspace`
     (ignores `X-Workspace-Id`)
   - `require_scope` / `require_role` / `require_org_role` → always allow
   - `get_membership` / `session_only` → synthesized owner membership
3. **Delete dead auth code** — `auth/clerk.py`, `auth/oauth_google.py`, native
   token/password paths, and Clerk/Stripe/Google-OAuth settings in `config.py`.

The 39 routers and every `org_id`/`workspace_id` query remain untouched.

### 4.2 Routers — keep / strip / stub / optional

- **Keep (product):** targets, scans, findings, unified_findings, reports,
  dashboard, repos, fix_proposals, agentic_fix, llm_proxy (+agentic), llm_providers,
  dependencies, sboms, advisories, registries, guardrails, proxy (+ingest), traffic,
  repeater, intruder, traces, memory_scan, comments, notes, schedules, assets, ws,
  compliance.
- **Strip (SaaS layer):** `auth`, `orgs` (+invite), `billing`, `branding`,
  `api_keys`, `engagements` (+handshake), `security_lake`.
- **Stub:** `workspaces` → returns the single default workspace (the frontend
  workspace context still calls it).
- **Optional (env-gated, off by default — code stays, router only registers when
  the relevant env is set):** `integrations` + `github_webhooks` (paid
  GitHub/Jira/GitLab apps); `otlp_ingest` / `observability` (external OTLP backends).

## 5. Frontend design

De-auth at the choke points:

1. **`components/clerk-provider.tsx`** → plain pass-through wrapper (no
   `<ClerkProvider>`). Remove `@clerk/*` from `package.json`.
2. **`lib/api.ts`** — strip `getToken()`/`Authorization` logic; requests carry no
   bearer token. Keep `X-Workspace-Id` only if the stub is kept (hardcode default or
   drop).
3. **`lib/workspace-context.tsx`** — drop `useAuth`; user is always "signed in";
   fetch the one workspace from the stub endpoint.
4. **Delete SaaS/marketing pages:** `login`, `signup`, `onboarding`, `billing`,
   `org`, `invite`, `oauth`, `enquiries`, `company`, `solutions`, `support`,
   `terms`, `privacy`, `methodology`, `process`, `resources`; the multi-workspace
   switcher UI; and the marketing landing `app/page.tsx` (55KB) → replace with a
   redirect to `/dashboard`.
5. **Keep app pages:** dashboard, targets, scans, findings, repos, dependencies,
   sbom, advisories, asm, compliance, deliverables, schedules, traces, observability,
   search, settings (trimmed), capabilities, platform.

## 6. Infra & "it just works"

- **`docker-compose.yml`** trimmed to `postgres` (pgvector), `redis`, `api`,
  `worker`, `web`. Drop `docs`/`blog`. Keep the toolchain compose
  (`docker-compose.toolchain.yml`) for scanner tools (nmap/sqlmap/nuclei/ffuf/etc.).
- **`.env.example`** rewritten: remove Clerk/Stripe/Google OAuth; keep DB/Redis and
  one optional `LLM_API_KEY` / `LLM_BASE_URL` / `LLM_MODEL`. Keep `fernet_key`
  (still used to encrypt stored credentials) and auto-generate it on first boot if
  unset.
- **One command up:** `docker compose up` → migrations run, single tenant seeds,
  app served at `localhost:3000` with no login screen, landing on the dashboard.

## 7. AI: graceful degradation

AI features stay in the codebase but key off `LLM_API_KEY`. With no key configured:
AI panels render a "configure an LLM key to enable" state; scans and findings work
fully without them. No paid default endpoints are assumed (current defaults pointing
at together.xyz / deepseek / sarvam / ollama are removed from defaults).

## 8. Testing & verification

- **Backend shim test** — unauthenticated requests to representative kept routers
  (targets, scans, findings) succeed and resolve to the seeded tenant; stripped
  routers return 404.
- **Smoke script** — `docker compose up`, wait for health, hit `/dashboard` and a
  scan-create endpoint with no token, assert 200.
- Retain existing test suites for kept routers; delete tests for stripped modules.

## 9. Implementation phasing

The implementation plan will be phased; each phase is independently verifiable.

1. **Phase 1** — create `pencheff-ce/` repo (copy + fresh git); backend shim
   (`single_tenant.py`, deps rewrite, seed-on-boot); delete dead auth code.
2. **Phase 2** — strip/stub/gate backend routers per §4.2; update `main.py`
   registration; prune `config.py`.
3. **Phase 3** — frontend de-auth (provider, `lib/api.ts`, workspace context);
   cull SaaS/marketing pages; landing redirect.
4. **Phase 4** — infra: trim `docker-compose.yml`, rewrite `.env.example`,
   first-boot key generation, one-command-up.
5. **Phase 5** — AI-optional behavior + tests (shim test, smoke script);
   docs/README/LICENSE/NOTICE.

## 10. Out of scope / explicit non-goals

- Re-introducing any account/login/RBAC concept.
- Multi-tenant operation (single tenant only).
- Paid integrations (GitHub App, Jira, GitLab CI, Stripe, AWS Security Lake) as
  shipped/enabled defaults.
- Dropping the vestigial tenant columns from the schema (deferred; not required).
