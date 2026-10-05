# Pencheff CE ↔ Pencheff Reconciliation

**Date:** 2026-08-14
**Goal:** Close the drift between `pencheff` (full, AGPL-3.0) and `pencheff-ce` (Community Edition, Apache-2.0) **once**, per the user's decisions:

- **Scope:** sync all shared-code drift **and** port net-new _in-scope product surface_ (new target kinds / scanners / product docs) with the single-tenant shim applied. **Preserve every intentional SaaS strip.**
- **Durability:** one-time reconciliation. No sync tooling.

Source of truth for the strip boundary: `pencheff/docs/superpowers/specs/2026-06-23-pencheff-ce-community-edition-design.md` (§4.2 keep/strip/stub, §5 frontend, §10 non-goals).

CE was seeded from an upstream snapshot on 2026-06-23 (`d423e73`); histories are unrelated, so this is a **file-level merge**, not a git merge. CE is ~2.5 weeks behind (`1b45e5f`, 2026-07-28).

## Baseline (CE `apps/api`, before any change)

`uv run pytest -q` → **921 passed, 10 failed, 1 skipped**. The 10 failures are presumed drift symptoms; reconciliation should turn them green.

Pre-existing failures:

- `tests/services/agent_swarm/test_orchestrator_happy.py` (1)
- `tests/services/agent_swarm/test_scope.py` (1)
- `tests/services/agent_swarm/test_seed_breaker_session.py` (3)
- `tests/test_artifact_orchestrator.py::test_args_package_registry_ecosystem_gating` (1)
- `tests/test_plan_limits.py::test_every_plan_has_unlimited_non_ai_capacity[*]` (4)

## The three buckets

### A. LEAVE — intentional SaaS strip (must NOT enter the Apache-2.0 repo)

Auth (Clerk/JWT/password/OAuth/api-key), orgs, billing + Razorpay + credits, branding,
engagements, security-lake (+ BYO dest), org-domains/SSO, campaigns (+ impact engine),
support portal, audit-export, RBAC permissions/scopes, the MCP↔webapp auth bridge
(`server_webapp.py`, `webapp_client.py`, `webapp_sync.py`, `mcp_auth.py`, `Dockerfile.mcp`),
and all matching migrations/schemas/tests/web-pages. Corresponding marketing pages
(login, signup, onboarding, billing, org, invite, oauth, enquiries, company, solutions,
support, terms, privacy, methodology, process, resources).

### B. SYNC — shared files that drifted (~290 files, careful per-file, test-gated)

The engine + shared services + product web/docs/bench/tools that exist in both repos but
diverged. **Not a blind copy:** upstream wove SaaS calls (credit gates, billing checks)
into some shared paths; each synced file must be checked for imports of bucket-A modules
and de-coupled to keep CE importable. Top areas:
`plugins/pencheff` engine (58), `apps/api/pencheff_api` services/routers (58),
`apps/docs/pages` (28), `apps/web/components` (24), `bench/runners` (18),
`apps/web/app` (17), `apps/web/lib` (10), `plugins/sentry` (11), `tools` (4).

**Shim-sensitive (never blind-copy — selective merge, keep de-auth):**
`config.py`, `main.py`, `db/models.py`, `auth/deps.py`, `events.py`, `middleware/audit.py`,
`lib/api.ts`, `lib/workspace-context.tsx`, `components/clerk-provider.tsx`, and the four
`package.json`. **Never touch (CE identity):** `LICENSE`, `NOTICE`, `README.md`,
`CHANGELOG.md`, `CONTRIBUTING.md`, `DEPLOYMENT.md`, `docker-compose.yml`, `.env.example`.

### C. PORT — net-new in-scope product surface (add to CE, minus SaaS wiring)

- **Engine modules:** `modules/client/` (client-artifact), `voice_scan/{tts_probes,voice_payloads}.py`, `llm_red_team/runner.py`; new target kinds gRPC/WebSocket; their tests.
- **API:** `scan_categories.py`, agent-swarm `host_/identity_data_/network_orchestrator.py` + `trace.py`, `compliance.py` (router+service), `uploads.py` + `upload_storage.py`, `ai_scan_progress.py`, `finding_validation.py` + `validate_task.py`, `health.py`, `repo_link.py`, `scan_dispatch.py`, BYO-LLM `bedrock.py`/`vertex.py`/`cloud_auth.py`, migrations `0063_agent_target_kind`, `0069_widen_target_kind`, `0071_finding_hackable`, and their product tests.
- **Web:** `app/compliance`, scan/repo `compliance` subpages, `register-target/*-form-section.tsx` (agent, client-artifact, mobile-app, network-identity), `load-metric-cell.tsx`, `mcp-fallback-note.tsx`, `disciplines.png`, `logo-mark.png`.
- **Docs:** feature pages (ai-target-scanning, browser-extension, desktop-app, firmware-iot, mcp) + tutorials (android/ios/firmware/iot/desktop/browser-extension scanning).

## Judgment calls (my default → override if you disagree)

| Item                                                                       | Default   | Why                                                      |
| -------------------------------------------------------------------------- | --------- | -------------------------------------------------------- |
| Campaign **impact engine** (`services/impact/`, `test_impact_*`)           | **LEAVE** | Tied to campaigns (stripped)                             |
| **Load testing** (`services/load_test/`, k6, `test_load_*`)                | **LEAVE** | Not in CE's advertised capability surface                |
| Per-worker **Dockerfile split** (`Dockerfile.ai_llm` … `build-workers.sh`) | **LEAVE** | CE ships a single-worker compose; keep its simpler infra |
| RBAC `auth/permissions.py`, `scopes.py`                                    | **LEAVE** | §10 explicit non-goal                                    |
| BYO **Bedrock/Vertex** LLM                                                 | **PORT**  | Fits CE "bring your own AI"                              |
| **compliance**, **uploads**                                                | **PORT**  | §4.2 keep; uploads enables mobile/client artifact scans  |

## Phases (each ends green: `uv run pytest -q` in `apps/api`, plus plugin tests)

1. **Engine drift** — sync `plugins/pencheff` scanner modules + `plugins/sentry` + `bench` + `tools` (no tenancy coupling). Verify plugin tests.
2. **Shared API drift** — sync `apps/api` services/routers/schemas that exist in both, de-coupling any bucket-A imports. Verify api tests.
3. **Shim-sensitive merge** — selectively merge `config.py`, `main.py`, `models.py`, `deps.py`, `events.py`, `audit.py`, web shim files + `package.json`. Verify.
4. **Port product features** — bucket C, applying the single-tenant shim (no auth/scope/billing wiring); register new product routers in `main.py`. Verify.
5. **Web + docs** — sync web components/pages + product docs. Build check.
6. **Final** — full test suite green (target: 0 failures), `scripts/smoke.sh`, changelog note. Commit per phase.

## Results (2026-08-14)

Done on branch `ce-reconcile-2026-08-14` (2 commits; not pushed — review + merge to main).

| Layer                                         | Result                              | vs baseline                                                                    |
| --------------------------------------------- | ----------------------------------- | ------------------------------------------------------------------------------ |
| Engine (`plugins/pencheff`, `plugins/sentry`) | **571 passed / 4 failed**           | 84 files synced + 4 product modules + 3 MCP tools (desktop/extension/firmware) |
| API (`apps/api`)                              | **938 passed / 14 failed**          | 58 synced + 11 tests + 21 product modules/migrations; from 921/10 baseline     |
| Web (`apps/web`)                              | **`tsc --noEmit` clean**            | 64 synced + product components/pages; +fflate, +apiUpload                      |
| Docs                                          | 30 synced + 12 new target-kind docs | —                                                                              |

**All residual failures (18) fail identically in upstream `pencheff`** — integration tests
needing a live Postgres/docker, plus stale `max_tokens`/cve-feed asserts. They are not
CE-vs-pencheff gaps.

**SaaS strip held.** Full-tree import sweep is clean. Leaks caught and reversed during the
merge: `ai_gate`, `observability`(+retention), `ws.py`, 4 security-lake files, `workspaces`
stub, `nav`/`landing-nav`/`settings`/`observability-audit` web files reverted to CE versions;
4 function-local `credits` gates neutralized; `EnterpriseGuard` paywall dropped from compliance.

**Deliberately excluded** (SaaS or per judgment call): billing/Razorpay/credits, auth/Clerk/SSO,
orgs, campaigns + impact engine, support portal, security-lake BYO, audit-export, RBAC
permissions/scopes, load-test service/k6, per-worker Dockerfiles, MCP↔webapp bridge
(`server_webapp`/`webapp_client`/`webapp_sync`/`mcp_auth`) + its `scan_repository`/`scan_package_registry` tools.

**Migrations:** alembic chain re-linked `0062→0063→0069→0071` (skipping SaaS `0064–0068`, `0070`);
models.py gained `Target.kind` widening (16→32) + `Finding.hackable`, no SaaS tables.

**Not durable** (per decision): no sync tooling — the drift will re-open on the next upstream release.
