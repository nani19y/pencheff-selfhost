# Tasks: Multi-Target Scan Pipelines

**Feature:** `001-multi-target-scan-pipelines`
**Status:** Draft (Phase 6 — pending GATE 3 audit)
**Based on:** `spec.md` v2 + `plan.md`
**Tracking:** `.sdd/sdd-state.md`

This file is consumed by future `/sdd-team implement` invocations (one per milestone). Each milestone gets its own implementation team (quality-lead / backend-lead / frontend-lead). Tasks follow TDD: RED (failing tests) → GREEN (implement) → VERIFY → E2E. Per the SDD-team known constraint, only one team per session — each milestone is a separate session.

---

## Task ID convention

`M{milestone}-US{story}-T{taskNum}` — e.g., `M1-US0-T01`.

Tasks within a story follow this canonical TDD ordering:
- **T01** quality-lead: failing unit tests
- **T02** quality-lead: failing integration tests
- **T03** frontend-lead: UI components (blocked by T01)
- **T04** frontend-lead: client-side state + form logic (blocked by T01)
- **T05** backend-lead: API routes + server actions (blocked by T01)
- **T06** backend-lead: DB schema + migrations + ORM changes (blocked by T01)
- **T07** quality-lead: run unit + integration tests; mark PASS (blocked by T03,T04,T05,T06)
- **T08** quality-lead: E2E verification against fixture target (blocked by T07)

US-0 has only backend + tooling + tests (no FE), so frontend-lead tasks are absent.

---

## M1 — Framework + web_app + source_code + k8s_cluster

Estimated: 6 weeks dev wall-clock, ~6,000–8,000 LOC. Critical path runs through US-0 (framework) which blocks every other story.

### US-0: Framework (P1, blocks M1-US1, M1-US6, M1-US12)

| Task | Owner | Files | Verification |
|------|-------|-------|--------------|
| M1-US0-T01 | quality-lead | `apps/api/tests/services/test_dispatch_mode_kind_aware.py` (NEW); `apps/api/tests/schemas/test_kind_config_validators.py` (NEW); `apps/api/tests/services/agent_swarm/test_breakers_kind_filter.py` (NEW); `apps/api/tests/services/agent_swarm/test_artifact_orchestrator.py` (NEW); `apps/api/tests/services/agent_swarm/test_hybrid_orchestrator.py` (NEW); `apps/api/tests/services/test_agent_runner_dangerous_args_extended.py` (NEW) | All tests FAIL initially. Covers dispatch_mode branches, KindConfig/KindPayload/KindCredentials Pydantic validators incl. `extra="forbid"`, `_validate_kind_config` cross-kind rejection, breaker-roster filter, RBAC on `force_deterministic_only`, FallbackController sentinel row, extended `_DANGEROUS_ARG_SUBSTRINGS`. |
| M1-US0-T02 | quality-lead | `apps/api/tests/integration/test_scan_kind_aware_routing.py` (NEW); `apps/api/tests/integration/test_kubeconfig_lifecycle.py` (NEW); `apps/api/tests/integration/test_fallback_engagement.py` (NEW); `apps/api/tests/integration/test_legacy_url_repo_llm_unchanged.py` (NEW) | Integration tests FAIL initially. Covers: scan_runner branches correctly per `target.kind`; kubeconfig materialized to `/tmp/<scan_id>/.kube/config` mode 0600 + unlinked; FallbackController row inserted with correct reason on each fallback trigger; legacy url/repo/llm scans produce identical findings count vs pre-feature baseline. |
| M1-US0-T05 | backend-lead | `apps/api/pencheff_api/db/migrations/versions/0044_multi_kind_pipelines.py` (NEW); `apps/api/pencheff_api/db/migrations/versions/0045_integrations_kinds.py` (NEW); `apps/api/pencheff_api/db/models.py` (MODIFY: Target/Scan/Org); `apps/api/pencheff_api/schemas/targets.py` (MODIFY: TargetKind Literal extension + KindConfig + KindCredentials unions + `_validate_kind_config`); `apps/api/pencheff_api/schemas/scans.py` (MODIFY: ScanCreate.kind_payload + KindPayload union + KIND_REQUIRED_DISCLOSED_ACTIONS); `apps/api/pencheff_api/routers/targets.py` (MODIFY: accept kind_config + kind_credentials + has_kind_credentials in TargetOut); `apps/api/pencheff_api/routers/scans.py` (MODIFY: validate kind_payload + enforce consent actions); `apps/api/pencheff_api/routers/orgs.py` (MODIFY: RBAC on force_deterministic_only + audit row); `apps/api/pencheff_api/services/credentials.py` (MODIFY: Fernet encrypt/decrypt for kind_credentials); `apps/api/pencheff_api/services/dispatch_mode.py` (MODIFY: target_kind arg + org-flag check + new-primary preference); `apps/api/pencheff_api/services/scan_runner.py` (MODIFY: _run_kind_aware_scan branch + _synthesize_kind_payload helper); `apps/api/pencheff_api/services/agent_swarm/agent_loop.py` (MODIFY: _primary_backend/_fallback_backend body swap + WARNING log); `apps/api/pencheff_api/services/agent_swarm/breakers.py` (MODIFY: KIND_TO_BREAKER_NAMES + _build_breakers(kind=…) + new BreakerSpecs: K8sReconAgent, RbacEnumAgent, ArtifactReconAgent, ScannerOrchestratorAgent, K8sManifestAuditAgent); `apps/api/pencheff_api/services/agent_swarm/tools.py` (MODIFY: BREAKER_TOOL_ALLOCATIONS extended); `apps/api/pencheff_api/services/agent_swarm/artifact_orchestrator.py` (NEW: run_artifact_orchestrator); `apps/api/pencheff_api/services/agent_swarm/hybrid_orchestrator.py` (NEW: run_hybrid_orchestrator + Phase A + Phase B); `apps/api/pencheff_api/services/agent_runner.py` (MODIFY: extend `_DANGEROUS_ARG_SUBSTRINGS` + new artifact-acquisition tool handlers with allowlist enforcement); `apps/api/pencheff_api/services/integration_dispatch.py` (MODIFY: filter by `Integration.kinds`); `apps/api/pencheff_api/config.py` (MODIFY: add `fallback_threshold_failed_breakers` config); `plugins/pencheff/pencheff/server.py` (MODIFY: add new MCP tool entries: `clone_repo`, `pull_image`, `download_artifact`, `parse_sbom`, `copy_from_session`, source_code SAST wrappers, k8s tools) | Migration runs cleanly on staging DB. All model changes pass Pydantic validation. `_validate_kind_config` rejects mismatched kinds. dispatch_mode kind-aware branches pass T01 tests. Artifact + hybrid orchestrators full implementations pass T02 tests. RBAC enforced on `force_deterministic_only`. |
| M1-US0-T06 | backend-lead | (subset of T05 — DB schema changes only — listed here as a separate task because GRANT/index review may happen out-of-band before migrations land) | Migration `0044` revises `0043`; migration `0045` revises `0044`. Both `op.add_column` only (no constraint additions). Downgrade paths tested. |
| M1-US0-T07 | quality-lead | (no new files; runs CI) | All unit + integration tests from T01/T02 PASS after T05/T06 implementations. CI green. Existing test suite (regression) green. |
| M1-US0-T08 | quality-lead | `tests/e2e/framework/test_kind_aware_smoke.py` (NEW) | E2E smoke: create one target per cluster, trigger one scan per kind, confirm all complete with `Scan.status="done"` (or `RepoScan.status="succeeded"` for source_code) within 5 min. Confirms no regression on url/repo/llm. |

### US-1: web_app (P1, blocked by US-0)

| Task | Owner | Files | Verification |
|------|-------|-------|--------------|
| M1-US1-T01 | quality-lead | `apps/api/tests/services/agent_swarm/test_breakers_web_app_roster.py` (NEW); `apps/web/__tests__/components/register-target/web-app-form-section.test.tsx` (NEW) | Tests FAIL: breaker filter for `kind="web_app"` returns exactly 9 breakers; FE form section renders all required fields, validates input. |
| M1-US1-T02 | quality-lead | `apps/api/tests/integration/test_web_app_scan_end_to_end.py` (NEW) | Integration test FAILS: register web_app target with crawl_depth=3 + credentials; trigger scan; verify swarm log includes "kind=web_app breakers=…"; confirm ≥1 finding emitted. |
| M1-US1-T03 | frontend-lead | `apps/web/components/register-target/web-app-form-section.tsx` (NEW); `apps/web/components/register-target/target-types.ts` (MODIFY: `web-app` card's `kind` field flips from `"url"` → `"web_app"`); `apps/web/lib/types.ts` (MODIFY: extend `SupportedKind` union — shared file, lead-coordinated) | Section component renders all WebAppConfig fields with conditional validation. Matches design pattern from `url-form-section.tsx`. Brutal UI primitives reused. |
| M1-US1-T04 | frontend-lead | `apps/web/app/targets/new/page.tsx` (MODIFY: wire web-app section); `apps/web/app/targets/[id]/page.tsx` (MODIFY: add KindConfigView switch for `web_app`); `apps/web/app/targets/[id]/edit/page.tsx` (MODIFY: import web-app section with edit-mode prop); `apps/web/app/targets/page.tsx` (MODIFY: badge map entry for `web_app`) | Submit flow POSTs to `/targets` with `kind="web_app"`, `kind_config={kind:"web_app", crawl_depth, …}`. Detail page renders config `<dl>`. Edit page round-trips. List page shows `WEB APP` TypeBadge + `DAST` coverage badge. |
| M1-US1-T05 | backend-lead | (verifies T05/T06 of US-0 properly cover web_app routing) — typically no separate code change since US-0 handles framework | Confirms POST `/scans` for `kind="web_app"` routes to `_run_kind_aware_scan` → `_run_dast_scan` correctly. |
| M1-US1-T06 | backend-lead | (no new DB changes) | — |
| M1-US1-T07 | quality-lead | (CI) | T01/T02 tests PASS. |
| M1-US1-T08 | quality-lead | `tests/e2e/web_app/test_dvwa_scan.py` (NEW) | E2E against DVWA fixture: scan completes; produces ≥3 findings; breaker log emits the filtered 9-agent roster. |

### US-6: source_code (P1, blocked by US-0)

| Task | Owner | Files | Verification |
|------|-------|-------|--------------|
| M1-US6-T01 | quality-lead | `apps/api/tests/services/agent_swarm/test_scanner_orchestrator_agent.py` (NEW); `apps/api/tests/tasks/test_repo_scan_task_source_code_branch.py` (NEW); `apps/web/__tests__/components/register-target/source-code-form-section.test.tsx` (NEW) | Tests FAIL: ScannerOrchestratorAgent selects scanners based on detected languages; repo_scan_task branches to artifact_orchestrator when `kind="source_code"`; FE source-type radio renders + conditional repo_url field. |
| M1-US6-T02 | quality-lead | `apps/api/tests/integration/test_source_code_scan_multi_language.py` (NEW); `apps/api/tests/integration/test_source_code_clone_repo_allowlist.py` (NEW) | Integration tests FAIL: source_code scan on multi-lang fixture repo runs only language-relevant scanners; `clone_repo` with off-allowlist URL is rejected without subprocess. |
| M1-US6-T03 | frontend-lead | `apps/web/components/register-target/source-code-form-section.tsx` (NEW); `apps/web/components/register-target/target-types.ts` (MODIFY: `source-code-repo` card's `kind` → `"source_code"`) | Section renders all SourceCodeConfig fields with conditional repo_url (when source ∈ {github_url, tarball_url}); github_app option triggers GitHub App install widget. |
| M1-US6-T04 | frontend-lead | `apps/web/app/targets/new/page.tsx`, `[id]/page.tsx`, `[id]/edit/page.tsx`, `apps/web/app/targets/page.tsx` (badge map: `source_code` → SAST+SCA+SECRETS) | Submit POSTs to `/repos/github` or `/targets` per source type. Detail page renders SourceCodeConfig `<dl>`. List badge displays correctly. |
| M1-US6-T05 | backend-lead | `apps/api/pencheff_api/tasks/repo_scan_task.py` (MODIFY: branch to `run_artifact_orchestrator` when `target.kind == "source_code"`); `apps/api/pencheff_api/services/agent_swarm/artifact_orchestrator.py` (MODIFY: ScannerOrchestratorAgent system prompt + language-detection logic + per-kind scanner allowlist); `plugins/pencheff/pencheff/server.py` (MODIFY: ensure source_code SAST wrappers `run_semgrep`, `run_bandit`, `run_gosec`, `run_brakeman`, `run_eslint`, `run_gitleaks`, `run_yara`, `run_osv_scanner` exist as agent-callable tools with allowlist) | repo_scan_task routes `kind="source_code"` to orchestrator; scanner allowlist enforced; OWASP tagging applied to findings. |
| M1-US6-T06 | backend-lead | (no new DB changes) | — |
| M1-US6-T07 | quality-lead | (CI) | T01/T02 tests PASS. |
| M1-US6-T08 | quality-lead | `tests/e2e/source_code/test_multi_lang_fixture.py` (NEW) | E2E against multi-language fixture repo (Python + Go + JS) — scan completes; produces findings; agent tool-call log shows correct scanner selection. |

### US-12: k8s_cluster (P3 but in M1 to validate hybrid pipeline, blocked by US-0)

| Task | Owner | Files | Verification |
|------|-------|-------|--------------|
| M1-US12-T01 | quality-lead | `apps/api/tests/services/agent_swarm/test_hybrid_phase_a_only.py` (NEW); `apps/api/tests/services/agent_swarm/test_k8s_recon_agent.py` (NEW); `apps/api/tests/integration/test_kubeconfig_redaction.py` (NEW); `apps/web/__tests__/components/register-target/k8s-cluster-form-section.test.tsx` (NEW) | Tests FAIL: hybrid_orchestrator runs Phase A only when no creds; K8sReconAgent enumerates namespaces from manifests; kubeconfig redacted from scan_llm_traces.request_messages; FE form section conditional rendering passes. |
| M1-US12-T02 | quality-lead | `apps/api/tests/integration/test_k8s_cluster_manifests_only_scan.py` (NEW); `apps/api/tests/integration/test_k8s_cluster_live_scan_mock.py` (NEW) | Integration tests FAIL: manifests-only scan runs checkov + trivy K8s mode; live cluster (mock kubeconfig) hits Phase B; FallbackController fires when `force_deterministic_only=true`. |
| M1-US12-T03 | frontend-lead | `apps/web/components/register-target/k8s-cluster-form-section.tsx` (NEW); `apps/web/components/register-target/target-types.ts` (MODIFY: `kubernetes` card → `kind="k8s_cluster"`) | Section renders target radio; conditional kubeconfig textarea or manifests_archive_url; namespaces list; rbac_enum + network_policy_audit toggles. Brutal UI primitives + Label htmlFor + role attributes. |
| M1-US12-T04 | frontend-lead | `apps/web/app/targets/new/page.tsx`, `[id]/page.tsx`, `[id]/edit/page.tsx`, `targets/page.tsx` (badge map: `k8s_cluster` → K8S) | Submit POSTs `kind="k8s_cluster"` + kind_config + kind_credentials (if live_cluster). Detail page renders config + credentials presence badge. |
| M1-US12-T05 | backend-lead | `apps/api/pencheff_api/services/agent_swarm/hybrid_orchestrator.py` (MODIFY: K8sManifestAuditAgent + K8sReconAgent + RbacEnumAgent prompts); `plugins/pencheff/pencheff/server.py` (MODIFY: add `run_checkov`, `run_trivy_k8s_config`, `run_kubectl_get`, `run_kubectl_describe`, `run_rakkess` tool wrappers); `apps/api/pencheff_api/services/scan_runner.py` (MODIFY: kubeconfig tempfile lifecycle in `try/finally`) | Hybrid orchestrator routes correctly; kubeconfig mode 0600; redaction filter applied; agents tag findings with OWASP categories (A05 Misconfig, A01 Access Control). |
| M1-US12-T06 | backend-lead | (no new DB changes) | — |
| M1-US12-T07 | quality-lead | (CI) | T01/T02 tests PASS. |
| M1-US12-T08 | quality-lead | `tests/e2e/k8s_cluster/test_vulnerable_helm_chart.py` (NEW); `tests/e2e/k8s_cluster/test_kubeconfig_lifecycle.py` (NEW) | E2E against vulnerable Helm chart fixture: scan flags ≥1 critical (e.g., privileged container, hostNetwork=true). E2E kubeconfig lifecycle: tempfile created mode 0600, unlinked after scan, no traces in scan_llm_traces. |

**M1 PR readiness checklist:**
- [ ] All 28 M1 tasks (US-0×6 + US-1×7 + US-6×7 + US-12×8) marked completed
- [ ] CI green; regression suite green
- [ ] Migration 0044 + 0045 round-trip tested on staging
- [ ] Canary scan on staging confirms all 4 stories produce expected findings
- [ ] `Org.force_deterministic_only=true` confirmed working via canary
- [ ] AGENT_FALLBACK_LLM_* swap default-fallback to AGENT_LLM_* verified
- [ ] PR description includes a "M1 acceptance" matrix mapping each AC to its test

---

## M2 — rest_api + container_image + iac + cicd_pipeline

Estimated: 4 weeks dev wall-clock, ~3,500–5,000 LOC. Reuses M1 framework patterns.

### US-2: rest_api (P1)

Same 8-task TDD shape. Highlights:
- M2-US2-T01: unit tests for breaker filter producing 6 breakers; FE form section for `rest_api` (api_spec paste/upload + format radio + auth_in_spec toggle).
- M2-US2-T05: backend wires `recon_api_discovery` to import the operator-supplied OpenAPI spec into the pencheff session before breaker fan-out.
- M2-US2-T08: E2E against a known-vulnerable REST fixture.

### US-7: container_image (P2)

- M2-US7-T01: ScannerOrchestratorAgent allowlist test for `{run_trivy_image, run_syft, run_grype, run_hadolint, run_trivy_secrets}` only.
- M2-US7-T02: integration test that `pull_image` calls `skopeo copy docker://...` not `docker pull` (mock subprocess).
- M2-US7-T05: backend wires `pull_image` handler with skopeo + OCI layout; offline-mode trivy invocation.
- M2-US7-T08: E2E against `alpine:3.10` — confirm ≥3 CVE findings.

### US-8: iac (P2)

- M2-US8-T01: framework-conditional scanner selection (terraform→tfsec; helm→checkov; etc.)
- M2-US8-T05: scanner argument allowlist for checkov `--external-checks-dir` rejection.
- M2-US8-T08: E2E against vulnerable Terraform fixture.

### US-11: cicd_pipeline (P3, closes hybrid cluster)

- M2-US11-T01: CicdConfigAuditAgent BreakerSpec + scanner allowlist `{run_checkov, run_gitleaks, run_yara}`.
- M2-US11-T02: Phase B (live CI API) only when `live_api_enabled=true` AND `kind_credentials` present.
- M2-US11-T05: GitHub Actions REST API integration; GitLab CI; Jenkins REST.
- M2-US11-T08: E2E against a fixture repo with a `pull_request_target` + actions/checkout-with-PR-ref vulnerable workflow.

**M2 PR readiness checklist:** same shape as M1; no new migrations.

---

## M3 — graphql + websocket + grpc + package_registry + sbom

Estimated: 3 weeks dev wall-clock, ~2,500–3,500 LOC. Mostly new MCP-tool wrappers + thin agent loops.

### US-3: graphql (P2)

- M3-US3-T01: GraphQLFuzzAgent BreakerSpec test; tool allowlist `{run_graphql_cop, run_inql, scan_api}`.
- M3-US3-T05: backend wires `run_graphql_cop` + `run_inql` as MCP tools; introspection-conditional schema_sdl fallback.
- M3-US3-T08: E2E against damn-vulnerable-graphql.

### US-4: websocket (P2)

- M3-US4-T01: websocket subprotocol negotiation + binary frame fuzzing in `scan_websocket`.
- M3-US4-T05: extend existing `scan_websocket` MCP tool with binary-frame support.
- M3-US4-T08: E2E against vulnerable WS server fixture.

### US-5: grpc (P3)

- M3-US5-T01: GrpcReflectionAgent + tool allowlist `{run_grpcurl, parse_proto, scan_api}`.
- M3-US5-T02: dangerous-arg test — `grpcurl --plaintext` and `--import-path` rejected.
- M3-US5-T05: backend wires `run_grpcurl` + `parse_proto` as MCP tools.
- M3-US5-T08: E2E against gRPC reflection-enabled fixture.

### US-9: package_registry (P3)

- M3-US9-T01: per-ecosystem dispatch (npm/pip/maven/cargo/gem/composer/go/nuget).
- M3-US9-T05: backend wires `run_npm_audit`, `run_pip_audit` MCP tools; existing `run_osv_scanner` reused.
- M3-US9-T08: E2E against vulnerable npm package list.

### US-10: sbom (P3)

- M3-US10-T01: 16 MiB content cap test; format validation.
- M3-US10-T05: backend wires `run_grype_sbom`, `run_osv_scanner_sbom`; CycloneDX/SPDX parser.
- M3-US10-T08: E2E uploading a CycloneDX SBOM with known-vuln components.

**M3 PR readiness checklist:** same shape; no new migrations.

---

## Cross-milestone tasks (run once)

| Task | Owner | When | Files | Verification |
|------|-------|------|-------|--------------|
| Bump VERSION + CHANGELOG | LEAD | End of M3 | `VERSION`, `CHANGELOG.md`, `apps/api/pencheff_api/__init__.py`, `apps/web/package.json` | Major-version bump (e.g., 1.0 → 2.0) reflecting expanded target taxonomy. CHANGELOG documents the 12 new kinds + the AGENT_FALLBACK_LLM_* primary swap + the org-level kill switch. |
| Update README + AGENTS.md | LEAD | End of M3 | `README.md`, `AGENTS.md` | Document new target kinds in feature matrix; document new env vars (`AGENT_FALLBACK_LLM_*` becomes primary); document `force_deterministic_only` for self-hosted operators. |
| Refresh `.env.example` | backend-lead | End of M1 | `.env.example` | Reorder so `AGENT_FALLBACK_LLM_*` block appears first with comments explaining the swap; preserve `AGENT_LLM_*` block as fallback. |
| Documentation page per kind | docs (deferred) | After M1 ships | `docs/scan-types/<kind>.md` (NEW per kind) | Each new kind gets a user-facing doc page explaining what it scans, what creds it needs, what limitations apply. |

---

## Dependency graph

```
M1-US0 ──┬─→ M1-US1 ──→ (US-1 acceptance)
         ├─→ M1-US6 ──→ (US-6 acceptance)
         └─→ M1-US12 ─→ (US-12 acceptance) ──→ M1 PR

M1 PR ──→ M2 (any order among US-2, US-7, US-8, US-11) ──→ M2 PR

M2 PR ──→ M3 (any order among US-3, US-4, US-5, US-9, US-10) ──→ M3 PR + cross-cutting

Within each US, T01+T02 are independent; T03+T04 block on T01; T05+T06 block on T01; T07 blocks on T03+T04+T05+T06; T08 blocks on T07.
```

---

## Total task count

- M1: 28 tasks (US-0: 6, US-1: 7, US-6: 7, US-12: 8)
- M2: 32 tasks (4 stories × 8)
- M3: 40 tasks (5 stories × 8)
- Cross-milestone: 4 tasks
- **Total: 104 tasks**

Across 3 milestones, each implementation team carries ~35 tasks. Per the implementation-team workflow, each story moves through RED → GREEN → VERIFY → E2E before the next story begins; this keeps the dependency graph linear within each milestone.

---

## Notes for implementation-team session

When a future `/sdd-team implement` session opens this file:
1. Read `.sdd/sdd-state.md` to identify which milestone is next.
2. Spawn team `sdd-impl-001-multi-target-scan-pipelines-M{N}`.
3. Create tasks per the story table above for the target milestone.
4. Spawn quality-lead / backend-lead / frontend-lead teammates with spawn-prompts from `~/.claude/skills/sdd-team/workflows/spawn-prompts/`.
5. Assign per the Owner column.
6. Coordinate file-ownership boundaries per `plan.md §3`.
7. Walk through each story RED → GREEN → VERIFY → E2E.
8. Commit per story with message `feat(multi-kind): implement US-{N} - {story title}`.
9. On milestone completion, run M{N} PR readiness checklist; open PR.
