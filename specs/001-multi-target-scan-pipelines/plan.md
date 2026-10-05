# Plan: Multi-Target Scan Pipelines

**Feature:** `001-multi-target-scan-pipelines`
**Status:** Draft (Phase 5 — pending GATE 3 audit)
**Based on:** `specs/001-multi-target-scan-pipelines/spec.md` v2 (GATE 2 PASS post-revision)
**Tracking:** `.sdd/sdd-state.md`

---

## 1. Milestone Composition

The 13 user stories cluster into three pipeline shapes. Per advisor recommendation, **M1 takes one kind from each cluster** so all three pipeline-shape patterns harden before M2 expands within each. This trades a tighter initial scope for cluster validation.

| Milestone | Stories | Cluster(s) | Rationale |
|-----------|---------|------------|-----------|
| **M1** | US-0 (framework) + US-1 (web_app) + US-6 (source_code) + US-12 (k8s_cluster) | DAST + Artifact + Hybrid | Validate all three pipeline shapes simultaneously. web_app reuses the most existing infrastructure; source_code reuses RepoScan path; k8s_cluster exercises Phase A+B and kubeconfig lifecycle. |
| **M2** | US-2 (rest_api) + US-7 (container_image) + US-8 (iac) + US-11 (cicd_pipeline) | DAST + Artifact + Hybrid | Expand within each cluster, building on M1 patterns. rest_api adds OpenAPI handling; container_image adds skopeo + image scanning; iac adds checkov/tfsec/trivy_config; cicd_pipeline closes the hybrid cluster. |
| **M3** | US-3 (graphql) + US-4 (websocket) + US-5 (grpc) + US-9 (package_registry) + US-10 (sbom) | DAST + Artifact | Tail: protocol-specific kinds needing new MCP-tool wrappers (graphql-cop, inql, grpcurl, grype-sbom). |

**Milestone size targets** (LOC est., backend+frontend combined):
- M1: ~6,000–8,000 LOC. Heaviest because framework changes plus 3 kinds.
- M2: ~3,500–5,000 LOC. Reuses M1 patterns.
- M3: ~2,500–3,500 LOC. Mostly new MCP-tool wrappers + thin agent loops.

Each milestone is **one PR** to keep review burden manageable. Three PRs total.

---

## 2. Architecture: Data Flow

### 2.1 Existing flow (preserved unchanged)

```
POST /scans   ─→ ConsentValidator ─→ ThreatModel ─→ Scan(status="queued")
              └─→ Celery: run_full_scan.delay(scan.id)
                  └─→ scan_runner.run_scan
                      ├─→ target.kind=="llm"  → _run_llm_scan (unchanged)
                      └─→ target.kind=="url"  → existing dispatch_mode + swarm (unchanged)

POST /repos/{id}/scan  ─→ RepoScan(status="queued")
                        └─→ Celery: run_repo_scan.delay(repo_scan.id)
                            └─→ repo_scan_task.run_repo_scan (static scanner fan-out)
```

### 2.2 New flow (added)

```
POST /scans   ─→ Same consent + threat-model setup
              ─→ Validate kind_payload.kind == target.kind
              ─→ Enforce KIND_REQUIRED_DISCLOSED_ACTIONS
              ─→ Scan(status="queued", kind_payload=...)
              ─→ run_full_scan.delay(scan.id)
                  └─→ scan_runner.run_scan
                      ├─→ (existing url/llm branches preserved)
                      └─→ _run_kind_aware_scan(scan, target)
                          ├─→ DAST cluster  → _run_dast_scan(kind)
                          │   └─→ agent_swarm.run_swarm + KIND_TO_BREAKER_NAMES filter
                          ├─→ Artifact     → _run_artifact_scan(kind)
                          │   └─→ artifact_orchestrator.run_artifact_orchestrator
                          │       ├─→ ArtifactReconAgent
                          │       └─→ ScannerOrchestratorAgent (per-kind tool allowlist)
                          └─→ Hybrid       → _run_hybrid_scan(kind)
                              └─→ hybrid_orchestrator.run_hybrid_orchestrator
                                  ├─→ Phase A (manifest audit, always)
                                  └─→ Phase B (live recon, if kind_credentials present)

POST /repos/{id}/scan  ─→ Same RepoScan + Celery enqueue
                        └─→ repo_scan_task.run_repo_scan
                            ├─→ target.kind == "repo"          → existing static fan-out (unchanged)
                            └─→ target.kind == "source_code"   → artifact_orchestrator.run_artifact_orchestrator
                                                                  with source_code scanner allowlist
```

### 2.3 Dispatch decision tree

```
resolve_dispatch_mode(session, org_id, target_kind):
  org.force_deterministic_only?   → "deterministic_only"   [NEW]
  _kind_supports_agent(kind)?     → continue, else "deterministic_only"  [NEW]
  agent_fallback_llm_api_key?     → continue              [CHANGED: prefer new primary]
  OR agent_llm_api_key?           → continue
  neither?                        → "deterministic_only"  [existing]
  agent_dispatch_beta_override?   → "deterministic_then_agent"
  plan ∈ {pro,team,self_hosted}?  → "deterministic_then_agent"
  free + quota_remaining?         → "deterministic_then_agent"
  else                            → "agent_only"
```

---

## 3. File Ownership Map (for implementation teammates)

Each implementation milestone uses a 3-teammate team: `quality-lead`, `backend-lead`, `frontend-lead`. File ownership prevents merge conflicts.

| Domain | Owner | File patterns |
|--------|-------|---------------|
| Frontend | frontend-lead | `apps/web/app/targets/**`, `apps/web/components/register-target/**`, `apps/web/components/brutal.tsx` (read-only), `apps/web/lib/api.ts` (additive only) |
| Backend (API + services) | backend-lead | `apps/api/pencheff_api/routers/**`, `apps/api/pencheff_api/services/**`, `apps/api/pencheff_api/schemas/**`, `apps/api/pencheff_api/db/models.py`, `apps/api/pencheff_api/db/migrations/versions/**`, `apps/api/pencheff_api/tasks/**`, `apps/api/pencheff_api/config.py` |
| MCP tools (Pencheff plugin) | backend-lead | `plugins/pencheff/pencheff/**` (new scanner wrappers) |
| Quality (tests) | quality-lead | `apps/api/tests/**`, `apps/web/__tests__/**`, `apps/web/e2e/**`, `tests/**` |
| Shared (types, package config) | LEAD ONLY | `apps/web/lib/types.ts`, `apps/api/pencheff_api/__init__.py` version, `package.json`, `pyproject.toml`, `.env.example` |

**Shared-file protocol:** teammate messages lead with type definition needed → lead creates/edits → lead notifies both teammates → teammates import.

---

## 4. Per-Milestone Plans

### 4.1 M1 — Framework + web_app + source_code + k8s_cluster

**Stories:** US-0, US-1, US-6, US-12

**Scope:**
- Alembic migration `0044_multi_kind_pipelines.py` (4 columns)
- SQLAlchemy model changes + Pydantic schemas (KindConfig + KindPayload + KindCredentials discriminated unions)
- `dispatch_mode.py` extension with `target_kind` arg + org-flag check + new-primary preference
- `agent_loop.py` `_primary_backend()`/`_fallback_backend()` body swap + WARNING log
- `agent_swarm/breakers.py` `KIND_TO_BREAKER_NAMES` dict + filter logic in `_build_breakers()`
- `agent_swarm/artifact_orchestrator.py` (NEW module) — full implementation
- `agent_swarm/hybrid_orchestrator.py` (NEW module) — full implementation
- `scan_runner.py::_run_kind_aware_scan` branch point
- Extended `_DANGEROUS_ARG_SUBSTRINGS` (8 new entries)
- 5 new artifact-acquisition tool handlers with allowlist enforcement: `clone_repo`, `pull_image` (skopeo), `download_artifact`, `parse_sbom`, `copy_from_session`
- 3 new kind-specific MCP-tool wrappers needed for M1's kinds: `run_semgrep`/`run_bandit`/`run_gosec`/`run_brakeman`/`run_eslint`/`run_gitleaks`/`run_yara`/`run_osv_scanner` (source_code), `run_kubectl_get`/`run_kubectl_describe`/`run_rakkess`/`run_checkov`/`run_trivy_k8s_config` (k8s_cluster). web_app reuses existing tools.
- Frontend: type-card kind remapping in `target-types.ts`, `SupportedKind` expansion, 3 new form sections (web-app, source-code, k8s-cluster), list-page badge map extension, detail-page renderer pattern + 3 kind renderers, edit-page integration with shared form-section components
- Consent kind-awareness (`KIND_REQUIRED_DISCLOSED_ACTIONS` map + router enforcement)
- RBAC on `Org.force_deterministic_only` toggle + `org_settings_changes` audit row
- Tests: migration round-trip, validators, dispatch_mode kind branches, allowlist enforcement, RBAC, fallback engagement, kubeconfig lifecycle, all per-story ACs

**Test pyramid for M1:**
- Unit (70%): Pydantic discriminated union validators, allowlist enforcement, `_DANGEROUS_ARG_SUBSTRINGS` entries, KIND_TO_BREAKER_NAMES lookup, consent-action coverage
- Integration (20%): dispatch_mode branches end-to-end, fallback engagement records FallbackController row, kubeconfig tempfile lifecycle, scan_runner branch point preserves url/llm/repo paths
- E2E (10%): web_app DAST against DVWA, source_code SAST against multi-language fixture repo, k8s_cluster manifests_only against known-vulnerable Helm chart

**Risks specific to M1:**
- Migration head drift if 0044 lands while another feature claims same revision → daily rebase check during M1
- AGENT_FALLBACK_LLM_* swap regression on existing url scans → CI runs the full existing scan-runner regression suite
- kubeconfig accidentally logged → unit test on redaction filter; integration test scanning SSE payload + scan_llm_traces for known sentinels (`BEGIN CERTIFICATE`, `client-key-data`)

**Definition of done for M1:**
- All M1 story ACs pass in CI
- Existing url/repo/llm scans pass with no behavior change (regression suite green)
- One canary run against staging confirms `force_deterministic_only=true` produces a clean fallback scan with `FallbackController` trace row
- M1 PR merged + deployed; canary scan completes within 2× existing url-scan SLA

### 4.2 M2 — rest_api + container_image + iac + cicd_pipeline

**Stories:** US-2, US-7, US-8, US-11

**Scope:**
- M1 framework reused as-is (no framework changes)
- 4 new kind-specific scanner wrappers: `run_trivy_image`, `run_syft`, `run_grype`, `run_hadolint`, `run_trivy_secrets`, `run_checkov` (already in M1), `run_trivy_config`, `run_tfsec`, `run_gitleaks` (existing reused)
- rest_api: OpenAPI/Swagger spec import flow in `recon_api_discovery` handler
- container_image: skopeo wrapper hardening (OCI layout, offline scanning)
- iac: framework-conditional scanner selection (terraform→tfsec; helm→checkov; etc.)
- cicd_pipeline: `CicdConfigAuditAgent` BreakerSpec + Phase B CI-API integrations (GitHub Actions, GitLab CI, Jenkins REST)
- Frontend: 4 new form sections, badge map extension, detail-page renderers, edit-page integration

**Test pyramid:**
- Unit: per-kind config validators, scanner argument allowlists, CicdConfigAuditAgent config parsing
- Integration: container_image pull via skopeo (mock the registry), iac framework selection, cicd_pipeline Phase A vs A+B branching
- E2E: rest_api against a known-vulnerable API fixture, container_image scan of `alpine:3.10`, iac scan against vulnerable terraform fixture, cicd_pipeline against a fixture repo with malicious workflow

**Definition of done for M2:** Same shape as M1 — ACs pass, regressions clean, canary green.

### 4.3 M3 — graphql + websocket + grpc + package_registry + sbom

**Stories:** US-3, US-4, US-5, US-9, US-10

**Scope:**
- 5 new BreakerSpecs: `GraphQLFuzzAgent`, `GrpcReflectionAgent` (DAST cluster); `ScannerOrchestratorAgent` adaptations for package_registry + sbom
- New MCP tools: `run_graphql_cop`, `run_inql`, `run_grpcurl`, `parse_proto`, `run_npm_audit`, `run_pip_audit`, `run_grype_sbom`, `run_osv_scanner_sbom`
- Extended `_DANGEROUS_ARG_SUBSTRINGS` for grpcurl (`--plaintext`, `--import-path` — already in M1's spec but verify M3 enables them in the tool wrapper)
- websocket: subprotocol negotiation + binary frame fuzzing in existing `scan_websocket`
- sbom: 16 MiB content cap enforcement + CycloneDX/SPDX parser
- package_registry: per-ecosystem dispatch (npm-audit / pip-audit / etc.)
- Frontend: 5 new form sections, badge map extension, file-upload UX for SBOM/package-list, detail-page renderers, edit-page integration

**Test pyramid:**
- Unit: per-ecosystem scanner selection, SBOM size cap, graphql-cop output parsing
- Integration: graphql introspection-disabled fallback path, grpc reflection enum, sbom upload flow
- E2E: graphql against damn-vulnerable-graphql, websocket against a known-vulnerable WS server, grpc against a reflection-enabled fixture, package_registry against a vulnerable npm/pip package list, sbom against a CycloneDX with known-vuln components

**Definition of done for M3:** Same shape as M1/M2.

---

## 5. Deferred MEDIUM Resolutions (from spec)

### 5.1 B-017 — Scheduled scan `kind_payload` synthesis

**Decision:** at trigger time, `scheduled_scan_task.dispatch_due_scans` calls a new helper `_synthesize_kind_payload(target)` that derives a default `kind_payload` from `target.kind_config`. No per-schedule override column; schedules track only `target_id` + `cron_expression` + `profile`.

**Consequence:** scheduled scans always use the Target's current `kind_config` at trigger time (not snapshotted at schedule-creation). If an operator changes `kind_config` between trigger times, the next scheduled scan picks up the new config — which matches the existing behavior for `url`/`repo`/`llm` schedules.

**Implementation note:** Add `_synthesize_kind_payload` in `services/scan_runner.py` (also called by manual POST `/scans` when client omits `kind_payload`). Owner: backend-lead in M1.

### 5.2 B-018 — Per-kind plan gating

**Decision:** All new kinds available on all plans, subject to existing per-scan quota at `services/quota.py`. No per-kind plan policy. Free plan's `Org.option_3_scans_used` counter continues to gate the `deterministic_then_agent` mode across all kinds.

**Rationale:** Per-kind plan policy is product/pricing work (commercial), not architectural. Adding it here would lock the team into pricing assumptions. Defer to a future commercial-policy spec.

**Implementation note:** No code change required. `Plan_LIMITS` in `quota.py` stays kind-agnostic (currently 100,000/month/workspace — effectively unlimited).

### 5.3 S-06 — Webhook integration scoping per kind

**Decision:** Extend `Integration` row with a per-row `kinds` JSONB list. Default for **existing** integrations on migration: `kinds=["url","repo","llm"]` (their pre-feature scope). New integrations default to all-kinds; admin UI surfaces the per-kind opt-in.

**Migration shape:** A second migration `0045_integrations_kinds.py` (within M1 PR) adds the `integrations.kinds` JSONB column with a default-list backfill for existing rows.

**Router enforcement:** `services/integration_dispatch.py` filters webhooks/integrations by membership in `Integration.kinds` for the scan's `target.kind`. If `Integration.kinds` is NULL (defensively), treat as all-kinds.

**Implementation note:** Owner: backend-lead in M1 (small addition).

### 5.4 S-10 — OWASP tagging on new agents

**Decision:** All new BreakerSpecs/agents (`GraphQLFuzzAgent`, `GrpcReflectionAgent`, `CicdConfigAuditAgent`, `K8sManifestAuditAgent`, `K8sReconAgent`, `RbacEnumAgent`, `ArtifactReconAgent`, `ScannerOrchestratorAgent`) must tag findings with `owasp_category` from the existing enum at `schemas/findings.py::OwaspCategory` (or equivalent enum source-of-truth file). Agent system prompts (`agent_swarm/prompts.py`) include the OWASP-tagging instruction in their tool-call output schema.

**AC added per new BreakerSpec:** "Findings emitted by this agent carry `owasp_category` populated from `OwaspCategory` enum; mapping: <agent-specific mapping table>."

**Implementation note:** Owner: backend-lead per milestone — each new BreakerSpec ships with its OWASP mapping rule in `agent_swarm/prompts.py`.

---

## 6. Test Strategy (cross-milestone)

### 6.1 Test pyramid targets

| Tier | Target % | Examples |
|------|----------|----------|
| Unit | 70% | Pydantic validators, dispatch_mode branches, allowlist functions, `_DANGEROUS_ARG_SUBSTRINGS` entries, kind→breaker filter, file-ownership validators, consent-action coverage, sentinel-row builder |
| Integration | 20% | scan_runner end-to-end with mocked Pencheff session, artifact_orchestrator full loop, hybrid_orchestrator Phase-A-only and Phase-A+B, kubeconfig tempfile lifecycle, FallbackController row insertion, RBAC enforcement on `force_deterministic_only`, integration dispatch filtering by `Integration.kinds` |
| E2E | 10% | Per-story happy + fallback paths against fixture targets (DVWA, damn-vulnerable-graphql, alpine:3.10, vulnerable terraform/helm fixtures) |

### 6.2 Test scaffolding location

- Backend unit + integration: `apps/api/tests/` (follow existing pytest conventions; mirror module structure `apps/api/pencheff_api/services/agent_swarm/` → `apps/api/tests/services/agent_swarm/`)
- Frontend unit: `apps/web/__tests__/` (vitest or jest — match existing project setup; if none, add vitest config in M1)
- E2E: `tests/e2e/<kind>/` (Playwright; one folder per kind)

### 6.3 Regression suite

Before each milestone merges:
- Full existing test suite passes (CI gate)
- Manual canary: register one `kind="url"` target, one `kind="repo"` target, one `kind="llm"` target — confirm scans complete with identical findings count to pre-feature baseline (allow ±5% variance for LLM non-determinism)

---

## 7. Performance Considerations

| Concern | Mitigation |
|---------|------------|
| Migration locks targets/scans/orgs tables during column add | PG ≥ 11 ADD COLUMN with NOT NULL DEFAULT is in-place; verify in staging before prod deploy |
| `scans` table grows ~12× (8 new kinds add rows) | Existing indexes `ix_scans_target_id`, `ix_scans_org_id` cover; monitor `pg_stat_user_tables.n_live_tup` post-M1 |
| `kind_payload` JSONB increases row size | Pydantic discriminated union keeps payloads typed + bounded; max payload < 4 KiB per scan |
| Artifact scans pull large images / repos → disk pressure | Per-scan `/tmp/<scan_id>/` dir; cleanup in orchestrator `finally`; soft cap 4 GiB per artifact (k8s_cluster manifests, container_image layers) |
| Image-pull network egress on container_image scans | skopeo `copy --override-os` to OCI layout — single fetch; no exec; offline scan via trivy `--offline-scan` |
| Agent-loop turn budget exhaustion on artifact orchestrator | Reuse `swarm_turns_*` env knobs; artifact orchestrator pulls from `swarm_turns_chain_*` profile (already exists) |
| LLM cost regression from primary swap | Single WARNING log + release notes; operators tune `AGENT_LLM_USAGE_THRESHOLD_PERCENT` per new provider's pricing |

---

## 8. Edge Cases

| Case | Handling |
|------|----------|
| `kind_config` omitted on new-kind target | Pydantic validator rejects with 400, naming the missing field |
| `kind_config.kind != target.kind` | `_validate_kind_config` rejects with 400 |
| `kind_payload.kind != target.kind` at POST /scans | Router rejects with 400 |
| Legacy `url`/`repo`/`llm` row with non-null `kind_config` (data drift) | Validator on `TargetUpdate` rejects; existing rows are NULL by migration design |
| `Org.force_deterministic_only` toggled mid-scan | Existing scan continues to completion (mode resolved at queue time); next scan honors new value |
| `AGENT_FALLBACK_LLM_API_KEY` empty AND `AGENT_LLM_API_KEY` empty | Dispatch resolves to `deterministic_only`; `FallbackController` row with reason `"no_api_key"` |
| `clone_repo` URL doesn't match `Target.kind_config.repo_url` | Tool handler returns `{"error": "url_not_allowed", "registered": <url>}` without subprocess invocation |
| `pull_image` ref doesn't match `Target.kind_config.image_ref` | Same as above |
| Kubeconfig parsing fails (malformed YAML) | Hybrid orchestrator falls back to manifests_only mode for this scan; emits warning to scan log |
| SBOM content > 16 MiB | Pydantic validator rejects at request time with 400 |
| Scheduled scan triggers on target whose `kind_config` was deleted | `_synthesize_kind_payload` raises; scheduler logs warning; schedule disabled (not retried) |
| Concurrent scan triggers on same target | Existing `Scan(status="queued")` row deduped by scheduler / quota check — preserved behavior |
| Webhook integration with NULL `kinds` (legacy) | Defensive default: dispatch to all kinds (forward-compat) |
| Agent emits malformed tool call 3× | Fallback engagement (§9); `FallbackController` row with reason `"malformed_tool_calls"` |
| GitHub App private key expires mid-scan | Existing GitHub-App token refresh in `services/github_app.py` unchanged; SourceCodeCreds.github_app_private_key feeds the same refresh path |

---

## 9. Acceptance Criteria Pass Plan (cross-milestone)

To declare GATE 3 / feature ship:
- Every US's ACs (4-5 per story × 13 stories = ~60 ACs) have at least one automated test
- 80% of ACs verified in CI without manual setup; remaining 20% (E2E against vulnerable fixtures) verified in milestone-canary runs
- 0 CRITICAL/HIGH from pre-impl audit (Phase 7)
- 0 P0 from QA / regression suite

---

## 10. Operational Concerns

### 10.1 Rollout

- M1: behind no feature flag (additive only — legacy paths preserved). Production-safe day 1.
- M2: same.
- M3: same.

If anything goes wrong, operator sets `Org.force_deterministic_only=true` for affected orgs to disable AI orchestration without disabling the new-kind targets entirely.

### 10.2 Observability

- Existing OTel spans extended with `pencheff.target_kind=<kind>` attribute on root scan span
- New WARNING log on agent_loop init when primary swap is active
- `scan_llm_traces.agent_name="FallbackController"` rows queryable for fallback-engagement audit (existing `/scans/{id}/llm-traces` endpoint)
- Audit row in `org_settings_changes` for every `force_deterministic_only` toggle

### 10.3 Migration safety checklist

Before each milestone deploy:
- [ ] Alembic head matches expected (M1: `0044` or `0045`; M2/M3: no new migrations beyond M1)
- [ ] Migration runs cleanly on staging-size DB in < 60 s
- [ ] Downgrade tested on staging
- [ ] No FK orphan risk (additive columns only)

---

## 11. Cross-cutting work split across milestones

| Concern | M1 | M2 | M3 |
|---------|-----|-----|-----|
| Migration 0044 | ✅ Add 4 columns | — | — |
| Migration 0045 (integration kinds) | ✅ Add column | — | — |
| KindConfig union | ✅ All 12 variants (full spec) | — | — |
| KindPayload union | ✅ All 12 variants (full spec) | — | — |
| KindCredentials union | ✅ All 4 variants (full spec) | — | — |
| `_DANGEROUS_ARG_SUBSTRINGS` entries | ✅ All 8 new entries (full spec) | — | — |
| Per-kind form section | ✅ web-app, source-code, k8s-cluster | rest-api, container-image, iac, cicd-pipeline | graphql, websocket, grpc, package-registry, sbom |
| Per-kind detail-page renderer | ✅ 3 renderers | 4 renderers | 5 renderers |
| Per-kind list-page badge map | ✅ Map for all 12 kinds | — | — |
| MCP tool wrappers | ✅ artifact tools + source_code SAST + k8s | container_image + iac scanners | graphql + grpc + sbom |
| New BreakerSpecs | ✅ K8sReconAgent, RbacEnumAgent, ArtifactReconAgent, ScannerOrchestratorAgent, K8sManifestAuditAgent | CicdConfigAuditAgent | GraphQLFuzzAgent, GrpcReflectionAgent |
| KIND_TO_BREAKER_NAMES entries | ✅ url + web_app + future (full table) | — | — |
| RBAC on `force_deterministic_only` | ✅ | — | — |
| Consent kind-awareness | ✅ Map covers all 15 kinds | — | — |
| Integration.kinds | ✅ Column + filter | — | — |

---

## 12. Decision log

- 2026-05-16: Milestones reorganized per advisor — one kind from each cluster in M1 (vs original "first 3 DAST kinds") to validate all three pipeline shapes early.
- 2026-05-16: Source code GitHub App private key extended into `SourceCodeCreds` rather than reusing `Credentials.headers` (advisor-flagged gap).
- 2026-05-16: B-018 — declined to add per-kind plan gating; defer to commercial-policy work.
- 2026-05-16: S-06 — chose `Integration.kinds` per-row column over org-level setting (more granular, matches existing per-integration target filtering pattern).
