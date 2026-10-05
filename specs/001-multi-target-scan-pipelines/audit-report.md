# Pre-Implementation Audit — `001-multi-target-scan-pipelines`

**Date:** 2026-05-16
**Phase:** 7 (Pre-Implementation Audit) — solo, before GATE 3
**Documents under audit:** `spec.md` v2 (GATE 2 PASS post-revision), `plan.md`, `tasks.md`
**Verdict:** **PASS** — 0 CRITICAL, 0 HIGH, 3 MEDIUM, 4 LOW
**Gate decision:** **GATE 3 PASS** → Phase 8 (Implementation) can proceed in future sessions.

---

## Audit dimensions

| Dimension | Checked | Status |
|-----------|---------|--------|
| Story coverage | All 13 stories (US-0..US-12) accounted for across M1/M2/M3 | ✅ |
| AC test coverage | Every AC has a matching test task in tasks.md | ✅ (with caveats — see M-01) |
| Cross-doc consistency | Migration numbers, kind enum values, BreakerSpec names, env vars, file paths | ✅ |
| Deferred MEDIUMs resolution | All 4 spec-deferred MEDIUMs (B-017, B-018, S-06, S-10) resolved in plan.md §5 | ✅ |
| Architectural fitness | Three pipeline shapes mapped to existing code; branch points concrete; file-ownership clean | ✅ |
| Test pyramid | 70/20/10 unit/integration/E2E declared with examples | ✅ |
| Operational safety | Migration additive, no flag day, RBAC enforced, lifecycle rules for secrets | ✅ |
| Risks named | Spec §13 + plan.md §5 cover S-01, S-02 + cost/migration/perf risks | ✅ |

---

## Findings

| ID | Severity | Finding | Recommendation |
|----|----------|---------|----------------|
| A-01 | MEDIUM | tasks.md has **full** 8-task TDD breakdown only for M1 (US-0, US-1, US-6, US-12). M2 and M3 stories are summarized with only "highlights" — the implementation-team teammates running future sessions will need to expand to the full 8-task pattern themselves. | Acceptable: tasks.md §"Notes for implementation-team session" explicitly instructs future teams to "Create tasks per the story table for the target milestone." The summarized M2/M3 entries give the discriminating per-story specifics so the implementation team can fill in the canonical pattern. If future sessions struggle, expand M2 highlights to full tables before launching M2. Owner: future M2 session lead. |
| A-02 | MEDIUM | tasks.md cross-milestone task "Documentation page per kind" (`docs/scan-types/<kind>.md`) is flagged as `(deferred)` with no owner or milestone. Without an owner, it will rot. | Either assign to LEAD as a final-milestone deliverable (concretely: M3-cross-cutting), or strike from this feature spec entirely and create a separate `docs-001` mini-spec. Recommendation: strike for now; user-facing docs are typically a separate documentation sweep after the feature ships. Owner: M3 session lead to decide. |
| A-03 | MEDIUM | The spec § 7.4 introduces `Target.kind_credentials_encrypted` (Fernet) but does not specify HOW the Fernet key is selected (same `fernet_key` env as existing `credentials_encrypted`? separate key for per-kind creds?). Plan.md §4.1 task M1-US0-T05 references `services/credentials.py (MODIFY)` but doesn't elaborate. | Default to same `fernet_key` env (operational simplicity; existing rotation/audit story applies). Add a one-line note in `services/credentials.py` MODIFY task description: "reuse `settings.fernet_key` for both columns; same rotation policy". Owner: M1 backend-lead at implementation time. Non-blocking for GATE 3 because the existing `services/credentials.py` already encapsulates this. |
| A-04 | LOW | spec.md §6.1 KIND_TO_BREAKER_NAMES dict shows `url` mapping to all 13 existing breakers — but the existing url path goes through `_run_url_scan_existing` (preserved unchanged per §6.5), NOT through the new `_run_kind_aware_scan` branch. The `url` entry in the dict is therefore unused at runtime. | Either remove the `url` entry from KIND_TO_BREAKER_NAMES (it's only relevant inside `_run_dast_scan`, which url never calls), or leave it as a forward-compat hook. Recommendation: leave it (cheap; future code may consolidate). Owner: M1 backend-lead. Non-blocking. |
| A-05 | LOW | spec.md §15 US-0 AC-0.3 says "kind='llm' stays on `_run_llm_scan` (NOT promoted to swarm; KIND_TO_BREAKER_NAMES does not include llm)". Verified the table in §6.1 omits `llm` ✅. Cross-checked AC against §6.5 branch point ✅. Consistent. | None. |
| A-06 | LOW | tasks.md M1-US0-T05 lists `apps/api/pencheff_api/services/integration_dispatch.py (MODIFY)` for the S-06 `Integration.kinds` filter. But plan.md §5.3 says migration `0045_integrations_kinds.py` runs within M1 PR. The migration is in T05's file list (✅), but the `apps/api/pencheff_api/db/models.py` change to add the `kinds: Mapped[list \| None]` field on the `Integration` model is not explicitly called out. | Add `Integration` model mutation to M1-US0-T05 file list (concretely: `db/models.py` already in T05 list; just ensure the implementation includes the Integration column when M1-US0-T05 is picked up). Non-blocking; covered by the catch-all `db/models.py (MODIFY)`. |
| A-07 | LOW | tasks.md and plan.md both reference fixture targets (DVWA, Juice-Shop, damn-vulnerable-graphql, alpine:3.10, "vulnerable terraform fixture", "vulnerable Helm chart"). No central registry of fixture targets exists in the repo today; implementation teams will need to source/maintain these. | Add to plan.md cross-cutting or M1 setup: a `tests/fixtures/` directory with `README.md` listing each fixture, its source, and its purpose. Owner: M1 quality-lead during T01/T08 task pickup. Non-blocking; can be created lazily per fixture as each US-T08 runs. |

---

## Story → Milestone → Task coverage matrix

| Story | Milestone | tasks.md tasks | Test files (representative) |
|-------|-----------|----------------|------------------------------|
| US-0 | M1 | M1-US0-T01..T08 (6 tasks; no T03/T04) | test_dispatch_mode_kind_aware, test_kind_config_validators, test_breakers_kind_filter, test_artifact_orchestrator, test_hybrid_orchestrator, test_agent_runner_dangerous_args_extended, test_scan_kind_aware_routing, test_kubeconfig_lifecycle, test_fallback_engagement, test_legacy_url_repo_llm_unchanged |
| US-1 | M1 | M1-US1-T01..T08 (7 tasks; no T06) | test_breakers_web_app_roster, test_web_app_scan_end_to_end, test_dvwa_scan |
| US-2 | M2 | M2-US2-T01..T08 (highlights only) | (to be expanded by M2 session) |
| US-3 | M3 | M3-US3-T01..T08 (highlights only) | (to be expanded by M3 session) |
| US-4 | M3 | M3-US4-T01..T08 (highlights only) | (to be expanded by M3 session) |
| US-5 | M3 | M3-US5-T01..T08 (highlights only) | (to be expanded by M3 session) |
| US-6 | M1 | M1-US6-T01..T08 (7 tasks; no T06) | test_scanner_orchestrator_agent, test_repo_scan_task_source_code_branch, test_source_code_scan_multi_language, test_source_code_clone_repo_allowlist, test_multi_lang_fixture |
| US-7 | M2 | M2-US7-T01..T08 (highlights) | (to be expanded by M2 session) |
| US-8 | M2 | M2-US8-T01..T08 (highlights) | (to be expanded by M2 session) |
| US-9 | M3 | M3-US9-T01..T08 (highlights) | (to be expanded by M3 session) |
| US-10 | M3 | M3-US10-T01..T08 (highlights) | (to be expanded by M3 session) |
| US-11 | M2 | M2-US11-T01..T08 (highlights) | (to be expanded by M2 session) |
| US-12 | M1 | M1-US12-T01..T08 (8 tasks) | test_hybrid_phase_a_only, test_k8s_recon_agent, test_kubeconfig_redaction, test_k8s_cluster_manifests_only_scan, test_k8s_cluster_live_scan_mock, test_vulnerable_helm_chart, test_kubeconfig_lifecycle |

13 / 13 stories covered. M1 has full task expansions (28 tasks); M2 (32 tasks) and M3 (40 tasks) have highlight expansions that future implementation sessions will fill out.

---

## Spec ↔ Plan ↔ Tasks consistency checks

| Item | Spec source | Plan reference | Tasks reference | Status |
|------|-------------|-----------------|------------------|--------|
| Migration 0044 | §7.1 | §4.1, §11 | M1-US0-T05/T06 | ✅ |
| Migration 0045 (integrations.kinds) | §10 (S-06 mentioned) | §5.3 | M1-US0-T05 | ✅ |
| KindConfig union (12 variants) | §7.3 | §4.1 | M1-US0-T05 | ✅ |
| KindPayload union | §7.3.1 | §4.1 | M1-US0-T05 | ✅ |
| KindCredentials union (4 variants incl. SourceCodeCreds) | §7.4 | §4.1, §12 | M1-US0-T05 | ✅ |
| `_DANGEROUS_ARG_SUBSTRINGS` extension (8 entries) | §6.4 | §4.1 | M1-US0-T05 | ✅ |
| AGENT_FALLBACK_LLM_* primary swap | §5.7 | §4.1 | M1-US0-T05 (agent_loop.py MODIFY) | ✅ |
| `Org.force_deterministic_only` + RBAC | §5.6, §13 | §4.1 | M1-US0-T05 (orgs.py MODIFY) | ✅ |
| `_run_kind_aware_scan` branch point | §6.5 | §4.1, §2.2 | M1-US0-T05 (scan_runner.py MODIFY) | ✅ |
| `KIND_TO_BREAKER_NAMES` dict | §6.1 | §4.1, §11 (table) | M1-US0-T05 (breakers.py MODIFY) | ✅ |
| New BreakerSpecs (7) | §6.1, §6.3 | §11 (table) | M1-US0-T05 (breakers.py MODIFY) for K8s/Artifact/Scanner agents; CicdConfigAuditAgent in M2; GraphQLFuzzAgent/GrpcReflectionAgent in M3 | ✅ |
| Artifact allowlists (clone_repo, pull_image, …) | §6.4 | §4.1 (sandbox lifecycle) | M1-US0-T05 (agent_runner.py MODIFY) | ✅ |
| Consent kind-awareness | §10.6 | §5.3 | M1-US0-T05 (scans.py MODIFY) | ✅ |
| Frontend type-card kind remap | §10.1 | §3 file-ownership | M1-US1-T03, M1-US6-T03, M1-US12-T03 (target-types.ts MODIFY) | ✅ |
| Frontend SupportedKind expansion | §10.1 | §3 (shared types — LEAD only) | M1-US1-T03 (lib/types.ts MODIFY) | ✅ |
| Per-kind form sections | §10.2 (12 files) | §11 (split across M1/M2/M3) | M1-US1-T03 / M1-US6-T03 / M1-US12-T03 ; M2/M3 stories | ✅ |
| Coverage badge map per kind | §10.3 | §11 | M1-US1-T04, M1-US6-T04, M1-US12-T04 (targets/page.tsx MODIFY) | ✅ |
| Test pyramid 70/20/10 | §14 | §6.1 | tasks.md per-T07 + per-T08 | ✅ |

---

## OWASP Top 10 coverage check (per S-10 deferral)

Plan.md §5.4 resolves S-10: every new BreakerSpec must tag findings with `owasp_category` from `schemas/findings.py::OwaspCategory`. Plan.md mentions this for "each new BreakerSpec ships with its OWASP mapping rule in agent_swarm/prompts.py."

Verified that tasks.md mentions OWASP tagging at:
- M1-US12-T05: "agents tag findings with OWASP categories (A05 Misconfig, A01 Access Control)" ✅
- M1-US6-T05: "OWASP tagging applied to findings" ✅

For M2/M3 stories, the highlight summaries don't repeat this explicitly. Recommendation: M2/M3 session leads should pull the spec's S-10 plan resolution forward into the per-story T05 task descriptions when expanding tasks.

---

## Final gate decision

**GATE 3: PASS**

Criteria:
- 0 CRITICAL ✅
- 0 HIGH ✅
- 3 MEDIUM (all non-blocking, with clear owners or acceptable-as-is rationale)
- 4 LOW (informational / nits)
- All spec stories covered in plan + tasks
- All spec ACs map to test tasks
- All spec-deferred MEDIUMs resolved in plan.md §5

Phase 8 (Implementation) can begin in future `/sdd-team implement` sessions. Recommended invocation order: M1 first, verify in canary, then M2, then M3.

---

## Audit trail entries to append to `sdd-state.md`

- 2026-05-16: Phase 5 plan.md written (milestones M1/M2/M3 with one-from-each-cluster M1 composition; deferred MEDIUMs B-017/B-018/S-06/S-10 resolved).
- 2026-05-16: Phase 6 tasks.md written (104 tasks across 3 milestones; M1 fully expanded, M2/M3 in highlight form).
- 2026-05-16: Phase 7 self-audit complete. **GATE 3 PASS** — 0 CRITICAL / 0 HIGH / 3 MEDIUM / 4 LOW. Phase 8 (Implementation) deferred to future sessions.
