# Changelog

All notable changes to Pencheff are documented here. The format is
loosely based on [Keep a Changelog](https://keepachangelog.com/) and
this project follows [Semantic Versioning](https://semver.org/).

The web-rendered release notes at
[pencheff.com/release-notes](https://pencheff.com/release-notes) carry
the full long-form per-version commentary; this file is the terse
machine-readable companion that PyPI surfaces under the
**Project description** of the package page.

## [Unreleased]

### Host target kind (sub-project A of the OS-exploitation ladder)

Sub-project A of a 6-part feature ladder that gives Pencheff the
Mythos-style "find OS-level vulns + prove exploitation" capability.
This first sub-project lands the target kind, UI, and consent gate;
the OSExploitAgent (sub-project B) reuses these foundations to add
nmap → CVE-match → exploit → evidence-capture against the listed
hosts. Scanning a host target is currently gated at the API
(`POST /scans` returns `HTTP 409 host_kind_scanning_not_yet_available`)
and at the UI (Run-scan button is disabled with a "ships in v2" tooltip).

- New `Target.kind = "host"` with multi-host input (`kind_config.hosts:
  list[str]`, max 50 per target). FQDN or IPv4 / IPv6 entries; per-host
  DNS resolution at create/PATCH time; case-insensitive dedup.
- `Org.allow_private_targets` admin opt-in (default `false`) gates
  RFC1918 / loopback / link-local / CGNAT / IPv6-ULA hosts. Flipping
  the flag ON requires a strong-attestation acknowledgement
  (`private_targets_disclosure_ack=true`) and writes an
  `org.allow_private_targets.flip` audit row capturing actor + IP +
  user-agent + prior/new value. Flipping OFF is freely allowed.
- New consent action ID `host_os_exploitation` declares the strongest
  ROE in the platform — read-only post-exploit reconnaissance, one
  session screenshot, and up to 256 KB of evidence per host, with the
  attestation that the operator owns these hosts or holds written
  authorization from the owner.
- `Scan.consent_payload` bumped from v1 → v2. New optional fields:
  `authorized_hosts`, `acknowledged_at`, `acknowledged_by_user_id`,
  `acknowledged_from_ip`, `acknowledged_user_agent`. v1 payloads
  remain readable via the new typed loader.
- Migration `0047_host_kind_target` adds the new Org column.

### Multi-target scan pipelines (feature 001)

The Register Target taxonomy expands from 3 wire kinds (`url`/`repo`/`llm`)
to **15** — adding 12 first-class target kinds, each with its own scan
pipeline shape. Three clusters, all dispatch-routed through the existing
`agent_swarm`:

- **DAST cluster** (`web_app`, `rest_api`, `graphql`, `websocket`, `grpc`) —
  reuses `run_swarm()` with a kind-filtered breaker roster
  (`KIND_TO_BREAKER_NAMES`). New specialists `GraphQLFuzzAgent` +
  `GrpcReflectionAgent` cover protocol-specific surface that `scan_api`
  alone can't reach. Existing `kind="url"` scans are byte-for-byte
  unchanged — verified by an isolation test asserting the 13 legacy
  breakers never see the 8 feature-001 agents in their roster.
- **Artifact cluster** (`source_code`, `container_image`, `iac`,
  `package_registry`, `sbom`) — new `artifact_orchestrator` runs the
  per-kind scanner allowlist against a sandboxed artifact. Acquisition
  tools (`artifact_clone_repo`, `artifact_pull_image`,
  `artifact_download`, `artifact_parse_sbom`) enforce a strict allowlist
  against `Target.kind_config` registered values — agent-emitted URLs /
  image refs / hosts that don't match are rejected without invoking the
  subprocess. Image pulls use `skopeo copy` to an OCI layout (never
  `docker pull` — avoids exec during layer extraction). Downloads
  require a sha256 + verify before scanning. SBOM content capped at
  16 MiB.
- **Hybrid cluster** (`cicd_pipeline`, `k8s_cluster`) — new
  `hybrid_orchestrator` runs Phase A (static config audit via
  `checkov`) always, then Phase B (live probing) when
  `kind_credentials` is bound. Phase B coverage: kubernetes via
  `kubectl get` + `kubectl describe` + `rakkess` (RBAC enumeration with
  wildcard-verb / impersonate / escalate flagged as CRITICAL+HIGH);
  CI/CD via all 5 providers — **GitHub Actions, GitLab CI, Jenkins,
  Azure Pipelines, CircleCI** — each with provider-specific security
  heuristics (admin-suggestive secret names, push-enabled deploy keys,
  unprotected variables, outdated Jenkins plugins as an RCE vector).

#### Backend additions

- **Migrations 0044 + 0045** (additive, downgrade-reversible):
  - `targets.kind_config` JSONB — per-kind config for the 11 new
    non-llm kinds (the existing `targets.llm_config` stays authoritative
    for `kind="llm"`). Pydantic discriminated union validates per kind.
  - `targets.kind_credentials_encrypted` LargeBinary (Fernet) — per-kind
    credentials whose shape doesn't fit the flat `Credentials` model:
    kubeconfig YAML, registry auth (ECR STS / GCR JSON / ACR client
    secret / docker config), CI provider tokens, GitHub App private
    keys, SSH keys. Field-level redaction rules apply; values never
    leave the API.
  - `scans.kind_payload` JSONB — per-scan operational overrides
    (e.g., container_image digest pin per scan).
  - `orgs.force_deterministic_only` Boolean — org-level AI-orchestration
    kill switch. Admin / owner role only via `require_org_role`; every
    toggle writes an `AuditLog` row with before/after + actor_role.
  - `integrations.target_kinds` JSONB — per-integration target-kind
    opt-in. Existing rows backfilled to `["url","repo","llm"]` (their
    pre-feature scope) so new kinds don't accidentally flood configured
    webhook channels.
- **Three new MCP-tool modules** (`plugins/pencheff/pencheff/`):
  - `artifact_tools.py` — 14 tools (4 acquisition + 10 scanners) with
    allowlist enforcement, subprocess safety, JSON-parse-to-finding
    mapping, OWASP tagging.
  - `dast_protocol_tools.py` — `run_graphql_cop`, `run_inql`,
    `run_grpcurl`, `parse_proto`.
  - `source_code_tools.py` — 8 SAST wrappers: `run_semgrep`,
    `run_bandit`, `run_gosec`, `run_brakeman`, `run_eslint`,
    `run_gitleaks`, `run_yara`, `run_osv_scanner`.
  - `hybrid_tools.py` — 6 Phase B tools across kubernetes + 5 CI
    providers. Kubeconfig materialised to `/tmp/<scan_id>/.kube/config`
    mode 0600 + always unlinked in the orchestrator's `finally`.
- **`dispatch_mode.resolve_dispatch_mode`** extended with an optional
  `target_kind` arg (legacy 2-arg call signature preserved for
  back-compat). New checks: `Org.force_deterministic_only` short-circuit
  (precedence #1), kind-capability gate (precedence #2), then the
  AGENT_FALLBACK_LLM_* / AGENT_LLM_* preference, then the existing
  plan + quota logic.
- **`AGENT_FALLBACK_LLM_*` becomes the unified primary**, with
  `AGENT_LLM_*` as the secondary fallback. Rollout is safe — code falls
  back to `AGENT_LLM_*` when `AGENT_FALLBACK_LLM_API_KEY` is unset, so
  existing deployments keep working without an env-var change. A
  one-time `WARNING` log on agent_loop init alerts operators that
  `AGENT_LLM_USAGE_*` budget thresholds now apply to the new primary's
  pricing curve.
- **`_DANGEROUS_ARG_SUBSTRINGS`** extended with 8 new entries to block
  scanner-flag pivots (`trivy --server`, `grpcurl --plaintext`,
  `grpcurl --import-path`, `checkov --external-checks-dir`,
  `tfsec --custom-check-dir`, `helm --post-renderer`, etc.).
- **`KIND_REQUIRED_DISCLOSED_ACTIONS`** — consent flow gets kind-aware
  vocabulary. The `disclosed_actions` array must cover the actions the
  scan will actually take (`image_pull`, `clone_repo`, `k8s_api_read`,
  `rbac_enumeration`, `ci_api_read`, etc.). Phase B disclosures are
  appended at the router when `kind_config` implies live-system probing.

#### Frontend additions

- `target-types.ts` — `SupportedKind` widened from 3 → 15 values. All
  12 existing active type-cards remapped from legacy `url/repo/llm` to
  their proper snake_case kind (`web-app → web_app`, `rest-api →
  rest_api`, `container-image → container_image`, `kubernetes →
  k8s_cluster`, etc.).
- **6 new per-kind form section components** —
  `container-image-form-section.tsx`, `iac-form-section.tsx`,
  `package-registry-form-section.tsx`, `sbom-form-section.tsx`,
  `cicd-pipeline-form-section.tsx`, `k8s-cluster-form-section.tsx`.
  File-upload + paste-content for SBOM / package list / kubeconfig
  (size-capped client-side); conditional rendering per kind config
  (k8s_cluster `live_cluster` shows the kubeconfig textarea + hides
  the manifests archive URL; cicd_pipeline `live_api_enabled` toggles
  the credentials requirement; etc.).
- `app/targets/new/page.tsx` submit flow handles all 12 new kinds with
  per-kind validation + `kind_config` / `kind_credentials` payload
  synthesis; `base_url` is derived from the kind-specific identifier
  (`oci://image_ref` / `k8s://live/namespaces` / `sbom://format`).
- `app/targets/[id]/page.tsx` — new `<KindConfigView>` renders the
  loaded `kind_config` as a typed `<dl>` per kind; `has_kind_credentials`
  surfaces a presence badge.
- `app/targets/[id]/edit/page.tsx` — full PATCH flow for all 6 new
  artifact/hybrid kinds. State hydrated from API; submit handles
  `kind_credentials` lifecycle (re-paste to overwrite OR
  `clear_kind_credentials` toggle when one is on file).
- `app/targets/page.tsx` — per-kind `TypeBadge` for all 15 kinds + new
  coverage badges (`CI`, `IAC`, `CONTAINER`, `K8S`, `SBOM`, `API`).
  `effectiveKind()` widened defensively against unknown wire kinds.

#### Spec / plan / docs

The full SDD artifact set lives under
`specs/001-multi-target-scan-pipelines/` (spec.md v2 with GATE 2 PASS
post-revision, plan.md, tasks.md, audit-report.md with GATE 3 PASS).
Discovery + validation history under `.sdd/`.

### Visual dashboards

- **Per-scan dashboard** at `/scans/{id}/dashboard` — severity donut,
  CVSS histogram, verification pie, OWASP-Top-10 coverage, top-risk
  list, affected-endpoint treemap, plus stat tiles for KEV / median
  EPSS / reachability. Linked from the assessment page when the scan
  finishes.
- **LLM red-team variant** of the per-scan dashboard — when the target
  is `kind="llm"`, the same route renders verdict funnel
  (vulnerable / refused / ambiguous), OWASP-LLM-Top-10 attack-success
  heatmap with per-category success rate, strategy + technique
  breakdown (`base`, `jailbreak`, `dataset`, `custom`, `guardrail` ×
  `direct_injection`, `role_play`, etc.), judge-confidence histogram,
  token + latency profile (prompt / completion / cached / reasoning,
  p50, p95), and the top-10 failures list. Renders the data already
  in `Scan.summary.llm_redteam_summary` plus the per-probe transcript
  JSONL.
- **Per-target trend dashboard** — embedded section on `/targets/{id}`
  showing grade trajectory over time, severity-stack area chart by
  scan date, MTTR tile, and a delta strip
  (`+N new · −N fixed · ±N regressed`) per consecutive scan pair with
  one-click links into `/scans/compare`. Hidden when the target has
  fewer than 2 completed scans.
- **Per-repo trend dashboard** at `/repos/{id}/dashboard` — severity
  score trajectory across recent `RepoScan`s, severity-stack chart,
  scanner-duration breakdown for the latest scan.
- **Per-repo-scan dashboard** at `/repos/scans/{id}/dashboard` —
  scanner-effort bar (count + duration per `semgrep` / `bandit` /
  `gosec` / `brakeman` / `eslint` / `gitleaks` / `ghsa` / `yara` /
  `trivy_iac` / `checkov`), file-hotspot treemap, top-CVE table with
  installed → fixed version delta and PR link, fix-status pie.
- **Executive dashboard** unchanged in behaviour but the inline-SVG
  trend chart migrated to Recharts for visual consistency.

### Email notifications (Resend)

- **Scan-completion email** — at commission time, an opt-in toggle on
  the `<CommissionScanModal>` lets you pick one or more recipients
  from a workspace-member dropdown or type any email. Recipients are
  persisted on `Scan.notify_emails` (JSONB array, capped at 10). The
  scan runner enqueues
  `pencheff_api.tasks.email_task.send_scan_complete_email_task`
  on the `done` and `failed` terminal points; failures degrade
  gracefully without blocking other scan post-processing.
- **Per-target weekly digest** — `Target.weekly_digest_emails`
  (JSONB array, capped at 20) configurable on the target edit page.
  Subscribers get a Monday 09:00 UTC email summarising the past 7
  days of completed scans for that target with grade, severity counts
  per scan, and a link to the target dashboard.
- **Per-workspace weekly digest** —
  `Workspace.weekly_digest_emails` (JSONB array, capped at 20)
  configurable on the org-settings page. Subscribers get a Monday
  09:00 UTC rollup email covering the latest grade and severity
  counts for every active target in the workspace.
- New endpoint `GET /workspaces/{id}/members` returns
  `(user_id, email, name, role)` per `OrgMember` of the workspace's
  parent org — powers the recipient-picker dropdown.
- New Celery beat job `weekly-digest`
  (`pencheff_api.tasks.email_task.run_weekly_digest`) walks every
  Target and Workspace with a non-empty digest list and dispatches
  via the existing Resend wrapper at `services/email.py`.

### API additions

- `GET /dashboard/target/{target_id}/trend` — per-target scan list
  with summary-diff deltas and aggregate open / fixed / MTTR.
- `GET /repos/{repo_id}/trend` — per-repository scan list with
  per-`RepoScan` severity counts (one rolled-up SQL query, no N+1)
  and scanner durations.
- `GET /workspaces/{workspace_id}/members` — workspace-member list
  for recipient pickers.
- `POST /scans` accepts `notify_emails: list[str]`.
- `PATCH /targets/{id}` accepts `weekly_digest_emails: list[str]`;
  `TargetOut` now returns it.
- `PATCH /workspaces/{id}` accepts `weekly_digest_emails: list[str]`;
  `WorkspaceOut` now returns it.

### Migration

- **`0043_email_notifications`** adds three JSONB columns:
  `scans.notify_emails`, `targets.weekly_digest_emails`,
  `workspaces.weekly_digest_emails`. Backfilled `NULL` everywhere —
  no behaviour change until subscriptions are configured.

### Bug fixes

- Wired `dashboard.router` into `main.py`. The router file existed
  with five aggregation endpoints (`/dashboard/heatmap`,
  `/dashboard/trend`, `/dashboard/top-repos`, `/dashboard/kev-exposure`,
  `/dashboard/fix-conversion`) but was never imported, so the
  executive dashboard frontend silently 404'd against it. Fixed
  alongside the new `/dashboard/target/{id}/trend` endpoint.

### New env vars

- `RESEND_API_KEY` — Resend API key for transactional + scheduled
  email. When unset, all email-sending paths log and short-circuit
  (no email sent, no exception); the rest of the app continues to
  work normally.
- `EMAIL_FROM` — `From:` address used by every Pencheff email.
  Defaults to `Pencheff <no-reply@pencheff.com>`.
- `EMAIL_APP_URL` — base URL for the dashboard / target links
  embedded in emails. Falls back to `web_base_url` when unset.

### Frontend dependencies

- `recharts@^2.13` added to `apps/web/package.json` for the dashboard
  primitives. ~95 KB gzipped on routes that use it; primitives live
  under `apps/web/components/dashboard/{,llm/,repo/}` so they
  code-split per route.

## [0.7.0] — 2026-05-08

### IP-risk fixes (Phase 0)

- **CodeQL removed.** GitHub CodeQL CLI is not licensed for commercial
  use on third-party code; Pencheff scans customer code, so the
  ongoing licensing question was eliminated by replacing CodeQL with
  Semgrep OSS (pinned packs only) + Bandit (Apache-2.0) + gosec
  (Apache-2.0) + Brakeman (MIT) + ESLint-security (MIT). All run as
  subprocesses; no static linking.
- Semgrep config tightened to an explicit OSS Registry pack list —
  no more `--config=auto`. Override via `PENCHEFF_SEMGREP_PACKS`.
- Llama Guard 3 hardened to opt-in only via
  `PENCHEFF_LLAMA_GUARD_ENABLED=1`; license notice surfaced in every
  `JudgeResult.reason`. Default judge is now Granite Guardian
  (Apache-2.0).
- DCO sign-off enforcement on every commit, license-audit CI, SPDX
  header check, auto-generated `THIRD_PARTY_NOTICES.md`.

### Foundation (Phase 1)

- Pluggable `BulkFeedSource` protocol replaces the inline EPSS / KEV
  refresh in `core/cve_feed.py`. New permissive sources: RustSec
  (CC0-1.0), GoVulnDB (BSD-3-Clause).
- `GET /advisories/{id}` and `GET /advisories?package=&ecosystem=`
  return cached advisory + NVD enrichment + EPSS / KEV labels +
  AI-enriched exploit walkthrough + provenance trail.
- HackerOne / Bugcrowd / Cobalt partner integrations with HMAC
  webhook signing primitive (`sign_webhook_body` /
  `verify_webhook_signature`).
- Per-release SBOM (CycloneDX 1.5 + SPDX 2.3) signed with cosign
  keyless via Sigstore on every `v*.*.*` tag.

### Probe & rule libraries (Phase 2)

- `pencheff-probes` community LLM red-team corpus + DoNotAnswer
  importer. HarmBench / AgentHarm / BeaverTails excluded for license
  reasons.
- `pencheff-rules` community DAST library with Nuclei→Pulse converter
  + AI rule synthesiser (validator rejects destructive payloads,
  disallowed methods, non-permissive PoCs).
- SAST tree-sitter pack with Solidity sub-pack (4 hand-curated rules:
  tx.origin auth, weak randomness, deprecated SELFDESTRUCT, unchecked
  low-level calls).

### Runtime + integration (Phase 3)

- **`pencheff-sentry`** (new package on PyPI): runtime LLM guardrail.
  HTTP proxy sidecar + LiteLLM plugin + MCP middleware. Blocks prompt
  injection / PII / unsafe HTML / token-ceiling violations inline.
- API discovery from runtime traffic — synthesises OpenAPI 3.1 from
  captured `ProxyFlow` rows; drift detector emits `api_drift`
  findings.
- GitHub Check Run + SARIF upload + Pencheff Suggest PR-comment
  suppression bot.

### Container, support, certs (Phase 4)

- Container registry push webhooks (DockerHub / ECR / GCR / ACR) →
  Trivy scan via Celery.
- Kubernetes `ValidatingAdmissionWebhook` (Go) + Helm chart
  published at `oci://ghcr.io/balasriharsha-ch/charts/pencheff-admission`.
  Fail-closed by default.
- "Verify with humans" finding-card flow → partner-pentest triage
  with a callback that flips `verification_status`.

### Migration

- Repo-scan `stats` keys shift: `stats.codeql` →
  `stats.semgrep` / `stats.bandit` / `stats.gosec` / `stats.brakeman`
  / `stats.eslint`. Old rows in the DB stay; UI filters them as
  legacy SAST.
- If you opted in to Llama Guard before v0.7, set
  `PENCHEFF_LLAMA_GUARD_ENABLED=1` to keep using it.
- New env vars: `PENCHEFF_SEMGREP_PACKS`,
  `PENCHEFF_LLAMA_GUARD_ENABLED`.

### Removed

- `bench/runners/codeql.sh` and the CodeQL download/install path in
  `apps/api/pencheff_api/tasks/repo_scan_task.py`.
- `services.repo_findings.normalize_codeql` — replaced by per-tool
  normalisers (`normalize_semgrep`, `normalize_bandit`,
  `normalize_gosec`, `normalize_brakeman`, `normalize_eslint`).

[0.7.0]: https://github.com/BalaSriharsha-Ch/pencheff/releases/tag/v0.7.0
