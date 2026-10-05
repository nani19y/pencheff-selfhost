# Spec: Multi-Target Scan Pipelines

**Feature:** `001-multi-target-scan-pipelines`
**Status:** Draft v2 (Phase 3 revised after GATE 2 FAIL — see `.sdd/validation-reports/validation-synthesis.md`)
**Author:** SDD-Team session 2026-05-16
**Tracking:** `.sdd/sdd-state.md`

---

## 1. Problem Statement

Pencheff today supports three target kinds — `url`, `repo`, `llm` — each with a hand-wired pipeline. The Register Target UI exposes 12 active type cards across 8 categories, **all collapsed onto only 3 backend kinds**. We extend the existing `agent_swarm` + `dispatch_mode` + `scan_runner` infrastructure to make every type card a first-class scan target with its own kind-aware pipeline, per-kind config + credentials, and a deterministic-only fallback when the AI agent fails.

This is **extension of an existing system**, not greenfield. The existing 13-breaker swarm, `dispatch_mode` selector, `scan_llm_traces` audit log, `scan_consent` flow, SSE/webhook integrations, scheduled-scan task, zombie-recovery task, and frontend section pattern all stay; we add kind-awareness at the dispatch and orchestration layer.

---

## 2. Target Kind Taxonomy

The full set after this feature ships — **15 wire values total**, 12 of them new:

| Kind (wire, snake_case) | FE Type ID (kebab-case) | Status | Cluster |
|-------------------------|-------------------------|--------|---------|
| `url` | (legacy — many cards remap below) | Existing — preserved | DAST (legacy) |
| `repo` | (legacy — many cards remap below) | Existing — preserved | Artifact (legacy) |
| `llm` | (legacy — `chat-completions`, etc.) | Existing — preserved | DAST (legacy, single-stage path) |
| `web_app` | `web-app` | **NEW** | DAST |
| `rest_api` | `rest-api` | **NEW** | DAST |
| `graphql` | `graphql-api` | **NEW** | DAST |
| `websocket` | `websocket` | **NEW** | DAST |
| `grpc` | `grpc` | **NEW** | DAST |
| `source_code` | `source-code-repo` | **NEW** | Artifact |
| `cicd_pipeline` | `cicd-pipeline` | **NEW** | Hybrid |
| `iac` | `iac` | **NEW** | Artifact |
| `container_image` | `container-image` | **NEW** | Artifact |
| `k8s_cluster` | `kubernetes` | **NEW** | Hybrid |
| `package_registry` | `package-registry` | **NEW** | Artifact |
| `sbom` | `sbom-deps` | **NEW** | Artifact |

`TargetKind` Pydantic Literal in `schemas/targets.py:7` extends to all 15:
```python
TargetKind = Literal[
    "url", "repo", "llm",
    "web_app", "rest_api", "graphql", "websocket", "grpc",
    "source_code", "cicd_pipeline", "iac",
    "container_image", "k8s_cluster",
    "package_registry", "sbom",
]
```

Existing rows untouched. The 11 new kinds (everything except `source_code` which reuses the existing repo+RepoScan path) require a non-null `kind_config`. The legacy 3 reject `kind_config` (validator analogous to existing `_validate_llm`).

---

## 3. Three Pipeline Shapes

The 15 kinds collapse into three pipeline shapes. **This is the central architectural decision.** Forcing all kinds through the existing 13-breaker swarm would produce dead code paths (no endpoints on SBOM, no recon on container_image, etc.).

### 3.1 DAST cluster — `url`, `web_app`, `rest_api`, `graphql`, `websocket`, `grpc`, `llm`

Reuses the existing `agent_swarm.run_swarm()` 9-phase flow with **kind-filtered breaker rosters** (see §6.1). The legacy `url` and `llm` kinds keep their current paths — only the 5 new DAST kinds change behavior.

### 3.2 Artifact cluster — `repo`, `source_code`, `container_image`, `iac`, `package_registry`, `sbom`

**New pipeline shape.** No live endpoint; agent orchestrates scanners against a static artifact. `repo` is the legacy artifact path (unchanged); `source_code` is the new agent-orchestrated artifact path that reuses the same `RepoScan` table. The other 4 new artifact kinds use the `scans` table with `kind_payload`.

```
Acquire artifact ─→ ArtifactReconAgent ─→ ScannerOrchestratorAgent
   (clone/pull/         (catalog the         (LLM sequences scanners
   download/parse)       artifact)            from per-kind allowlist)
   ─→ Merge findings ─→ ComplianceAgent ─→ Summary
```

### 3.3 Hybrid cluster — `cicd_pipeline`, `k8s_cluster`

Two-phase: artifact analysis first (Phase A), then live-system probing if credentials provided (Phase B).

---

## 4. Existing Infrastructure Preserved

Every item below stays exactly as it is today; new kinds plug into them.

- `services/agent_swarm/` (orchestrator, agent_loop, breakers, chain, recon, tools, prompts, llm_trace, telemetry)
- `services/agent_runner.py` legacy single-agent path (catastrophic-fallback target)
- `services/dispatch_mode.py` — **signature extends** (new `target_kind` arg); modes unchanged
- `services/scan_runner.py` — top-level dispatcher; new kinds plug in via `_run_kind_aware_scan()` branch
- Migrations 0019/0022/0023/0024 (kind, llm_config), 0036 (scan_llm_traces), 0037 (scan_consent), 0038–0043 (existing)
- `Scan` and `RepoScan` tables — additive changes only (see §5)
- SSE channel `scan:{scan_id}`, `/scans/{id}/stream`, `/scans/{id}/llm-traces`
- Webhook / integration dispatch, scheduled scans (`scheduled_scan_task.py`), zombie recovery (`scan_task.py:62–119`)
- Frontend `apps/web/components/register-target/` section pattern, `apps/web/app/targets/*` pages
- Quota gating (`services/quota.py`), consent flow (`schemas/scans.py`)
- All 60 MCP tools in `plugins/pencheff/pencheff/server.py` plus the 80+ `run_security_tool` external tools

---

## 5. Locked Architecture Decisions

1. **Target.kind enum** — `String(16)` column; expand allowed values to all 15 (see §2). Existing `url`/`repo`/`llm` rows untouched. No alembic data backfill.

2. **Per-kind config storage** — add sibling JSONB column `Target.kind_config` validated by Pydantic discriminated union (§7.3). **`Target.llm_config` remains authoritative for `kind="llm"`**; the 11 other new kinds use `kind_config`. Validators enforce: `kind="llm"` → `llm_config` required + `kind_config` rejected; legacy `url`/`repo` → `kind_config` rejected; the 11 new kinds → `kind_config` required + `llm_config` rejected.

3. **Per-kind credentials storage (NEW — addresses B-005 / F-07 / S-02)** — add sibling Fernet-encrypted column `Target.kind_credentials_encrypted` carrying per-kind credential discriminated union (§7.4). The existing `Target.credentials_encrypted` keeps its current `Credentials` schema for kinds whose secrets fit it (`url`/`web_app`/`rest_api`/`graphql`/`websocket`/`grpc`/`llm`/`repo`/`source_code`). Kinds with structurally different secrets (`container_image`, `k8s_cluster`, `cicd_pipeline`) use `kind_credentials_encrypted`. Field-level redaction rules apply — see §7.4.

4. **Scan table strategy** — Add nullable `kind_payload` JSONB to existing `scans` table. **`source_code` keeps using `RepoScan`** (it has SAST semantics already wired via `repo_scan_task.py`). The other 8 new kinds (`web_app`, `rest_api`, `graphql`, `websocket`, `grpc`, `container_image`, `iac`, `cicd_pipeline`, `k8s_cluster`, `package_registry`, `sbom`) add rows to `scans`. **Zero new scan tables.** Zombie recovery, SSE, traces, webhooks, scheduling, dashboard, compliance — all keep working with no code change to readers.

5. **AI orchestrator pattern** — LLM agent (OpenAI tool-calling shape) chooses + sequences existing deterministic scanners. Agent does **NOT** generate payloads directly; it composes from the existing 35-tool registry plus new per-cluster tools (`clone_repo`, `pull_image`, `parse_sbom`, etc.). All artifact-acquisition tools are **allowlisted** against `Target.kind_config` registered values (§6.4) — never agent-freeform URLs/refs.

6. **Deterministic-only fallback triggers** — extend `dispatch_mode.py`:
   - Existing: no LLM API key → `deterministic_only`
   - **NEW** (a): LLM API failures persisting after retry budget exhausted → fall back to deterministic pipeline for this scan
   - **NEW** (b): repeated malformed tool calls / low confidence (≥3 turns producing no valid tool call) → abandon agent loop, run deterministic for remaining stages
   - **NEW** (c): org-level config flag `Org.force_deterministic_only` → always `deterministic_only` regardless of plan/quota. **RBAC:** only org-admin / org-owner may set this. Toggle is audit-logged via `org_settings_changes` row.

7. **LLM creds swap (revised — addresses B-007 / S-05)** — `AGENT_FALLBACK_LLM_*` becomes unified **primary**; `AGENT_LLM_*` becomes **secondary** fallback. Concrete changes:
   - `agent_swarm/agent_loop.py:181–189` `_primary_backend()` body reads `settings.agent_fallback_llm_*` (was: `agent_llm_*`)
   - `agent_swarm/agent_loop.py:192–200` `_fallback_backend()` body reads `settings.agent_llm_*` (was: `agent_fallback_llm_*`)
   - `dispatch_mode.py:47` gate prefers `settings.agent_fallback_llm_api_key`, falls back to `settings.agent_llm_api_key`, declares `deterministic_only` only when both empty
   - **Budget tracking** (the 15+ `AGENT_LLM_USAGE_*` settings at `config.py:97–107`) now apply to the **new primary** (`AGENT_FALLBACK_LLM_*`) by default. Operators are warned on agent-loop init that thresholds are applied to the new primary — emit single WARNING log line: `"AGENT_FALLBACK_LLM_API_KEY is now PRIMARY; budget thresholds AGENT_LLM_USAGE_* are applied to its token counts. Review AGENT_LLM_USAGE_THRESHOLD_PERCENT / TOKENS_PER_PERCENT for the new provider's pricing."` Separate `AGENT_FALLBACK_LLM_USAGE_*` env family deferred to a future feature.
   - **Migration safety:** roll out in two steps — (1) merge code that prefers `AGENT_FALLBACK_LLM_*` but falls back to `AGENT_LLM_*` when fallback is unset (no flag day); (2) operators set `AGENT_FALLBACK_LLM_*` env values in production. Until step 2, scans transparently use the existing `AGENT_LLM_*` path.

8. **Migration strategy** — strictly additive. Single Alembic migration `0044_multi_kind_pipelines.py` (head is `0043`; revises `0043`):
   - Add `targets.kind_config` JSONB column (nullable)
   - Add `targets.kind_credentials_encrypted` LargeBinary column (nullable)
   - Add `scans.kind_payload` JSONB column (nullable)
   - Add `orgs.force_deterministic_only` Boolean column (`nullable=False, server_default=sa.text("false"), default=False`)
   - No data backfill
   - Downgrade drops the four columns

9. **Frontend** — extend `apps/web/components/register-target/target-types.ts`:
   - Existing 12 active type-cards remap their `kind` field from legacy `url/repo/llm` to the new kind values per the table in §2
   - Backward compatibility: API accepts legacy `url`/`repo`/`llm` on the wire indefinitely (existing rows + integrations)
   - Add 12 new per-kind form section components mirroring `url-form-section.tsx` / `llm-form-section.tsx`
   - Step-1 selector keeps current 8 categories (no re-grouping); cluster classification is internal to backend pipeline shapes only

---

## 6. Pipeline Shapes — Detail

### 6.1 DAST cluster — kind-filtered breaker roster

Code contract: `services/agent_swarm/breakers.py` adds `kind` parameter to `_build_breakers()`:

```python
# services/agent_swarm/breakers.py

KIND_TO_BREAKER_NAMES: dict[str, frozenset[str]] = {
    "url":       frozenset({"InjectionAgent", "ClientSideAgent", "AuthAgent", "AuthzAgent",
                            "APIAgent", "InfraAgent", "CloudAgent", "LLMRedTeamAgent",
                            "SupplyChainAgent", "K8sAgent", "ActiveDirectoryAgent",
                            "MobileAppAgent", "ThreatModelAgent"}),  # unchanged — all 13
    "web_app":   frozenset({"InjectionAgent", "ClientSideAgent", "AuthAgent", "AuthzAgent",
                            "APIAgent", "InfraAgent", "CloudAgent", "SupplyChainAgent",
                            "ThreatModelAgent"}),
    "rest_api":  frozenset({"InjectionAgent", "AuthAgent", "AuthzAgent", "APIAgent",
                            "InfraAgent", "ThreatModelAgent"}),
    "graphql":   frozenset({"InjectionAgent", "AuthAgent", "AuthzAgent",
                            "GraphQLFuzzAgent", "APIAgent", "ThreatModelAgent"}),
    "websocket": frozenset({"InjectionAgent", "AuthAgent", "AuthzAgent",
                            "APIAgent", "ThreatModelAgent"}),
    "grpc":      frozenset({"InjectionAgent", "AuthAgent", "AuthzAgent",
                            "GrpcReflectionAgent", "ThreatModelAgent"}),
    # llm: not in this map — uses existing single-stage _run_llm_scan path (see §6.5)
}

def _build_breakers(profile: str, snapshot, kind: str):
    if kind not in KIND_TO_BREAKER_NAMES:
        raise ValueError(f"DAST breaker roster not defined for kind={kind}")
    names = KIND_TO_BREAKER_NAMES[kind]
    return [(spec, agent) for spec, agent in _build_all_breakers(profile, snapshot)
            if spec.name in names]
```

**New BreakerSpec definitions** (added to `BREAKER_SPECS` in `breakers.py`):

```python
BreakerSpec(
    name="GraphQLFuzzAgent",
    mandate="GraphQL-specific: introspection, alias attacks, query depth DoS, "
            "directive injection, batched-query DoS, field suggestions",
    tools_exclusive=("run_graphql_cop", "run_inql", "scan_api"),
),
BreakerSpec(
    name="GrpcReflectionAgent",
    mandate="gRPC reflection-driven enumeration; primitive payload fuzzing on "
            "discovered methods; TLS verification",
    tools_exclusive=("run_grpcurl", "parse_proto", "scan_api"),
),
```

**New `BREAKER_TOOL_ALLOCATIONS` entries** in `tools.py`:

```python
BREAKER_TOOL_ALLOCATIONS = {
    # ... existing 13 entries unchanged ...
    "GraphQLFuzzAgent":      frozenset({"run_graphql_cop", "run_inql", "scan_api"}),
    "GrpcReflectionAgent":   frozenset({"run_grpcurl", "parse_proto", "scan_api"}),
}
# SHARED_BREAKER_TOOLS still adds {test_endpoint, get_findings, suppress_finding, finish}
```

**Phase 3 inclusion per kind:**

| Kind | Chain | Compliance | ProofOfImpact | PayloadCrafting | EvidenceCapture | AdminAccess |
|------|-------|------------|---------------|-----------------|-----------------|-------------|
| url (legacy) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| web_app | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| rest_api | ✅ | ✅ | ✅ | ✅ | — | — |
| graphql | ✅ | ✅ | ✅ | ✅ | — | — |
| websocket | ✅ | ✅ | — | ✅ | — | — |
| grpc | ✅ | ✅ | ✅ | ✅ | — | — |
| llm | (existing single-stage path; no swarm Phase 3) | — | — | — | — | — |

Kind-specific recon:
- `url` / `web_app`: existing ReconAgent (passive + active web crawl + api discovery + WAF)
- `rest_api`: import OpenAPI/Swagger spec if provided in `kind_config.api_spec`; else `recon_api_discovery`
- `graphql`: introspection query first, then schema enumeration; fall back to operator-supplied `schema_sdl`
- `websocket`: WS handshake + protocol negotiation
- `grpc`: gRPC reflection → service/method enumeration; fall back to operator-supplied `.proto` files
- `llm`: validate `llm_config` reachable; existing single-stage flow unchanged

### 6.2 Artifact cluster — new pipeline shape

**New entry point:** `services/scan_runner.py::_run_artifact_scan(scan, target, db_session_factory, on_event)` (see §6.5 for branching).

**New module:** `services/agent_swarm/artifact_orchestrator.py` defines `run_artifact_orchestrator()`.

Flow (each stage is one agent loop turn or one tool call):

```
1. Acquire artifact (agent calls one of these, with allowlist-checked args — §6.4):
   - clone_repo(url, ref, auth)         → local path
   - pull_image(ref, registry_auth)     → local OCI layout
   - download_artifact(url, hash)       → local file (e.g., tarball)
   - parse_sbom(content, format)        → in-memory SBOM tree
   - copy_from_session(session_id)      → re-use already-attached artifact

2. ArtifactReconAgent (NEW agent):
   - Catalog artifact: file tree, manifests, languages, layers, deps
   - Output: ArtifactSnapshot (analogous to ReconSnapshot — frozen)
   - Tools: list_files, read_manifest, detect_languages, inspect_layers

3. ScannerOrchestratorAgent (NEW agent — kind-aware tool allowlist):
   - Receives ArtifactSnapshot + per-kind scanner allowlist (below)
   - Calls scanners in agent loop; emits findings via existing copy_finding pattern
   - Scanners run SERIALLY inside the agent loop (one tool call per loop iter at
     agent_loop.py:585; no agent-internal parallelism). Phase-2-style asyncio.gather
     parallelism is NOT used inside the artifact orchestrator. This is a deliberate
     decision to keep agent_loop.py unchanged.
   - Per-kind scanner allowlist (KIND_TO_ARTIFACT_TOOLS):
       source_code:    run_semgrep, run_bandit, run_gosec, run_brakeman,
                       run_eslint, run_gitleaks, run_yara, run_osv_scanner
       container_image: run_trivy_image, run_syft, run_grype, run_hadolint,
                        run_trivy_secrets
       iac:            run_checkov, run_trivy_config, run_tfsec
       package_registry: run_osv_scanner, run_pip_audit, run_npm_audit
       sbom:           run_grype_sbom, run_osv_scanner_sbom

4. Merge findings into master session (existing copy_finding pattern)
5. Phase 3 reduced: ComplianceAgent only
6. Summary stitched, returned as SwarmOutcome-equivalent
```

**`source_code` uses `RepoScan` table, NOT `Scan`.** It plugs in at `repo_scan_task.py::run_repo_scan` and conditionally invokes `run_artifact_orchestrator()` instead of the existing static fan-out when `Target.kind == "source_code"`. The 4 other artifact kinds use the `scans` table with `kind_payload` and route through `_run_artifact_scan()` from `scan_runner.run_scan`.

**source_code vs legacy `repo` Target identity (addresses F-15).** A `source_code` target row is a **distinct Target row** with `kind="source_code"` and `kind_config` set; it MAY have `repository_id` set if the operator chose `kind_config.source="github_app"` (which auto-creates the Repository row for the org's GitHub App install) — that `repository_id` is the SAST artifact handle (cloned by `repo_scan_task` via existing GitHub App token path), not a "this is a repo-mirror" marker. Legacy repo-mirror rows (`kind="repo"` + `repository_id` set + no `kind_config`) keep their current behavior unchanged. The `effectiveKind()` helper in §10.1 trusts `t.kind` first and falls through to `repository_id` heuristic only for legacy rows (`t.kind == "repo"` with no `kind_config`). No automatic kind-flip of existing rows; operators register a new `source_code` target if they want the agent-orchestrated SAST flow.

### 6.3 Hybrid cluster (cicd_pipeline, k8s_cluster)

**New module:** `services/agent_swarm/hybrid_orchestrator.py` defines `run_hybrid_orchestrator()`.

Two phases:

**Phase A — Artifact analysis** (always runs):
- `cicd_pipeline`: parse `.github/workflows/*.yml`, `.gitlab-ci.yml`, `Jenkinsfile`, `azure-pipelines.yml`
- `k8s_cluster`: parse uploaded manifests (helm chart, kustomize, raw YAML)
- Uses `CicdConfigAuditAgent` (new) or `K8sManifestAuditAgent` (new — wraps checkov + trivy K8s)

**Phase B — Live recon + probing** (only if credentials provided in `kind_credentials_encrypted`):
- `cicd_pipeline`: hit CI provider API (GitHub Actions / GitLab / Jenkins REST) — enumerate workflows, secrets, deploy keys, runner pools
- `k8s_cluster`: hit K8s API with kubeconfig — list namespaces, RBAC bindings, network policies, exposed services
- Uses `K8sReconAgent` (new) + `RbacEnumAgent` (new — wraps rakkess via `run_security_tool` with extended `_DANGEROUS_ARG_SUBSTRINGS`)

**Phase 3:** Chain + Compliance.

**New BreakerSpecs:**
```python
BreakerSpec(name="CicdConfigAuditAgent", mandate="...", tools_exclusive=("run_checkov","run_gitleaks","run_yara")),
BreakerSpec(name="K8sManifestAuditAgent", mandate="...", tools_exclusive=("run_checkov","run_trivy_k8s_config")),
BreakerSpec(name="K8sReconAgent", mandate="...", tools_exclusive=("run_kubectl_get","run_kubectl_describe")),
BreakerSpec(name="RbacEnumAgent", mandate="...", tools_exclusive=("run_rakkess",)),
BreakerSpec(name="ArtifactReconAgent", mandate="...", tools_exclusive=("list_files","read_manifest","detect_languages","inspect_layers")),
BreakerSpec(name="ScannerOrchestratorAgent", mandate="...", tools_exclusive=()), # tools delivered dynamically per kind
```

### 6.4 Tool Input Allowlists & Sandbox Boundaries (NEW — addresses S-01)

**Per-tool allowlist contracts.** Every artifact-acquisition tool validates its inputs against the calling scan's `Target.kind_config` before invoking subprocess.

| Tool | Allowlist rule |
|------|----------------|
| `clone_repo(url, ref, auth)` | `url` MUST equal `target.kind_config.repo_url` OR be a prefix-match against a registered org GitHub App scope. NEVER agent-freeform URLs. `ref` is operator-specified or HEAD. `auth` resolved from `kind_credentials_encrypted` server-side (agent receives a credential handle, not raw creds). |
| `pull_image(ref, registry_auth)` | `ref` MUST equal `target.kind_config.image_ref` (or a digest that resolves to the same image). `registry_auth` resolved from `kind_credentials_encrypted`. |
| `download_artifact(url, hash)` | `url` host MUST be on operator-registered allowlist (`Target.kind_config.allowed_hosts` for that kind, or default per-kind allowlist e.g., `["registry.npmjs.org","pypi.org","oss-cdn.coc.io",...]`). `hash` REQUIRED for download integrity check. |
| `parse_sbom(content, format)` | `content` size ≤ 16 MiB. `format` ∈ allowed enum. No file path inputs (content is embedded JSON/XML). |
| `copy_from_session(session_id)` | `session_id` MUST belong to the same scan's pencheff session. Agent cannot reference arbitrary other sessions. |

**Sandbox isolation requirements:**
- `clone_repo` shells out as `git -c core.hooksPath=/dev/null clone --depth=1 --no-hardlinks <url>`. Sets `GIT_TERMINAL_PROMPT=0`, `GIT_ASKPASS=true` in env. Never uses `--recurse-submodules` by default.
- `pull_image` uses `skopeo copy docker://<ref> oci:/tmp/<scan_id>/oci-layout` (NOT `docker pull`, which executes entrypoints during pull on some daemons). Image layers are inspected via `oci-layout` without exec.
- `download_artifact` uses `httpx.get` with timeout + size cap; verifies `sha256(downloaded) == hash` before passing path to scanner.
- All scanners that have remote-mode flags use offline equivalents: `trivy image --offline-scan`, `osv-scanner --offline`, `syft --select-catalogers ...` without network catalogers.

**Extended `_DANGEROUS_ARG_SUBSTRINGS` (per S-07).** Add to `services/agent_runner.py:39-65`:
```python
_DANGEROUS_ARG_SUBSTRINGS = (
    # ... existing entries ...
    "--server",                # trivy: spawns remote-attack client
    "--listen",                # generic: bind on attacker-controlled port
    "--import-path",           # grpcurl: file read
    "--plaintext",             # grpcurl: forces no-TLS — security regression
    "--external-checks-dir",   # checkov: loads arbitrary Python
    "--custom-check-dir",      # tfsec: same
    "--post-renderer",         # helm: arbitrary executable
    "--values-from-stdin",     # helm: stdin injection
    "--output-file",           # syft: write outside sandbox (allowed only with /tmp/ prefix; checked separately)
)
```

**Sensitive credential lifecycle (per S-11).** Kubeconfigs, registry secrets, CI tokens decrypted for live probing MUST be:
1. Materialized only in-memory OR in `/tmp/<scan_id>/.kube/config` with mode 0600
2. Unlinked in the orchestrator's `finally` block (same pattern as existing breaker session cleanup at `orchestrator.py:482-489`)
3. Excluded from `scan_llm_traces.request_messages` via a redaction filter on tool arguments containing markers: `kubeconfig`, `cert-data`, `BEGIN PRIVATE KEY`, `BEGIN CERTIFICATE`, `client-key-data`, `client-certificate-data`
4. Excluded from SSE payloads (`publish_scan_event` filter)
5. NEVER passed in an LLM prompt — only tool wrappers see them; the model receives an opaque credential handle (`cred_ref="kc_<scan_id>"`)

### 6.5 Branch point in `scan_runner.run_scan`

`scan_runner.py::run_scan` branches **before** the existing `target.kind == "llm"` short-circuit at line 523, **after** consent + threat-model setup at lines 425-448. Concretely:

```python
# scan_runner.py — after consent + threat-model setup, before existing kind branches
if target.kind == "llm":
    # EXISTING — preserved unchanged
    return await _run_llm_scan(...)

if target.kind == "url":
    # EXISTING — preserved unchanged (full deterministic populator + swarm flow)
    return await _run_url_scan_existing(...)

# NEW — kind-aware dispatch for the 9 new non-repo kinds
# (source_code goes through repo_scan_task, not here — see §6.2)
return await _run_kind_aware_scan(scan, target, db_session_factory, on_event)
```

`_run_kind_aware_scan` signature:
```python
async def _run_kind_aware_scan(
    scan: Scan,
    target: Target,
    db_session_factory: Any,
    on_event: LogSink,
) -> None:
    """Branch to DAST / Artifact / Hybrid pipeline shape by Target.kind."""
    kind = target.kind
    if kind in KIND_TO_BREAKER_NAMES:        # DAST cluster: web_app, rest_api, graphql, websocket, grpc
        return await _run_dast_scan(scan, target, kind, db_session_factory, on_event)
    if kind in {"container_image", "iac", "package_registry", "sbom"}:  # Artifact cluster (source_code excluded — handled by repo_scan_task)
        return await _run_artifact_scan(scan, target, kind, db_session_factory, on_event)
    if kind in {"cicd_pipeline", "k8s_cluster"}:  # Hybrid cluster
        return await _run_hybrid_scan(scan, target, kind, db_session_factory, on_event)
    raise ValueError(f"unsupported target kind: {kind}")
```

**Backward compatibility (AC-0.3):** `kind="llm"` keeps its existing `_run_llm_scan` path. No promotion to DAST swarm. The §6.1 KIND_TO_BREAKER_NAMES table does NOT include `llm`.

---

## 7. Data Model Changes

### 7.1 Alembic migration `0044_multi_kind_pipelines.py`

```python
"""multi-kind scan pipelines

Revision ID: 0044
Revises: 0043
Create Date: 2026-05-16
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0044"
down_revision = "0043"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Per-kind config for the 11 new non-llm kinds (web_app, rest_api, graphql, websocket,
    # grpc, source_code, cicd_pipeline, iac, container_image, k8s_cluster, package_registry, sbom).
    op.add_column(
        "targets",
        sa.Column("kind_config", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    )

    # Per-kind credentials for kinds with structurally different secrets:
    # container_image (registry auth), k8s_cluster (kubeconfig), cicd_pipeline (CI tokens).
    # Other kinds keep using credentials_encrypted. Fernet-encrypted JSONB-after-decrypt blob.
    op.add_column(
        "targets",
        sa.Column("kind_credentials_encrypted", sa.LargeBinary(), nullable=True),
    )

    # Per-scan artifact descriptor + scan metadata. Carries: artifact_ref, scanner subset,
    # per-kind options. Nullable so existing url/llm scans see NULL.
    op.add_column(
        "scans",
        sa.Column("kind_payload", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    )

    # Org-level kill switch for the agent loop. NOT NULL DEFAULT false is safe in PG >=11.
    op.add_column(
        "orgs",
        sa.Column(
            "force_deterministic_only",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
    )


def downgrade() -> None:
    op.drop_column("orgs", "force_deterministic_only")
    op.drop_column("scans", "kind_payload")
    op.drop_column("targets", "kind_credentials_encrypted")
    op.drop_column("targets", "kind_config")
```

### 7.2 SQLAlchemy model changes (`db/models.py`)

```python
class Target(Base):
    # ... existing fields preserved ...
    kind_config: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    kind_credentials_encrypted: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    # llm_config remains source of truth for kind="llm"; kind_config for the 11 new non-llm kinds.

class Scan(Base):
    # ... existing fields preserved ...
    kind_payload: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

class Org(Base):
    # ... existing fields preserved ...
    force_deterministic_only: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default=sa.text("false"), default=False,
    )
```

**Model-validator additions** (`schemas/targets.py`):

```python
@model_validator(mode="after")
def _validate_kind_config(self) -> "TargetCreate":
    NEW_KINDS_REQUIRE_CONFIG = {"web_app","rest_api","graphql","websocket","grpc",
                                "source_code","cicd_pipeline","iac","container_image",
                                "k8s_cluster","package_registry","sbom"}
    if self.kind in NEW_KINDS_REQUIRE_CONFIG and self.kind_config is None:
        raise ValueError(f"kind={self.kind!r} requires kind_config")
    if self.kind in {"url","repo","llm"} and self.kind_config is not None:
        raise ValueError(f"kind_config not allowed for legacy kind={self.kind!r}")
    if self.kind_config is not None and self.kind_config.get("kind") != self.kind:
        raise ValueError(f"kind_config.kind must match Target.kind ({self.kind})")
    return self
```

### 7.3 Pydantic discriminated union `KindConfig` (`schemas/targets.py`)

Every variant has `model_config = ConfigDict(extra="forbid")` to prevent silent field drops (B-003).

```python
from pydantic import BaseModel, Field, HttpUrl, ConfigDict
from typing import Annotated, Literal, Union

class _Base(BaseModel):
    model_config = ConfigDict(extra="forbid")

class WebAppConfig(_Base):
    kind: Literal["web_app"] = "web_app"
    crawl_depth: int = Field(default=3, ge=1, le=10)
    max_pages: int = Field(default=100, ge=1, le=1000)
    browser_render: bool = True
    api_spec_url: HttpUrl | None = None

class RestApiConfig(_Base):
    kind: Literal["rest_api"] = "rest_api"
    api_spec: dict | None = None
    api_spec_url: HttpUrl | None = None
    api_spec_format: Literal["openapi3","swagger2","postman","auto"] = "auto"
    auth_in_spec: bool = True

class GraphqlConfig(_Base):
    kind: Literal["graphql"] = "graphql"
    introspection_enabled: bool = True
    schema_sdl: str | None = None  # required if introspection_enabled=False
    max_query_depth: int = Field(default=10, ge=1, le=50)
    operations_to_test: list[Literal["query","mutation","subscription"]] = Field(default_factory=lambda: ["query","mutation"])

class WebsocketConfig(_Base):
    kind: Literal["websocket"] = "websocket"
    subprotocols: list[str] = Field(default_factory=list)
    origin_header: str | None = None
    auth_token_in_query: str | None = None

class GrpcConfig(_Base):
    kind: Literal["grpc"] = "grpc"
    reflection_enabled: bool = True
    proto_files: list[str] | None = None  # required if reflection_enabled=False
    tls_verify: bool = True

class SourceCodeConfig(_Base):
    kind: Literal["source_code"] = "source_code"
    source: Literal["github_url","github_app","local_path","tarball_url"] = "github_url"
    repo_url: HttpUrl | None = None  # required if source ∈ {github_url, tarball_url}
    git_ref: str = "HEAD"
    languages_hint: list[str] | None = None
    scanners_disabled: list[str] = Field(default_factory=list)

class CicdPipelineConfig(_Base):
    kind: Literal["cicd_pipeline"] = "cicd_pipeline"
    provider: Literal["github_actions","gitlab_ci","jenkins","azure_pipelines","circleci"]
    repo_url: HttpUrl | None = None
    config_paths: list[str] = Field(default_factory=list)
    live_api_enabled: bool = False  # if True, kind_credentials_encrypted REQUIRED

class IacConfig(_Base):
    kind: Literal["iac"] = "iac"
    frameworks: list[Literal["terraform","cloudformation","helm","kustomize","arm"]] = Field(default_factory=lambda: ["terraform"])
    source: Literal["repo","tarball_url","local_path"] = "repo"
    repo_url: HttpUrl | None = None

class ContainerImageConfig(_Base):
    kind: Literal["container_image"] = "container_image"
    image_ref: str = Field(min_length=1)
    registry: Literal["dockerhub","ecr","gcr","ghcr","acr","custom"] = "dockerhub"
    scan_layers: bool = True
    scan_secrets: bool = True
    scan_misconfigs: bool = True

class K8sClusterConfig(_Base):
    kind: Literal["k8s_cluster"] = "k8s_cluster"
    target: Literal["manifests_only","live_cluster"] = "manifests_only"
    manifests_archive_url: HttpUrl | None = None  # required if target=="manifests_only"
    namespaces: list[str] = Field(default_factory=lambda: ["default"])
    rbac_enum: bool = True
    network_policy_audit: bool = True

class PackageRegistryConfig(_Base):
    kind: Literal["package_registry"] = "package_registry"
    ecosystem: Literal["npm","pypi","maven","cargo","gem","composer","go","nuget"]
    package_list: list[dict] = Field(min_length=1)  # [{name, version}, ...]
    include_dev: bool = False

class SbomConfig(_Base):
    kind: Literal["sbom"] = "sbom"
    format: Literal["cyclonedx-json","cyclonedx-xml","spdx-json","spdx-tag-value"]
    content: str | None = None  # inline (≤ 16 MiB after encoding)
    url: HttpUrl | None = None  # OR remote SBOM
    check_licenses: bool = True
    check_suppliers: bool = True

KindConfig = Annotated[
    Union[WebAppConfig, RestApiConfig, GraphqlConfig, WebsocketConfig, GrpcConfig,
          SourceCodeConfig, CicdPipelineConfig, IacConfig, ContainerImageConfig,
          K8sClusterConfig, PackageRegistryConfig, SbomConfig],
    Field(discriminator="kind"),
]
```

### 7.3.1 Pydantic discriminated union `KindPayload` (NEW — addresses F-14 / B-019)

`Scan.kind_payload` carries per-scan overrides + derived data from `Target.kind_config`. Server-side, `kind_payload` is **derived** from `Target.kind_config` at scan-creation time; clients MAY supply overrides for specific operational fields (e.g., container_image digest pinning per scan).

```python
class _PayloadBase(BaseModel):
    model_config = ConfigDict(extra="forbid")

class WebAppPayload(_PayloadBase):
    kind: Literal["web_app"] = "web_app"
    crawl_depth_override: int | None = Field(default=None, ge=1, le=10)
    max_pages_override: int | None = Field(default=None, ge=1, le=1000)

class RestApiPayload(_PayloadBase):
    kind: Literal["rest_api"] = "rest_api"
    api_spec_override: dict | None = None  # one-time spec override

# ... similar for all 12 new kinds, each typically with only operational override fields ...

class ContainerImagePayload(_PayloadBase):
    kind: Literal["container_image"] = "container_image"
    digest_override: str | None = None  # pin to specific digest for this scan
    skip_layers: list[int] | None = None

class SbomPayload(_PayloadBase):
    kind: Literal["sbom"] = "sbom"
    # SBOMs are typically static per scan; payload is normally empty/derived

KindPayload = Annotated[
    Union[WebAppPayload, RestApiPayload, GraphqlPayload, WebsocketPayload, GrpcPayload,
          SourceCodePayload, CicdPipelinePayload, IacPayload, ContainerImagePayload,
          K8sClusterPayload, PackageRegistryPayload, SbomPayload],
    Field(discriminator="kind"),
]
```

`ScanCreate` Pydantic schema (`schemas/scans.py`) gets:
```python
class ScanCreate(BaseModel):
    # ... existing fields ...
    kind_payload: KindPayload | None = None  # required for the 8 new non-source_code/non-legacy kinds

    @model_validator(mode="after")
    def _validate_kind_payload(self) -> "ScanCreate":
        # router enforces kind_payload.kind == Target.kind via 400 response (target loaded in router)
        return self
```

### 7.4 Per-kind credentials (NEW — addresses B-005 / F-07 / S-02)

`Target.kind_credentials_encrypted` is a Fernet-encrypted blob; decrypted to a Pydantic discriminated union:

```python
class _CredBase(BaseModel):
    model_config = ConfigDict(extra="forbid")

class KubeconfigCreds(_CredBase):
    kind: Literal["k8s_cluster"] = "k8s_cluster"
    kubeconfig: str = Field(min_length=10, max_length=65536)  # ≤ 64 KiB
    context: str | None = None  # which context to use

class RegistryCreds(_CredBase):
    kind: Literal["container_image"] = "container_image"
    registry_host: str
    auth_type: Literal["basic","token","docker_config","ecr_sts","gcr_service_account","acr_sp"]
    username: str | None = None
    password_or_token: str | None = None
    docker_config_json: str | None = None  # for auth_type=docker_config
    gcr_service_account_json: str | None = None
    ecr_sts_role_arn: str | None = None
    acr_client_id: str | None = None
    acr_client_secret: str | None = None
    acr_tenant_id: str | None = None

class CicdCreds(_CredBase):
    kind: Literal["cicd_pipeline"] = "cicd_pipeline"
    provider: Literal["github_actions","gitlab_ci","jenkins","azure_pipelines","circleci"]
    token: str | None = None  # PAT, project token, etc.
    github_app_id: str | None = None  # github_actions only
    github_app_private_key: str | None = None  # github_actions only, PEM
    jenkins_user: str | None = None  # jenkins only

class SourceCodeCreds(_CredBase):
    kind: Literal["source_code"] = "source_code"
    auth_type: Literal["pat","github_app","ssh_key"]
    pat: str | None = None  # auth_type=pat
    github_app_id: str | None = None  # auth_type=github_app
    github_app_private_key: str | None = None  # auth_type=github_app, PEM ≤ 8 KiB
    github_app_installation_id: str | None = None  # auth_type=github_app
    ssh_private_key: str | None = None  # auth_type=ssh_key, PEM ≤ 8 KiB

KindCredentials = Annotated[
    Union[KubeconfigCreds, RegistryCreds, CicdCreds, SourceCodeCreds],
    Field(discriminator="kind"),
]
```

**`TargetCreate` / `TargetUpdate` / `TargetOut` API surface for `kind_credentials`** (mirrors existing `credentials` / `clear_credentials` pattern):

```python
class TargetCreate(BaseModel):
    # ... existing fields ...
    kind_config: KindConfig | None = None
    kind_credentials: KindCredentials | None = None

class TargetUpdate(BaseModel):
    # ... existing fields ...
    kind_config: KindConfig | None = None         # None = leave unchanged
    clear_kind_config: bool = False               # True = nullify
    kind_credentials: KindCredentials | None = None
    clear_kind_credentials: bool = False

class TargetOut(BaseModel):
    # ... existing fields ...
    kind_config: KindConfig | None = None         # safe to expose (no secrets)
    has_kind_credentials: bool = False            # SECRETS NEVER RETURNED
```
```

**Redaction rules:**
- GET `/targets` and GET `/targets/{id}` NEVER return `kind_credentials_encrypted` content. Field is presented as `has_kind_credentials: bool` on `TargetOut`.
- Field is excluded from `scan_llm_traces.request_messages` via redaction filter (§6.4 sandbox lifecycle).
- Field is excluded from SSE payloads.
- Size cap enforced per-field at the Pydantic layer (kubeconfig ≤ 64 KiB; PEM ≤ 8 KiB).

---

## 8. Dispatch Mode Extension (corrected — addresses B-006 / B-007)

`services/dispatch_mode.py::resolve_dispatch_mode` signature extends to accept `target_kind`. Layered checks:

```python
async def resolve_dispatch_mode(
    session: AsyncSession,
    org_id: str,
    target_kind: str,  # NEW parameter
) -> DispatchMode:
    settings = get_settings()

    # NEW (S-04): org-level kill switch (precedence #1)
    org = (await session.execute(select(Org).where(Org.id == org_id))).scalar_one_or_none()
    if org and org.force_deterministic_only:
        return "deterministic_only"

    # NEW: kind-level capability check (precedence #2)
    if not _kind_supports_agent(target_kind):
        return "deterministic_only"

    # CHANGED (per §5.7): prefer new primary (AGENT_FALLBACK_LLM_*), accept either set
    if not (settings.agent_fallback_llm_api_key or settings.agent_llm_api_key):
        return "deterministic_only"

    if settings.agent_dispatch_beta_override:
        return "deterministic_then_agent"

    # ... existing plan + quota logic at lines 51-67, unchanged ...
```

**`_kind_supports_agent` (all 15 kinds default to True):**
```python
def _kind_supports_agent(kind: str) -> bool:
    # All kinds are agent-capable; helper kept for future per-kind toggles.
    KNOWN_KINDS = {"url","repo","llm","web_app","rest_api","graphql","websocket","grpc",
                   "source_code","cicd_pipeline","iac","container_image","k8s_cluster",
                   "package_registry","sbom"}
    return kind in KNOWN_KINDS
```

**Call site updates:**

| Caller | File:Line today | `target_kind` passed |
|--------|-----------------|----------------------|
| `_engine` in scan_runner.run_scan | scan_runner.py:647 | `target.kind` (loaded from DB earlier) |
| Legacy `repo_scan_task.run_repo_scan` | repo_scan_task.py (not yet a caller; exempt) | **NOT CALLED** — legacy repo path bypasses kind-aware dispatch. RepoScan rows have an attached `Target` row with `kind="repo"` or `kind="source_code"`; only `source_code` enters the agent-orchestrated path inside `run_repo_scan`. |
| `_run_kind_aware_scan` | scan_runner.py (new) | `target.kind` (already in scope) |
| Scheduled scan task | scheduled_scan_task.py (creates scan rows, doesn't dispatch directly) | N/A — dispatch happens inside `run_full_scan` → `run_scan` → `_engine` |

**Backward compat:** existing single call site at `scan_runner.py:647` keeps working — the `target` row is loaded earlier in `run_scan`, so `target.kind` is available.

---

## 9. Fallback Engine (revised — addresses §6.6 fallback engagement)

Three NEW failure paths beyond today's "no API key → deterministic_only":

1. **LLM API failures persisting after retry** — `_TransientLLMError` propagates from primary+secondary both having failed. Orchestrator catches; if count of failed breakers ≥ `fallback_threshold_failed_breakers` (config, default = ⌈breakers/2⌉), the remaining scan stages transition to deterministic.

2. **Repeated malformed tool calls / low confidence** — NEW condition in `_run_single_agent`: if 3 consecutive turns produce no valid tool call (empty `tool_calls`, or all rejected by `_reject_tool_call`), the orchestrator sets `force_deterministic_for_remainder=True` and skips remaining agent phases. The deterministic scanner pool defined per kind runs to completion.

3. **Org config flag** — `Org.force_deterministic_only=True` short-circuits at `resolve_dispatch_mode` (§8).

**Trace storage (addresses B-013).** Fallback engagement records one sentinel row in `scan_llm_traces`:

```python
ScanLLMTrace(
    scan_id=scan_id,
    agent_name="FallbackController",
    turn=0,
    request_messages=[{"role": "system", "content": "fallback marker"}],  # NOT NULL stub
    request_tools_count=0,
    response_content=f"deterministic_fallback engaged: reason={reason}",
    response_tool_calls=None,
    response_reasoning=None,
    prompt_tokens=0,
    completion_tokens=0,
    cached_tokens=0,
    reasoning_tokens=0,
)
```

`reason` ∈ `{"api_failures_after_retry", "malformed_tool_calls", "org_force_deterministic_only", "no_api_key"}`.

Audit consumers can distinguish `FallbackController` rows by the `agent_name` sentinel.

---

## 10. Frontend Changes (rewritten — addresses F-01 / F-02 / F-03 / F-04 / F-05 / F-06 / F-08 / F-09 / F-10 / F-11 / F-12 / F-13 / F-14 / F-15 / F-16 / F-17 / F-18)

### 10.1 Type-card kind remapping + SupportedKind expansion

**Current state (verified against `apps/web/components/register-target/target-types.ts`):** all 12 active type-cards (across 8 categories) map to one of `kind: "url" | "repo" | "llm"`. Spec extends this mapping so each type-card maps to its own first-class `kind`.

**SupportedKind type expansion** (in `apps/web/lib/types.ts` or wherever defined):
```typescript
export type SupportedKind =
  | "url" | "repo" | "llm"  // legacy — preserved on the wire indefinitely
  | "web_app" | "rest_api" | "graphql" | "websocket" | "grpc"
  | "source_code" | "cicd_pipeline" | "iac"
  | "container_image" | "k8s_cluster"
  | "package_registry" | "sbom";
```

**Type-card-id → wire-kind mapping table** (normative — `target-types.ts::CATEGORIES`):

| Type card id (kebab) | Pre-feature kind | Post-feature kind (snake) |
|----------------------|------------------|---------------------------|
| `web-app` | `url` | `web_app` |
| `rest-api` | `url` | `rest_api` |
| `graphql-api` | `url` | `graphql` |
| `websocket` | `url` | `websocket` |
| `grpc` | `url` | `grpc` |
| `source-code-repo` | `repo` | `source_code` |
| `cicd-pipeline` | `repo` | `cicd_pipeline` |
| `iac` | `repo` | `iac` |
| `container-image` | `repo` | `container_image` |
| `kubernetes` | `repo` | `k8s_cluster` |
| `package-registry` | `repo` | `package_registry` |
| `sbom-deps` | `repo` | `sbom` |
| `chat-completions`, `embeddings-api`, … (existing LLM cards) | `llm` | `llm` (unchanged) |

**Naming convention (addresses F-02):** wire `kind` values are snake_case (matching Pydantic Literal); FE type-card IDs are kebab-case (matching existing convention in `target-types.ts`). The two namespaces never mix.

**Step-1 selector grouping (addresses F-03):** keep current 8 categories. Cluster classification (DAST/Artifact/Hybrid) is internal to backend pipeline-shape selection ONLY; the UI does NOT regroup by cluster.

**Backward compatibility (addresses F-01, F-18):** API accepts legacy `url`/`repo`/`llm` wire values indefinitely. Existing rows untouched. FE legacy-list rendering (`effectiveKind()` in `targets/page.tsx:51-54`) updates to prefer `t.kind` over `t.repository_id`-derived heuristics; the heuristic only fires for legacy rows.

**effectiveKind helper update (addresses F-15):**
```typescript
function effectiveKind(t: Target): SupportedKind {
  // Trust the wire field first.
  if (t.kind && KNOWN_KINDS.has(t.kind)) return t.kind as SupportedKind;
  // Legacy fallback: repo_mirror rows without explicit kind.
  if (t.repository_id) return "repo";
  return "url";
}
```

**Icon assignments per kind (addresses F-17):** each new kind gets an inline SVG icon in `step-1-type-selector.tsx` following the existing pattern. The 12 SVGs ship in `target-types.ts` icons map. Specific assignments deferred to plan.md.

### 10.2 Per-kind form section components

Create 12 new components, one per new kind, in `apps/web/components/register-target/`:

| File | Fields |
|------|--------|
| `web-app-form-section.tsx` | crawl_depth (1-10), max_pages (1-1000), browser_render toggle, api_spec_url |
| `rest-api-form-section.tsx` | api_spec (paste/upload), api_spec_url, api_spec_format radio, auth_in_spec toggle |
| `graphql-form-section.tsx` | introspection toggle; if off → schema_sdl textarea; max_query_depth; operations checkboxes |
| `websocket-form-section.tsx` | subprotocols list, origin_header, auth_token_in_query |
| `grpc-form-section.tsx` | reflection toggle; if off → proto_files list; tls_verify toggle |
| `source-code-form-section.tsx` | source radio (4 options); if github_url/tarball_url → repo_url; git_ref; languages_hint multiselect; scanners_disabled multiselect |
| `cicd-pipeline-form-section.tsx` | provider radio (5 options), repo_url, config_paths list, live_api_enabled toggle → if true: provider-specific credentials |
| `iac-form-section.tsx` | frameworks multi-select (5), source-type radio (3), repo_url |
| `container-image-form-section.tsx` | image_ref, registry radio (6), scan flag checkboxes, registry-type-conditional credentials |
| `k8s-cluster-form-section.tsx` | target radio (manifests_only/live_cluster); if live_cluster → kubeconfig textarea + context name; if manifests_only → manifests_archive_url; namespaces list; rbac_enum toggle; network_policy_audit toggle |
| `package-registry-form-section.tsx` | ecosystem radio (8), package_list textarea / file upload, include_dev toggle |
| `sbom-form-section.tsx` | format radio (4), content paste / file upload OR url, check_licenses toggle, check_suppliers toggle |

**Shared component contract (addresses F-05):** each per-kind section is a self-contained React component accepting `(value: KindConfigByKind[K], onChange: (v) => void, mode: "create" | "edit", errors?: Record<string,string>)` props. No internal state. Consumed by BOTH `new/page.tsx` and `[id]/edit/page.tsx`.

**Conditional rendering rules (addresses F-08):**

| Kind | Condition | Effect |
|------|-----------|--------|
| graphql | `introspection_enabled=false` | Show + require `schema_sdl` |
| grpc | `reflection_enabled=false` | Show + require `proto_files` |
| source_code | `source ∈ {github_url, tarball_url}` | Show + require `repo_url` |
| source_code | `source == github_app` | Show GitHub App install/select widget |
| cicd_pipeline | `live_api_enabled=true` | Show + require provider-specific credentials section |
| container_image | `registry != dockerhub` | Show registry-specific credentials section (ECR / GCR / ACR / custom) |
| k8s_cluster | `target == "live_cluster"` | Show + require kubeconfig textarea + context; hide manifests upload |
| k8s_cluster | `target == "manifests_only"` | Show + require manifests_archive_url; hide kubeconfig |
| package_registry | `ecosystem == npm` | Lockfile placeholder = `package-lock.json` content |
| package_registry | `ecosystem == pypi` | Lockfile placeholder = `requirements.txt` content |
| sbom | `content != null` | Hide `url`; show paste/upload UI |
| sbom | `url != null` | Hide content; show URL input |

**Multi-kind submission cap (addresses F-12):** when any new (non-legacy) kind is selected on the Step-1 selector, multi-kind submission is disabled (single kind per registration). Legacy kinds (`url`+`repo`+`llm`) keep their existing multi-select capability.

**a11y (addresses F-13):** new sections follow existing patterns — explicit `htmlFor` IDs, `role="radiogroup"` / `aria-checked` for radio groups, `role="alert"` for inline error regions. No new Radix/Headless UI dependency. Step-1 selector keyboard nav tested at 12 cards.

### 10.3 List page extensions (`app/targets/page.tsx`)

**Coverage badges map per kind (addresses F-09):**

```typescript
const COVERAGE_BADGES_BY_KIND: Record<SupportedKind, string[]> = {
  url:              ["DAST"],
  repo:             ["SAST", "SCA", "SECRETS"],
  llm:              ["LLM_RED_TEAM"],
  web_app:          ["DAST"],
  rest_api:         ["DAST", "API"],
  graphql:          ["DAST", "API"],
  websocket:        ["DAST", "API"],
  grpc:             ["DAST", "API"],
  source_code:      ["SAST", "SCA", "SECRETS"],
  cicd_pipeline:    ["CI", "SAST", "SECRETS"],
  iac:              ["IAC"],
  container_image:  ["CONTAINER", "SCA", "SECRETS"],
  k8s_cluster:      ["K8S"],
  package_registry: ["SCA"],
  sbom:             ["SBOM", "SCA"],
};
```

New badge color tokens to add to `COVERAGE_STYLES`: `CI`, `IAC`, `CONTAINER`, `K8S`, `SBOM`, `API`.

**TypeBadge styles** — extend `TYPE_BADGE_STYLES` map with one entry per new kind (12 new entries), each with a kind-appropriate color.

**Stat tiles** — un-dim existing Containers + IaC tiles. Add new K8S and CI tiles (deferred — first cut may show "—" for empty kinds).

**Filter tabs** — extend filter tab list to include the 12 new kinds. Group visually by category (mirroring 8 Step-1 categories).

### 10.4 Detail page extensions (`app/targets/[id]/page.tsx`)

**Per-kind renderer pattern:** one `<KindConfigView>` switching component renders the appropriate `<dl>` per kind. Every non-default `kind_config` field becomes a `<dt>/<dd>` row. For credentials presence, render a "Credentials configured" badge or "No credentials" placeholder.

```tsx
function KindConfigView({ target }: { target: Target }) {
  if (!target.kind_config) return null;
  switch (target.kind) {
    case "web_app":     return <WebAppConfigView config={target.kind_config as WebAppConfig} />;
    case "rest_api":    return <RestApiConfigView config={target.kind_config as RestApiConfig} />;
    // ... 10 more cases ...
    default: return null;
  }
}
```

Each `<XxxConfigView>` renders a `<dl>` with the minimal field set per kind (deferred to plan.md task breakdown).

### 10.5 Submit flow (addresses F-06 / F-10)

**POST routing per kind:**

| Kind | Endpoint | Notes |
|------|----------|-------|
| `url`, `llm`, `web_app`, `rest_api`, `graphql`, `websocket`, `grpc`, `container_image`, `iac`, `cicd_pipeline`, `k8s_cluster`, `package_registry`, `sbom` | POST `/scans` | `kind_payload` body field required for the 9 NEW non-source_code kinds |
| `repo` (legacy), `source_code` | POST `/repos/{id}/scan` | Existing path preserved |

**kind_payload provenance:** server-derives `kind_payload` from `Target.kind_config` at scan-creation time. Client MAY send a partial `kind_payload` with operational overrides (e.g., `container_image_payload.digest_override`); server merges and validates. The frontend's `CommissionScanModal` collects these overrides only when applicable per kind.

**File upload contract (addresses F-10):** all payloads remain JSON. Files (SBOM content, kubeconfig, package.json, manifest tarballs) are read client-side via `FileReader.readAsText` (size ≤ 1 MiB) and embedded as strings into the appropriate `kind_config` or `kind_credentials` field. No new `/uploads` endpoint. The form sections enforce size and format hints inline.

### 10.6 Consent kind-awareness (addresses S-03)

`disclosed_actions` (`schemas/scans.py::ConsentPayload`) becomes a kind-aware enum-superset. Per-kind required-action map:

```python
KIND_REQUIRED_DISCLOSED_ACTIONS: dict[str, frozenset[str]] = {
    "url":              frozenset({"passive_recon", "active_recon", "exploitation"}),
    "web_app":          frozenset({"passive_recon", "active_recon", "exploitation"}),
    "rest_api":         frozenset({"passive_recon", "api_fuzzing", "exploitation"}),
    "graphql":          frozenset({"introspection_query", "api_fuzzing", "exploitation"}),
    "websocket":        frozenset({"ws_handshake", "api_fuzzing", "exploitation"}),
    "grpc":             frozenset({"grpc_reflection", "api_fuzzing", "exploitation"}),
    "llm":              frozenset({"llm_red_team_prompts"}),
    "repo":             frozenset({"source_code_scan"}),
    "source_code":      frozenset({"source_code_scan", "clone_repo"}),
    "container_image":  frozenset({"image_pull", "container_scan"}),
    "iac":              frozenset({"iac_scan", "clone_repo"}),
    "package_registry": frozenset({"dependency_scan", "registry_query"}),
    "sbom":             frozenset({"sbom_scan", "vuln_db_query"}),
    "cicd_pipeline":    frozenset({"ci_config_audit"}),  # add "ci_api_read" if live_api_enabled
    "k8s_cluster":      frozenset({"k8s_manifest_scan"}),  # add "k8s_api_read","rbac_enumeration" if live_cluster
}
```

**Router enforcement** (`routers/scans.py::start_scan`): after validating the request's `consent_payload`, check `set(KIND_REQUIRED_DISCLOSED_ACTIONS[target.kind]).issubset(set(consent.disclosed_actions))`. Reject with 400 if missing required actions, listing exactly which actions are missing.

**Frontend:** per-kind form sections surface their required-actions vocabulary by default; operators may add to it. `authorization_text` remains free-form ≥50 chars.

### 10.7 Per-kind UX states (addresses F-11)

| State | Per-kind handling |
|-------|-------------------|
| Empty (no scans) | DAST kinds: existing "10-25 minutes" copy. Artifact kinds: "Upload artifact and trigger scan — typically completes in <2 minutes". |
| Scan-trigger failure | Existing `advisory-warn` div; extend with kind-aware error templates (e.g., "Failed to pull container image: <reason>") |
| Partial results | Existing pattern (some scanners succeed, others fail) preserved; `Scan.stats` JSONB extended with per-scanner duration + error |
| Loading during file upload | Per-kind form section shows progress indicator + size readback during paste/upload |

### 10.8 Mobile responsive (addresses F-12)

Multi-kind cap (above) plus: per-kind form sections use `formal-surface-elev p-8 md:p-10` (existing pattern). Step-2 layout on `<640px` viewports collapses Section A2 (credentials) from 5-cell grid to single-column vertical stack.

---

## 11. Migration Strategy

**Strictly additive:**
- New `targets.kind_config` column (nullable)
- New `targets.kind_credentials_encrypted` column (nullable)
- New `scans.kind_payload` column (nullable)
- New `orgs.force_deterministic_only` column (NOT NULL DEFAULT false)
- Existing `url`/`repo`/`llm` rows untouched
- Legacy `scan_task.py` / `repo_scan_task.py` code paths preserved (source_code adds new branch inside `run_repo_scan`)
- New kinds dispatch to new code paths via `_run_kind_aware_scan`
- No alembic data backfill

**Backward compatibility:**
- `Target.llm_config` continues authoritative for `kind="llm"`. New kinds use `kind_config`.
- API accepts legacy `url`/`repo`/`llm` wire kind values indefinitely.
- Existing FE rendering paths preserved; new kinds wire into existing UI primitives.

**LLM creds swap rollout:**
- Step 1: ship code that reads `AGENT_FALLBACK_LLM_*` first, falls back to `AGENT_LLM_*` automatically — no env-var change required for existing operators.
- Step 2: operators set `AGENT_FALLBACK_LLM_*` env vars to make the swap explicit.
- Until Step 2, scans transparently use the existing `AGENT_LLM_*` credentials with NO behavior change.

**Migration ordering:**
- Migration `0044_multi_kind_pipelines.py` adds columns (zero-downtime additive).
- Application deploys following migration (reads new columns conditionally).
- No data migration required.

---

## 12. Non-Goals

- Re-architecting existing `url`, `repo`, `llm` flows.
- Rewriting `agent_swarm/orchestrator.py` (extending entry points + roster filtering only).
- Building new scanners from scratch (we wrap existing tools).
- LLM-payload-generation — agent only sequences existing scanners; does NOT emit fuzz payloads.
- Cost caps (per locked decision: no cost-cap fallback trigger).
- Per-org per-kind LLM provider selection (single primary/secondary stays org-global).
- Real-time scanner streaming (results merge after each scanner completes — existing pattern).
- New audit-log table beyond `scan_llm_traces`.
- Editing existing 13 breakers' system prompts (only add new agents).
- Parallel scanner execution within a single agent loop (agent_loop.py:585 stays serial).
- Re-grouping Step-1 type selector into 3 clusters (keep 8 categories).
- `/uploads` REST endpoint for file inputs (files embedded as strings in JSON).

---

## 13. Risks

| Risk | Severity | Mitigation |
|------|----------|------------|
| Artifact tools (clone_repo, pull_image, download_artifact) pivot to attacker-controlled sources | **HIGH** | §6.4 mandates allowlist on every tool input vs `Target.kind_config`; `git -c core.hooksPath=/dev/null`; `skopeo copy` not `docker pull`; offline scanner modes; subprocess sandbox isolation |
| New scanner CLIs have shell-pivot flags | **HIGH** | Extended `_DANGEROUS_ARG_SUBSTRINGS` (§6.4); explicit allowlist subset per new tool |
| Credentials swap breaks scans during deployment | **HIGH** | Two-step rollout (§5.7 / §11); no flag day; auto-fallback to AGENT_LLM_* while AGENT_FALLBACK_LLM_* unset |
| Kubeconfig leak via traces / SSE / logs | **HIGH** | §6.4 lifecycle rules: in-memory or `/tmp/<scan_id>/.kube/config` mode 0600; redaction filter on trace messages; excluded from SSE; only tool wrappers see plaintext |
| Cost overrun from primary swap without operator awareness | MEDIUM | Single WARNING log line on agent-loop init (§5.7); release notes call out budget tuning |
| Per-kind scanner timeouts cascade | MEDIUM | Reuse existing `AGENT_REQUEST_TIMEOUT`; per-scanner timeout caps; existing zombie recovery at 120 min preserved |
| Pydantic schemas allow extra fields (junk drawer) | MEDIUM | `model_config = ConfigDict(extra="forbid")` on all KindConfig + KindPayload variants (§7.3 / §7.3.1) |
| New kinds expose vulnerable scanner binaries | MEDIUM | Sandboxed subprocess; output-path checks; allowlist on `_DANGEROUS_ARG_SUBSTRINGS` |
| `kind_payload` divergence from `kind_config` | LOW | Pydantic discriminator forces kind alignment; router checks `kind_payload.kind == target.kind` |
| Org admin flips kill switch silently | MEDIUM | RBAC enforcement (S-04): admin/owner only; audit-log via `org_settings_changes` row; FE control hidden for non-admins |
| Compliance mappings don't cover new kinds | MEDIUM | Each new agent tags findings with OWASP categories from existing enum (S-10) |
| Webhook integration noise from new kinds | MEDIUM | Existing integrations scoped to legacy kinds (`url`,`repo`,`llm`) by default; operators opt-in to new kinds per integration |
| File upload size grows >1 MiB | LOW | Client-side size check; server validates `len(content) ≤ 16 MiB` (Pydantic) |
| Existing `scans` table grows 12× | LOW | Existing indexes cover; monitor `pg_stat_user_tables` after M1 |

---

## 14. Acceptance Criteria Framework

Every user story has **at least three** acceptance criteria:
- **AC-N.1 — Happy path**: scan against representative target produces ≥1 finding (or clean verdict) within budget
- **AC-N.2 — Fallback path**: with no LLM keys OR `Org.force_deterministic_only=True`, scan completes through deterministic pipeline
- **AC-N.3 — Cluster-specific check**:
  - DAST: log emits filtered breaker roster
  - Artifact: agent's tool-call log shows scanner selection from per-kind allowlist
  - Hybrid: Phase A only when no creds; Phase B only when creds provided

**Cross-cutting test suite (addresses S-13):** target test pyramid 70% unit / 20% integration / 10% e2e.

Required test cases beyond per-story ACs:
- Unit tests for each new `_DANGEROUS_ARG_SUBSTRINGS` entry
- Integration test: agent-emitted `clone_repo` with off-allowlist URL returns error without invoking subprocess
- Integration test: kubeconfig tempfile lifecycle (created mode 0600, unlinked in finally)
- Unit tests for kind-aware `disclosed_actions` validation
- Integration test for org-flag RBAC (non-admin rejected)
- Integration test for fallback engagement — `scan_llm_traces` records `FallbackController` row with reason
- Unit tests for `extra="forbid"` enforcement on all KindConfig + KindPayload variants

---

## 15. User Stories

### US-0: Framework (P1, foundation)

**Story.** As a platform engineer, I want the orchestrator, dispatch, JSONB schemas, and credentials wiring to be kind-aware so that all subsequent kind stories plug into a single contract.

**Tasks (sketch — final task list in tasks.md):**
- Alembic migration `0044_multi_kind_pipelines.py` (4 columns)
- SQLAlchemy model changes (`Target.kind_config`, `Target.kind_credentials_encrypted`, `Scan.kind_payload`, `Org.force_deterministic_only`)
- Pydantic `KindConfig` + `KindPayload` + `KindCredentials` discriminated unions in `schemas/targets.py` and `schemas/scans.py`
- `TargetCreate` / `TargetUpdate` / `TargetOut` accept `kind_config` + `kind_credentials` (with `has_kind_credentials` on `TargetOut`)
- `_validate_kind_config` model validator (per-kind required/forbid rules)
- `services/dispatch_mode.py` extended with `target_kind` arg + org-flag check + new-primary preference
- `services/agent_swarm/agent_loop.py::_primary_backend()` / `_fallback_backend()` body swap + WARNING log on init
- `services/agent_swarm/breakers.py::_build_breakers(profile, snapshot, kind)` + `KIND_TO_BREAKER_NAMES` dict + 7 new BreakerSpec entries
- `services/agent_swarm/tools.py::BREAKER_TOOL_ALLOCATIONS` extended with 7 new entries
- `services/agent_swarm/chain.py` per-kind Phase 3 agent inclusion table
- New entry point `services/scan_runner.py::_run_kind_aware_scan()` with branch at line 523 area
- New module `services/agent_swarm/artifact_orchestrator.py` (`run_artifact_orchestrator()`)
- New module `services/agent_swarm/hybrid_orchestrator.py` (`run_hybrid_orchestrator()`)
- `routers/scans.py::start_scan` accepts `kind_payload`, validates per `target.kind`, enforces `KIND_REQUIRED_DISCLOSED_ACTIONS`
- `routers/targets.py` accepts `kind_config` + `kind_credentials`, per-kind validation
- `routers/orgs.py` (or equivalent) gates `force_deterministic_only` toggle to admin/owner role; audit-logs via `org_settings_changes`
- Extended `_DANGEROUS_ARG_SUBSTRINGS` with 8 new entries
- New tools (handlers): `clone_repo`, `pull_image`, `download_artifact`, `parse_sbom`, `copy_from_session` + allowlist enforcement
- New tools: `run_graphql_cop`, `run_inql`, `run_grpcurl`, `parse_proto`, `run_trivy_image`, `run_syft`, `run_grype`, `run_hadolint`, `run_trivy_secrets`, `run_checkov`, `run_trivy_config`, `run_tfsec`, `run_osv_scanner`, `run_pip_audit`, `run_npm_audit`, `run_grype_sbom`, `run_osv_scanner_sbom`, `run_trivy_k8s_config`, `run_kubectl_get`, `run_kubectl_describe`, `run_rakkess`
- Tests for migration, validators, dispatch_mode kind branches, allowlist enforcement, RBAC, fallback engagement
- **No frontend code in US-0** — frontend changes ride on US-1..US-12

**Explicit plan.md responsibilities (addresses deferred MEDIUMs):**
- B-017 — scheduled scan `kind_payload` synthesis: plan.md must specify whether the schedule snapshots `Target.kind_config` at trigger-time OR adds a per-schedule `kind_payload_override` JSONB column.
- B-018 — per-kind plan gating: plan.md must define a per-kind plan-policy table (e.g., does free plan allow `k8s_cluster` / `container_image`?) or explicitly declare "all kinds available on all plans".
- S-06 — webhook integration scoping: plan.md must extend `Integration` rows with a per-kind opt-in flag; legacy integrations default to `kinds=[url, repo, llm]` (their pre-feature scope).
- S-10 — OWASP tagging on new agents: plan.md must add a "Compliance tagging" AC line to each new BreakerSpec's task list, citing the source-of-truth OWASP enum file (`schemas/findings.py` or equivalent).

**AC-0.1 (Happy path).** A `kind="web_app"` target with valid `kind_config` and credentials submits a scan that flows through `_run_kind_aware_scan` → `_run_dast_scan`, picks the filtered breaker roster (logged), uses `AGENT_FALLBACK_LLM_*` as primary, and produces ≥1 finding.

**AC-0.2 (Fallback path).** With `Org.force_deterministic_only=True`, the same scan completes through the deterministic populator only; `scan_llm_traces` records a single `FallbackController` row with reason `"org_force_deterministic_only"`. With both LLM keys missing, same outcome with reason `"no_api_key"`.

**AC-0.3 (Backward compat).** Existing `kind="url"`, `kind="repo"`, `kind="llm"` scans continue to work unchanged — same task module, same status machine, same scan_llm_traces output. The `kind="llm"` path stays on `_run_llm_scan` (NOT promoted to swarm; KIND_TO_BREAKER_NAMES does not include `llm`).

**AC-0.4 (RBAC).** Non-admin org member's request to set `force_deterministic_only=true` returns 403; org-admin's request succeeds and writes an `org_settings_changes` audit row.

---

### US-1: web_app (DAST cluster, P1)

**Story.** As a security engineer, I want to register a web application target with full `kind_config` (crawl depth, browser rendering, optional API spec hint) and run an AI-orchestrated DAST scan that filters the breaker roster to web-app-relevant specialists.

**AC-1.1 (Happy path).** Registering a `web_app` target against DVWA / Juice-Shop and triggering a scan produces ≥3 findings across `InjectionAgent`, `ClientSideAgent`, `AuthAgent`. Breaker log shows ThreatModelAgent, no K8sAgent, no MobileAppAgent.

**AC-1.2 (Fallback path).** Same target with `Org.force_deterministic_only=True` completes via deterministic-only; finds baseline TLS / header issues.

**AC-1.3 (Breaker filtering).** Log emits `[Swarm] kind=web_app breakers=InjectionAgent,ClientSideAgent,AuthAgent,AuthzAgent,APIAgent,InfraAgent,CloudAgent,SupplyChainAgent,ThreatModelAgent`.

**AC-1.4 (Consent).** Submission without `disclosed_actions` covering `{passive_recon, active_recon, exploitation}` returns 400 listing the missing actions.

---

### US-2: rest_api (DAST cluster, P1)

**Story.** As an API team lead, I want to register a REST API target by pasting/uploading an OpenAPI spec, and have the scan focus on parameter fuzzing, BOLA, mass assignment, broken-auth — skipping client-side breakers.

**AC-2.1 (Happy path).** Register `rest_api` target with attached OpenAPI 3.0 spec (≥10 endpoints). Scan produces ≥1 finding from APIAgent or AuthzAgent. ReconAgent emits `import_api_spec` tool call with the operator-supplied spec.

**AC-2.2 (Fallback path).** Without LLM creds, deterministic flow imports the spec, fuzzes endpoints via `scan_api`, persists findings.

**AC-2.3 (Breaker filtering).** No ClientSideAgent in the breaker log.

---

### US-3: graphql (DAST cluster, P2)

**Story.** GraphQL-specific scanning: introspection, alias attacks, query depth DoS, directive injection.

**Tasks include:** wrap `graphql-cop` and `inql` as MCP tools (`run_graphql_cop`, `run_inql`); add `GraphQLFuzzAgent` BreakerSpec + BREAKER_TOOL_ALLOCATIONS entry.

**AC-3.1 (Happy path).** Against damn-vulnerable-graphql, GraphQLFuzzAgent flags ≥1 introspection-exposure or batched-query DoS finding.

**AC-3.2 (Fallback path).** Deterministic flow runs `graphql-cop` + `scan_api` GraphQL types only.

**AC-3.3 (Breaker filtering).** `GraphQLFuzzAgent` in breaker log; `ClientSideAgent` / `MobileAppAgent` absent.

**AC-3.4 (Conditional rendering, FE).** With `kind_config.introspection_enabled=false`, form section requires `schema_sdl`; without it, returns 400.

---

### US-4: websocket (DAST cluster, P2)

**Story.** WS-specific scanning: CSWSH, auth on handshake, message tampering, binary frame fuzzing.

**AC-4.1 (Happy path).** Register `websocket` target with `wss://` URL, subprotocols, origin header. Scan finds ≥1 issue (e.g., missing origin check).

**AC-4.2 (Fallback path).** Deterministic flow runs `scan_websocket` standalone.

**AC-4.3 (Breaker filtering).** APIAgent with WS-only tools enabled; no ClientSideAgent.

---

### US-5: grpc (DAST cluster, P3)

**Story.** Reflection-driven enumeration plus injection probing across discovered methods.

**Tasks include:** wrap `grpcurl` + `protoc` as MCP tools; add `GrpcReflectionAgent`. Extended `_DANGEROUS_ARG_SUBSTRINGS` block grpcurl `--plaintext` and `--import-path`.

**AC-5.1 (Happy path).** Register `grpc` target with reflection enabled. Scan enumerates ≥1 service/method; InjectionAgent probes each.

**AC-5.2 (Fallback path).** Deterministic flow runs `grpcurl` reflection + static payload set.

**AC-5.3 (Breaker filtering).** `GrpcReflectionAgent` in log; no ClientSideAgent.

**AC-5.4 (Security guard).** Agent tool call with `--plaintext` or `--import-path` is rejected by `_reject_tool_call`.

---

### US-6: source_code (Artifact cluster, P1)

**Story.** Register a `source_code` target (GitHub URL / GitHub App / tarball URL / local path) with language hints and scanner opt-outs. Run AI-orchestrated SAST + SCA + secrets scan.

**Important:** Uses existing `RepoScan` table. Reuses `repo_scan_task.py` cloning + scanner fan-out. NEW work:
- Wire `kind_config` (SourceCodeConfig) into existing RepoScan flow
- Add `ScannerOrchestratorAgent` mode that picks subset of scanners based on language detection + operator hints
- Without LLM, every scanner runs against every file (today's behavior)

**AC-6.1 (Happy path).** Register `source_code` target pointing to a multi-language repo. Agent detects languages, runs only relevant scanners. Findings persist to `RepoScan` + `RepoFinding`.

**AC-6.2 (Fallback path).** Without LLM creds, every scanner runs against every file (today's behavior preserved).

**AC-6.3 (Scanner orchestration).** Agent tool-call log shows selection from `{run_semgrep, run_bandit, run_gosec, run_brakeman, run_eslint, run_gitleaks, run_yara, run_osv_scanner}` only.

**AC-6.4 (Allowlist).** Agent-emitted `clone_repo` with URL NOT matching `Target.kind_config.repo_url` is rejected without subprocess invocation.

---

### US-7: container_image (Artifact cluster, P2)

**Story.** Scan a container image (by reference) for vulnerabilities, secrets, misconfigs, license issues.

**AC-7.1 (Happy path).** `image_ref="alpine:3.10"` (known-vulnerable). Scan produces ≥3 CVE findings via trivy + ≥1 SBOM-derived via syft+grype.

**AC-7.2 (Fallback path).** Deterministic flow runs `run_trivy_image` + `run_syft` + `run_grype` + `run_hadolint` sequentially.

**AC-7.3 (Scanner orchestration).** Agent selects from `{run_trivy_image, run_syft, run_grype, run_hadolint, run_trivy_secrets}` only.

**AC-7.4 (Pull mechanism).** `pull_image` uses `skopeo copy docker://<ref> oci:/tmp/<scan_id>/oci-layout`, not `docker pull`. Verified by mocking subprocess.

**AC-7.5 (Registry creds, FE).** Per-registry credential form section captures the right fields (ECR STS / GCR JSON / ACR client / docker basic).

---

### US-8: iac (Artifact cluster, P2)

**Story.** Scan Terraform / CloudFormation / Helm / Kustomize for policy violations and provider-specific misconfigurations.

**AC-8.1 (Happy path).** Terraform repo with known issues (e.g., public S3 bucket). Scan flags ≥1 critical via checkov + ≥1 from trivy config.

**AC-8.2 (Fallback path).** Deterministic flow runs `run_checkov` + `run_trivy_config` + `run_tfsec`.

**AC-8.3 (Scanner orchestration).** Agent picks based on `frameworks` config.

**AC-8.4 (Dangerous args).** Checkov `--external-checks-dir` and tfsec `--custom-check-dir` rejected.

---

### US-9: package_registry (Artifact cluster, P3)

**Story.** Scan a list of dependencies without needing a full repo — paste package list.

**AC-9.1 (Happy path).** `ecosystem="npm"` + `package.json` content. Scan returns ≥1 CVE via osv-scanner + npm-audit.

**AC-9.2 (Fallback path).** Deterministic flow runs `run_osv_scanner` + `run_npm_audit` (or per-ecosystem analog).

**AC-9.3 (Scanner orchestration).** Agent selects per `ecosystem` field.

---

### US-10: sbom (Artifact cluster, P3)

**Story.** Upload a CycloneDX or SPDX SBOM and get vuln + license + supplier risk report without re-cloning source.

**AC-10.1 (Happy path).** Upload CycloneDX JSON SBOM with ≥10 components. Scan produces ≥1 vuln via `run_grype_sbom`, ≥1 license finding (e.g., GPL-3.0), supplier summary.

**AC-10.2 (Fallback path).** Deterministic flow runs `run_grype_sbom` + `run_osv_scanner_sbom`.

**AC-10.3 (Scanner orchestration).** Agent uses only SBOM-consuming tools; never `clone_repo` / `pull_image`.

**AC-10.4 (Size cap).** SBOM content > 16 MiB rejected at Pydantic layer.

---

### US-11: cicd_pipeline (Hybrid cluster, P3)

**Story.** Audit CI/CD pipeline config for risks (untrusted PR triggers, secret leakage, missing approvals); optionally probe CI provider API.

**Tasks include:** New `CicdConfigAuditAgent` that knows GH Actions / GitLab CI / Jenkins syntax. Conditional Phase B if creds provided.

**AC-11.1 (Happy path).** `provider="github_actions"` + repo with vulnerable workflow (e.g., `pull_request_target` + `actions/checkout` with PR ref). Audit flags this.

**AC-11.2 (Fallback path).** Deterministic flow runs `run_checkov` + `run_gitleaks` against workflow files only.

**AC-11.3 (Phase A only when no creds).** Without CI provider creds, no live API calls; only static config audit.

**AC-11.4 (Conditional rendering, FE).** `live_api_enabled=true` requires kind_credentials; without them, form blocks submission.

---

### US-12: k8s_cluster (Hybrid cluster, P3)

**Story.** Upload K8s manifests (or paste kubeconfig for live access). Scan covers manifest misconfigs, RBAC bindings, network policies, exposed services.

**AC-12.1 (Happy path).** `target="manifests_only"` + manifests_archive_url. Scan flags ≥1 via checkov + trivy K8s. With `target="live_cluster"` + kubeconfig, `K8sReconAgent` lists namespaces and `RbacEnumAgent` enumerates permissions.

**AC-12.2 (Fallback path).** Deterministic flow runs `run_checkov` + `run_trivy_k8s_config` against manifests only.

**AC-12.3 (Phase A only when no creds).** `target="manifests_only"` → no live API calls.

**AC-12.4 (Kubeconfig lifecycle).** kubeconfig materialized to `/tmp/<scan_id>/.kube/config` mode 0600, unlinked in `finally`, not present in `scan_llm_traces.request_messages`, not in SSE events.

**AC-12.5 (Conditional rendering, FE).** `target="live_cluster"` shows kubeconfig textarea + requires kind_credentials; `manifests_only` shows archive URL + hides kubeconfig.

---

## 16. Open Items / [NEEDS CLARIFICATION]

No `[NEEDS CLARIFICATION]` markers remain. All open questions resolved during GATE 2 revision.

---

## 17. Glossary

- **Breaker** — specialist agent within swarm Phase 2 (e.g., InjectionAgent)
- **Snapshot** — frozen recon output (ReconSnapshot for DAST, ArtifactSnapshot for Artifact)
- **Scanner** — deterministic security tool (semgrep, trivy, etc.) wrapped as agent tool
- **Pipeline shape** — one of {DAST, Artifact, Hybrid}; determines orchestrator entry point
- **Kind** — value of `Target.kind` column; one of 15 wire values (3 legacy + 12 new)
- **Type-card ID** — FE kebab-case identifier in `target-types.ts::CATEGORIES`; maps to a wire kind
- **Cluster** — group of kinds sharing a pipeline shape (internal to backend)
- **Fallback** — deterministic-only execution when AI orchestrator can't proceed
- **Allowlist** — registered acceptable values for tool inputs, checked before subprocess invocation

---

## 18. Out of scope for this feature (defer to future specs)

- Multi-target scans (one scan, multiple kinds in parallel)
- Cross-kind correlation (finding in `iac` linked to finding in `container_image` deployed from it)
- New compliance frameworks (PCI DSS, HIPAA mappings) for new kinds
- LLM-as-judge / red-team evaluation harness for the agent itself
- Cost dashboards per scan
- Parallel scanner execution within a single agent loop
- Per-org per-kind LLM provider selection
- AGENT_FALLBACK_LLM_USAGE_* separate env family for the new primary's budget tracking
