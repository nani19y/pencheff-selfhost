# Scan Types Reference

Pencheff's `Target.kind` accepts **15** wire values: 3 legacy
(`url`, `repo`, `llm`) and 12 added by feature 001 (multi-target scan
pipelines). This page is the per-kind reference for `kind_config`
(non-secret), `kind_credentials` (secrets, Fernet-encrypted at rest),
required scanner binaries, and example `POST /targets` payloads.

For the architecture rationale and full spec, see
[`specs/001-multi-target-scan-pipelines/spec.md`](../specs/001-multi-target-scan-pipelines/spec.md).

## Pipeline shape by kind

| Kind | Cluster | Orchestrator |
|------|---------|--------------|
| `url` / `web_app` / `rest_api` / `graphql` / `websocket` / `grpc` | DAST | `agent_swarm.run_swarm` with kind-filtered breaker roster |
| `source_code` / `container_image` / `iac` / `package_registry` / `sbom` | Artifact | `artifact_orchestrator.run_artifact_orchestrator` |
| `cicd_pipeline` / `k8s_cluster` | Hybrid | `hybrid_orchestrator.run_hybrid_orchestrator` (Phase A always + Phase B with `kind_credentials`) |
| `repo` / `llm` | Legacy | Unchanged from pre-feature-001 |

## Per-kind reference

### `web_app`

DAST against a live web application. Full breaker roster minus
mobile/K8s/AD/LLM specialists.

| Field | Type | Default | Notes |
|---|---|---|---|
| `crawl_depth` | int (1-10) | 3 | |
| `max_pages` | int (1-1000) | 100 | |
| `browser_render` | bool | true | Use Playwright for SPA discovery |
| `api_spec_url` | URL? | null | Optional OpenAPI hint |

```json
POST /targets
{
  "name": "Staging Web",
  "base_url": "https://staging.example.com",
  "kind": "web_app",
  "kind_config": {
    "kind": "web_app",
    "crawl_depth": 5,
    "browser_render": true
  }
}
```

### `rest_api`

API-focused breaker roster (InjectionAgent, AuthAgent, AuthzAgent,
APIAgent, InfraAgent, ThreatModelAgent). No ClientSideAgent.

| Field | Type | Notes |
|---|---|---|
| `api_spec` | dict? | Parsed OpenAPI / Swagger / Postman blob |
| `api_spec_url` | URL? | OR fetch from URL |
| `api_spec_format` | `openapi3` / `swagger2` / `postman` / `auto` | |
| `auth_in_spec` | bool | If false, the agent skips spec-declared auth and probes anonymous endpoints |

### `graphql`

Adds `GraphQLFuzzAgent` (graphql-cop + inql). Skips ClientSideAgent.

| Field | Type | Notes |
|---|---|---|
| `introspection_enabled` | bool | When false, requires `schema_sdl` |
| `schema_sdl` | str? | Operator-supplied schema for introspection-disabled targets |
| `max_query_depth` | int (1-50) | DoS guardrail |
| `operations_to_test` | `["query", "mutation", "subscription"]` | Subset |

Scanner deps: `graphql-cop`, `inql` (otherwise both skip gracefully).

### `websocket`

| Field | Type | Notes |
|---|---|---|
| `subprotocols` | str[] | Negotiated subprotocols |
| `origin_header` | str? | Bypass origin-pin checks |
| `auth_token_in_query` | str? | When auth is on `?token=` |

### `grpc`

Adds `GrpcReflectionAgent`. `grpcurl --plaintext` / `--import-path` blocked
at the `_DANGEROUS_ARG_SUBSTRINGS` allowlist; set `tls_verify=false` for
self-signed targets to pass `-insecure` (still TLS).

| Field | Type | Notes |
|---|---|---|
| `reflection_enabled` | bool | When false, requires `proto_files` |
| `proto_files` | str[]? | Inline `.proto` contents |
| `tls_verify` | bool | Default true |

Scanner deps: `grpcurl`, optionally `protoc`.

---

### `source_code`

SAST + SCA + secrets against a cloned repository. Uses
`artifact_clone_repo` (`git -c core.hooksPath=/dev/null --depth=1`).

| Field | Type | Notes |
|---|---|---|
| `source` | `github_url` / `github_app` / `local_path` / `tarball_url` | |
| `repo_url` | URL? | Required when `source` is `github_url` or `tarball_url` |
| `git_ref` | str | Default `HEAD` |
| `languages_hint` | str[]? | Narrow the SAST scanner subset |
| `scanners_disabled` | str[] | Per-org scanner opt-out |

Scanner deps: any of `semgrep`, `bandit`, `gosec`, `brakeman`, `eslint`,
`gitleaks`, `yara`, `osv-scanner` — missing ones skip with a clear
`scanner_stats` entry.

**Credentials.** GitHub App: set `kind_credentials.auth_type="github_app"`
with `github_app_id` + `github_app_private_key` (PEM, ≤ 8 KiB) +
`github_app_installation_id`. PAT: `auth_type="pat"` + `pat`. SSH:
`auth_type="ssh_key"` + `ssh_private_key`.

### `container_image`

Trivy + syft + grype + hadolint against an OCI layout pulled via
`skopeo copy` (never `docker pull`).

| Field | Type | Notes |
|---|---|---|
| `image_ref` | str | `alpine:3.10`, `ghcr.io/owner/img:sha256:…`, etc. |
| `registry` | `dockerhub` / `ecr` / `gcr` / `ghcr` / `acr` / `custom` | |
| `scan_layers` / `scan_secrets` / `scan_misconfigs` | bool | All default true |

Scanner deps: `skopeo`, `trivy`, `syft`, `grype`, `hadolint`.

**Credentials.** Private registries — `kind_credentials.auth_type`:

- `basic` — `username` + `password_or_token`
- `token` — `password_or_token` only
- `docker_config` — `docker_config_json` (≤ 64 KiB)
- `ecr_sts` — `ecr_sts_role_arn`
- `gcr_service_account` — `gcr_service_account_json` (≤ 16 KiB)
- `acr_sp` — `acr_client_id` + `acr_client_secret` + `acr_tenant_id`

### `iac`

Checkov + tfsec against a cloned IaC repo.

| Field | Type | Notes |
|---|---|---|
| `frameworks` | `terraform` / `cloudformation` / `helm` / `kustomize` / `arm` (multi-select) | tfsec runs only when `terraform` is selected |
| `source` | `repo` / `tarball_url` / `local_path` | |
| `repo_url` | URL? | |

Scanner deps: `checkov`, `tfsec`.

### `package_registry`

Per-ecosystem dependency audit without a full source clone.

| Field | Type | Notes |
|---|---|---|
| `ecosystem` | `npm` / `pypi` / `maven` / `cargo` / `gem` / `composer` / `go` / `nuget` | |
| `package_list` | `[{name, version}, …]` | Non-empty |
| `include_dev` | bool | |

Scanner deps: `npm` (for npm-audit), `pip-audit` (for pypi), `osv-scanner`.

### `sbom`

Vuln + license + supplier checks against an uploaded CycloneDX / SPDX SBOM.

| Field | Type | Notes |
|---|---|---|
| `format` | `cyclonedx-json` / `cyclonedx-xml` / `spdx-json` / `spdx-tag-value` | |
| `content` | str (≤ 16 MiB) | OR — |
| `url` | URL | Hosted SBOM |
| `check_licenses` / `check_suppliers` | bool | |

Scanner deps: `grype`, `osv-scanner`.

---

### `cicd_pipeline` (Hybrid)

Phase A always (config audit via checkov). Phase B enumerates the provider's
REST API when `live_api_enabled=true` and `kind_credentials` is bound.

| Field | Type | Notes |
|---|---|---|
| `provider` | `github_actions` / `gitlab_ci` / `jenkins` / `azure_pipelines` / `circleci` | |
| `repo_url` | URL? | Provider-specific (Jenkins: controller base URL) |
| `config_paths` | str[] | Workflow file paths (auto-detected if empty) |
| `live_api_enabled` | bool | Default false |

Phase B credentials per provider:

- **GitHub Actions** — `kind_credentials = {kind: "cicd_pipeline", provider: "github_actions", token: "ghp_…"}`. Surfaces admin-suggestive secret names and read-write deploy keys.
- **GitLab CI** — `{provider: "gitlab_ci", token: "glpat-…"}`. Flags variables that are neither protected nor masked, push-enabled deploy keys.
- **Jenkins** — `{provider: "jenkins", token: "<api token>", jenkins_user: "admin"}`. Flags plugins with available updates (RCE vector).
- **Azure Pipelines** — `{provider: "azure_pipelines", token: "azp_…"}`. Flags variable groups without project gating, admin-suggestive non-isSecret variables.
- **CircleCI** — `{provider: "circleci", token: "cci_…"}`. Flags admin-suggestive env var names. Uses `repo_url` host to derive the VCS prefix (gh / bb).

### `k8s_cluster` (Hybrid)

Phase A always (checkov against manifests). Phase B (live cluster) runs
`kubectl get` + `kubectl describe` + `rakkess`.

| Field | Type | Notes |
|---|---|---|
| `target` | `manifests_only` / `live_cluster` | |
| `manifests_archive_url` | URL? | Required when `target=manifests_only` |
| `namespaces` | str[] | Default `["default"]` — bounds Phase B kubectl queries |
| `rbac_enum` | bool | Default true — runs rakkess |
| `network_policy_audit` | bool | Default true |

Phase B credentials: `kind_credentials = {kind: "k8s_cluster", kubeconfig: "apiVersion: v1\n…", context: "prod"}`.

The kubeconfig is **never logged**. At scan time it's materialised to
`/tmp/<scan_id>/.kube/config` mode 0600 and unlinked in the
orchestrator's `finally` block. The redaction filter on
`scan_llm_traces.request_messages` strips any tool argument containing
`kubeconfig` / `cert-data` / `BEGIN PRIVATE KEY` markers.

Scanner deps: `kubectl`, `rakkess` (or `kubectl-access_matrix`).

---

## Org-level controls

| Setting | Effect |
|---|---|
| `Org.force_deterministic_only=true` | Short-circuits `dispatch_mode` to `deterministic_only` regardless of plan / quota / beta override. **Admin / owner role only**; every flip writes an `AuditLog` row. |
| `Integration.target_kinds` | Per-integration target-kind opt-in. Existing integrations were backfilled to `["url", "repo", "llm"]` so new kinds don't accidentally flood configured webhook channels. |

## Required consent disclosures per kind

`ConsentPayload.disclosed_actions` must include the kind's required set
(`schemas/scans.py::KIND_REQUIRED_DISCLOSED_ACTIONS`). Phase B disclosures
(`ci_api_read`, `k8s_api_read`, `rbac_enumeration`) are auto-required by
the router when `kind_config` implies live-system probing.

## LLM credentials (post-feature-001)

`AGENT_FALLBACK_LLM_*` is now the **active primary**, with `AGENT_LLM_*` as
the secondary fallback. Existing deployments keep working — code falls
back to `AGENT_LLM_*` when `AGENT_FALLBACK_LLM_API_KEY` is unset. Budget-
tracking knobs (`AGENT_LLM_USAGE_*`) follow the active primary; review
threshold values for the new provider's pricing curve. A one-time
`WARNING` log on agent_loop init flags this transition.

## End-to-end: register and scan a `container_image`

```bash
# 1. Register the target
curl -X POST https://api.example.com/targets \
  -H "Authorization: Bearer $PAT" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "alpine 3.10 (CVE baseline)",
    "base_url": "oci://alpine:3.10",
    "kind": "container_image",
    "kind_config": {
      "kind": "container_image",
      "image_ref": "alpine:3.10",
      "registry": "dockerhub",
      "scan_layers": true,
      "scan_secrets": true,
      "scan_misconfigs": true
    }
  }'

# 2. Commission a scan with the kind-aware consent
curl -X POST https://api.example.com/scans \
  -H "Authorization: Bearer $PAT" \
  -H "Content-Type: application/json" \
  -d '{
    "target_id": "<id>",
    "profile": "standard",
    "consent_payload": {
      "acknowledged": true,
      "authorization_text": "I am authorized to scan this container image and its dependencies for vulnerabilities.",
      "disclosed_actions": ["image_pull", "container_scan"]
    }
  }'
```

The scan flows through `_run_kind_aware_scan` → `artifact_orchestrator` →
`skopeo copy` → `trivy image --offline-scan` + `syft` + `grype`. Findings
land in the regular `findings` table tagged with `owasp_category=A06:2021`.
