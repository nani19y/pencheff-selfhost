# Agent guide — Pencheff

This repository is **Pencheff**, an AI-powered penetration testing platform.

- The MCP server lives in `plugins/pencheff/` and exposes the full pentest
  toolkit (49 tools, 53 attack modules, 326 payloads). After feature 001
  the surface widens with three additional tool modules:
  `artifact_tools.py` (14 acquisition + container/IaC/SBOM scanners),
  `dast_protocol_tools.py` (GraphQL/gRPC), `source_code_tools.py`
  (8 SAST wrappers), `hybrid_tools.py` (kubernetes + 5 CI providers).
- The SaaS API lives in `apps/api/`. The LLM-driven scan agent is in
  `apps/api/pencheff_api/services/agent_runner.py`. It talks to any
  OpenAI-compatible chat-completions endpoint with tool-calling support.
  **Per-feature-001:** `AGENT_FALLBACK_LLM_*` is now the active primary,
  with `AGENT_LLM_*` as the secondary fallback. Configure whichever
  set you have credentials for — code falls back automatically.
- **Target kinds (feature 001).** `Target.kind` accepts 15 wire values:
  legacy `url`/`repo`/`llm` plus 12 new — `web_app`, `rest_api`, `graphql`,
  `websocket`, `grpc` (DAST cluster), `source_code`, `container_image`,
  `iac`, `package_registry`, `sbom` (artifact cluster), `cicd_pipeline`,
  `k8s_cluster` (hybrid cluster). Per-kind config rides on the
  `Target.kind_config` JSONB column (Pydantic discriminated union in
  `apps/api/pencheff_api/schemas/targets.py`); structurally-distinct
  credentials (kubeconfig YAML, registry auth, CI tokens, GitHub App
  keys) ride on `Target.kind_credentials_encrypted` (Fernet).
  Orchestrator selection happens in
  `apps/api/pencheff_api/services/scan_runner.py::_run_kind_aware_scan`
  → `agent_swarm/artifact_orchestrator.py` or
  `agent_swarm/hybrid_orchestrator.py`. DAST kinds fall through to the
  existing url path with `kind` plumbed to `run_swarm` for breaker-roster
  filtering via `KIND_TO_BREAKER_NAMES` in `agent_swarm/breakers.py`.
- **Org kill switch (feature 001).** `Org.force_deterministic_only`
  short-circuits `dispatch_mode.resolve_dispatch_mode` to
  `deterministic_only`. Owner / admin only via `require_org_role`; every
  flip writes an `AuditLog` row with actor + before/after.
- The web app lives in `apps/web/`. The 12 new kinds each have their own
  form section at `apps/web/components/register-target/<kind>-form-section.tsx`.
- Observability is opt-in (`PENCHEFF_OBSERVABILITY_ENABLED=true`, default
  off): OpenTelemetry SDK in `apps/api/pencheff_api/observability/` and
  `plugins/pencheff/pencheff/observability/`, custom Postgres exporter
  (raw psycopg2 — bypasses SQLAlchemy auto-instrumentation to break
  recursion), day-partitioned `otel_spans` / `otel_logs` /
  `otel_metrics` (migrations `0041`, `0042`), tamper-evident `audit_logs`
  hash chain via `apps/api/pencheff_api/middleware/audit.py`, hourly
  retention task `pencheff.observability.prune_partitions`. Web UI:
  `apps/web/app/observability/{slo,audit,cost,traces/[scanId]}/`.
- Documentation is in `apps/docs/` (Nextra) and `plugins/pencheff/docs/`.

When making changes, prefer editing in place over wholesale rewrites,
and keep the deterministic methodology free for every plan.


<claude-mem-context>
# Memory Context

# [pencheff] recent context, 2026-06-21 6:14pm GMT+5:30

No previous sessions found.
</claude-mem-context>