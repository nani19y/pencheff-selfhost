"""Per-agent tool subset selectors over the existing
``agent_runner._build_tool_registry`` registry.

The legacy registry exposes ~25 tools to one agent. The swarm slices
that registry into role-specific subsets so each specialised agent
sees only the tools it owns. Every breaker also sees the shared
utility tools (verify, list, suppress, finish).
"""
from __future__ import annotations

from typing import Iterable

from ..agent_runner import _build_tool_registry, AgentTool


# Tools every breaker has access to regardless of category.
SHARED_BREAKER_TOOLS = frozenset({
    "test_endpoint",
    "get_findings",
    "suppress_finding",
    "exploit_finding",  # per-finding category-specific exploitation + evidence capture
    "finish",
})


# Per-breaker EXCLUSIVE tool allocation. Each scan_* tool appears in
# exactly one breaker's exclusive list — see test_breakers_table.py.
BREAKER_TOOL_ALLOCATIONS: dict[str, frozenset[str]] = {
    "InjectionAgent":   frozenset({"scan_injection", "scan_file_handling",
                                    "oast_init", "oast_new_url", "oast_poll"}),
    "ClientSideAgent":  frozenset({"scan_client_side", "scan_dom_xss"}),
    "AuthAgent":        frozenset({"scan_auth", "scan_oauth", "scan_mfa_bypass"}),
    "AuthzAgent":       frozenset({"scan_authz"}),
    "APIAgent":         frozenset({"scan_api", "scan_websocket",
                                    "scan_business_logic"}),
    "InfraAgent":       frozenset({"scan_infrastructure", "scan_advanced",
                                    "scan_subdomain_takeover",
                                    "run_security_tool"}),
    "CloudAgent":       frozenset({"scan_cloud",
                                    "oast_init", "oast_new_url", "oast_poll"}),
    "LLMRedTeamAgent":  frozenset({"scan_llm_red_team"}),
    "SupplyChainAgent": frozenset({"run_security_tool"}),
    "K8sAgent":         frozenset({"run_security_tool"}),
    # AD / mobile / threat-model agents wire MCP-side tools that don't
    # appear in the runtime registry because they live in the plugin
    # rather than the FastAPI tool catalogue. The empty allocation lets
    # the breaker spawn but limits it to the SHARED tools (get_findings,
    # test_endpoint, finish) — exactly what these "lens" agents need.
    "ActiveDirectoryAgent": frozenset(),
    "MobileAppAgent":       frozenset(),
    "ThreatModelAgent":     frozenset(),
    # ── Feature 001 — new DAST-cluster agents ────────────────────────
    # GraphQLFuzzAgent + GrpcReflectionAgent surface kinds the existing
    # 13 specialists can't cover. Tools land in plugins/pencheff/ as new
    # MCP entries during M3 (graphql / grpc stories) — they are listed
    # here so KIND_TO_BREAKER_NAMES picks them up via breaker_tools_for
    # without throwing KeyError. Empty allocation in the meantime keeps
    # the agent restricted to SHARED tools until the wrappers ship.
    # NOTE: ``scan_api`` is the existing APIAgent's exclusive tool — kept there
    # to preserve the "every scan_* tool is owned by exactly one breaker" invariant
    # (test_breakers_table.py). GraphQL/gRPC agents get to ``scan_api`` via the
    # shared utility tool path at runtime if needed.
    # Per-feature-001: protocol-specific wrappers are now live; the runtime
    # subset is enforced by KIND_TO_BREAKER_NAMES so legacy url scans never
    # spawn these agents and never see their tools.
    "GraphQLFuzzAgent":    frozenset({"run_graphql_cop", "run_inql"}),
    "GrpcReflectionAgent": frozenset({"run_grpcurl", "parse_proto"}),
    # ── Feature 001 — artifact + hybrid cluster agents ───────────────
    # Dispatched from artifact_orchestrator.py / hybrid_orchestrator.py rather
    # than the DAST run_swarm fan-out. ArtifactReconAgent has the artifact-
    # acquisition tools (clone/pull/download/parse); ScannerOrchestratorAgent
    # has the union of every artifact scanner — its kind-specific allowlist
    # at runtime is enforced by artifact_orchestrator.KIND_TO_ARTIFACT_TOOLS,
    # not by this static table.
    "ArtifactReconAgent": frozenset({
        "artifact_clone_repo", "artifact_pull_image",
        "artifact_download", "artifact_parse_sbom",
    }),
    "ScannerOrchestratorAgent": frozenset({
        "run_trivy_image", "run_syft", "run_grype", "run_grype_sbom",
        "run_hadolint", "run_checkov", "run_tfsec",
        "run_npm_audit", "run_pip_audit", "run_osv_scanner_sbom",
    }),
    "CicdConfigAuditAgent": frozenset({
        "run_checkov", "run_tfsec",
    }),
    "K8sManifestAuditAgent": frozenset({
        "run_checkov",
    }),
    # Phase B tools landed in feature 001 (kubectl_get/describe + rakkess +
    # CI provider API). K8sReconAgent owns kubectl enumeration; RbacEnumAgent
    # owns rakkess.
    "K8sReconAgent":  frozenset({"run_kubectl_get", "run_kubectl_describe"}),
    "RbacEnumAgent":  frozenset({"run_rakkess"}),
}


def recon_tools() -> tuple[str, ...]:
    return (
        "recon_passive", "recon_active", "recon_api_discovery",
        "scan_waf", "authenticated_crawl", "finish",
    )


def chain_tools() -> tuple[str, ...]:
    return (
        "get_findings", "exploit_chain_suggest", "test_chain",
        "test_endpoint", "exploit_finding",  # ChainAgent stamps evidence on each finding when no chain exists
        "oast_init", "oast_new_url", "oast_poll",
        "finish",
    )


def select_tools(profile: str, names: Iterable[str]) -> list[AgentTool]:
    """Return the subset of the legacy registry whose tool.name is in ``names``."""
    full = _build_tool_registry(profile=profile)
    wanted = set(names)
    return [t for t in full if t.name in wanted]


def breaker_tools_for(*, profile: str, breaker_name: str) -> list[AgentTool]:
    """Tools available to one specific breaker."""
    exclusive = BREAKER_TOOL_ALLOCATIONS[breaker_name]
    names = exclusive | SHARED_BREAKER_TOOLS
    return select_tools(profile, names)
