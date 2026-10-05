"""Allocation invariant: every scan_* tool appears in exactly one breaker
(plus shared utility tools that must appear in every breaker)."""
from __future__ import annotations

from pencheff_api.services.agent_swarm.tools import (
    BREAKER_TOOL_ALLOCATIONS,
    SHARED_BREAKER_TOOLS,
    recon_tools,
    chain_tools,
)


def test_every_scan_tool_in_exactly_one_breaker():
    """Tools whose name starts with `scan_` must appear in exactly
    one breaker's exclusive list."""
    seen: dict[str, str] = {}
    for breaker_name, exclusive in BREAKER_TOOL_ALLOCATIONS.items():
        for t in exclusive:
            if not t.startswith("scan_"):
                continue
            assert t not in seen, (
                f"{t!r} allocated to both {seen[t]!r} and {breaker_name!r}"
            )
            seen[t] = breaker_name
    # Sanity: at least these scan_* tools are covered (allocation may
    # legitimately add more later).
    must_cover = {
        "scan_injection", "scan_client_side", "scan_auth", "scan_authz",
        "scan_oauth", "scan_mfa_bypass", "scan_api", "scan_websocket",
        "scan_business_logic", "scan_infrastructure", "scan_advanced",
        "scan_subdomain_takeover", "scan_cloud", "scan_dom_xss",
        "scan_file_handling", "scan_llm_red_team",
    }
    assert must_cover.issubset(seen.keys())


def test_shared_breaker_tools_present_in_every_breaker():
    expected = {"test_endpoint", "get_findings", "suppress_finding", "finish"}
    assert expected.issubset(SHARED_BREAKER_TOOLS)


def test_recon_tools_carry_mapping_tools_only():
    names = {t for t in recon_tools()}
    assert "recon_passive" in names
    assert "recon_active" in names
    assert "recon_api_discovery" in names
    assert "scan_waf" in names
    assert "authenticated_crawl" in names
    assert "finish" in names
    # Recon does NOT do exploitation
    assert "scan_injection" not in names
    assert "test_chain" not in names


def test_chain_tools_carry_chain_tools_only():
    names = {t for t in chain_tools()}
    assert "exploit_chain_suggest" in names
    assert "test_chain" in names
    assert "test_endpoint" in names
    assert "get_findings" in names
    assert "oast_init" in names
    assert "finish" in names
    # Chain does NOT run new scans
    assert "scan_injection" not in names
    assert "scan_authz" not in names


def test_new_agents_present_in_breaker_specs():
    from pencheff_api.services.agent_swarm.breakers import BREAKER_SPECS
    names = {s.name for s in BREAKER_SPECS}
    assert "LLMRedTeamAgent" in names
    assert "SupplyChainAgent" in names
    assert "K8sAgent" in names
    # v0.8.0 added AD + mobile; v0.8.5 added the threat-model lens.
    # Feature 001 (multi-target-scan-pipelines) added 8 new BreakerSpecs:
    # GraphQLFuzzAgent + GrpcReflectionAgent for the DAST cluster, and
    # ArtifactReconAgent + ScannerOrchestratorAgent + CicdConfigAuditAgent +
    # K8sManifestAuditAgent + K8sReconAgent + RbacEnumAgent for the artifact
    # and hybrid clusters. The new agents are dispatched from their dedicated
    # orchestrator modules — they DO NOT spawn for legacy url scans (see
    # _LEGACY_DAST_BREAKER_NAMES in breakers.py).
    assert names == {
        # Original 13 (legacy roster):
        "InjectionAgent", "ClientSideAgent", "AuthAgent", "AuthzAgent",
        "APIAgent", "InfraAgent", "CloudAgent",
        "LLMRedTeamAgent", "SupplyChainAgent", "K8sAgent",
        "ActiveDirectoryAgent", "MobileAppAgent", "ThreatModelAgent",
        # Feature 001 — DAST cluster extras:
        "GraphQLFuzzAgent", "GrpcReflectionAgent",
        # Feature 001 — artifact + hybrid cluster agents:
        "ArtifactReconAgent", "ScannerOrchestratorAgent",
        "CicdConfigAuditAgent", "K8sManifestAuditAgent",
        "K8sReconAgent", "RbacEnumAgent",
    }


def test_legacy_dast_breaker_names_excludes_feature_001_agents():
    """The legacy default roster (used when _build_breakers is called without
    a ``kind`` arg) must NOT include any feature-001 agents. Existing url
    scans depend on the original 13-breaker fan-out per AC-0.3."""
    from pencheff_api.services.agent_swarm.breakers import _LEGACY_DAST_BREAKER_NAMES
    feature_001_agents = {
        "GraphQLFuzzAgent", "GrpcReflectionAgent",
        "ArtifactReconAgent", "ScannerOrchestratorAgent",
        "CicdConfigAuditAgent", "K8sManifestAuditAgent",
        "K8sReconAgent", "RbacEnumAgent",
    }
    assert _LEGACY_DAST_BREAKER_NAMES.isdisjoint(feature_001_agents)
    assert len(_LEGACY_DAST_BREAKER_NAMES) == 13
