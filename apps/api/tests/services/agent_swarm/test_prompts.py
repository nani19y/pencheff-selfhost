"""Per-agent prompts share a skeleton + carry their mandate scoping."""
from __future__ import annotations

from pencheff_api.services.agent_swarm import prompts


def test_recon_prompt_has_skeleton_and_recon_mandate():
    p = prompts.build_recon_prompt()
    # Skeleton: identity protection
    assert "Pencheff" in p
    assert "I'm Pencheff" in p
    # Mandate-specific
    assert "ReconAgent" in p or "Recon agent" in p
    assert "attack surface" in p.lower()
    assert "do not call any tool that is not in your registry" in p.lower()


def test_breaker_prompt_carries_mandate():
    p = prompts.build_breaker_prompt(
        agent_name="InjectionAgent",
        mandate_one_liner="Surface SQLi/NoSQLi/XXE/SSTI/cmdi + path traversal + file upload flaws.",
    )
    assert "InjectionAgent" in p
    assert "SQLi" in p
    assert "do not call any tool that is not in your registry" in p.lower()
    # Skeleton: exploit don't scan
    assert "EXPLOIT" in p


def test_chain_prompt_mandate_focuses_on_chains():
    p = prompts.build_chain_prompt()
    assert "ChainAgent" in p
    assert "exploit_chain_suggest" in p
    assert "test_chain" in p
    assert "executive summary" in p.lower()


def test_chain_prompt_has_blast_radius_and_cross_system():
    p = prompts.build_chain_prompt()
    assert "blast" in p.lower()
    assert "cross-system" in p.lower()
    assert "whole platform" in p.lower()


def test_compliance_prompt_mandate_focuses_on_frameworks():
    p = prompts.build_compliance_prompt()
    assert "ComplianceAgent" in p
    assert "PCI-DSS" in p
    assert "HIPAA" in p
    assert "SOC2" in p
    assert "GDPR" in p
    assert "get_findings" in p
    # Read-only mandate: the ComplianceAgent-specific mandate section must say
    # it does not run new scans. (The shared skeleton may mention test_endpoint
    # as part of general rules, but the mandate itself should not call it out.)
    assert "You DO NOT run new scans" in p


def test_no_distinctive_hexstrike_strings():
    """Sanity: the IP-safety contract forbids copying hexstrike-ai
    distinctive identifiers. None of these should appear anywhere."""
    forbidden = (
        "BugBountyWorkflowManager", "VulnerabilityCorrelator",
        "AIExploitGenerator", "CTFWorkflowManager",
        "IntelligentDecisionEngine", "HexStrike",
    )
    full = (
        prompts.build_recon_prompt()
        + prompts.build_breaker_prompt("InjectionAgent", "x")
        + prompts.build_chain_prompt()
        + prompts.build_compliance_prompt()
    )
    for s in forbidden:
        assert s not in full, f"forbidden hexstrike-ai identifier in prompt: {s!r}"


def test_ip_safety_forbidden_strings_absent():
    """IP-safety contract: none of the forbidden literal phrases appear
    in any agent prompt."""
    forbidden_literals = (
        "Voice AI Attack Agent",
        "AI Hallucination Security Agent",
        "Healthcare workflow validation",
        "Insurance fraud path detection",
        "Runtime Defense Agent",
        "Autonomous Attack Graph Engine",
        "Business Logic Security AI",
    )
    full = (
        prompts.build_recon_prompt()
        + prompts.build_breaker_prompt("LLMRedTeamAgent",
            "Surface AI/LLM endpoint weaknesses.")
        + prompts.build_breaker_prompt("SupplyChainAgent",
            "Surface exposed dependency manifests.")
        + prompts.build_breaker_prompt("K8sAgent",
            "Surface Kubernetes control-plane exposure.")
        + prompts.build_chain_prompt()
        + prompts.build_compliance_prompt()
    )
    for s in forbidden_literals:
        assert s not in full, f"forbidden IP string found in prompt: {s!r}"
