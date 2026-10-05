"""Deterministic bug-bounty workflow.

Pipeline (each step is decided by ``selector.candidates`` + ``fallback``):

    subdomain enum  →  live host filter  →  tech detect  →
    crawler         →  param discovery   →  template scan →
    XSS scan        →  SQLi scan         →  triage

This is what hexstrike-ai's "BugBountyWorkflowManager" does, but the entire
pipeline is rule-based.
"""

from __future__ import annotations

import asyncio
from typing import Any

from pencheff.core.orchestrator.engine import Orchestrator


async def run(target: str, *, intensity: str = "default", **_: Any) -> dict[str, Any]:
    orch = Orchestrator()

    # Stage 1: passive subdomain enum + live host filter.
    subdomain_result = await orch.run_tool_with_fallback(
        primary_tool="subfinder",
        target=target,
        objective="discovery",
        target_profile="web",
    )
    httpx_result = await orch.run_tool_with_fallback(
        primary_tool="httpx",
        target=target,
        objective="discovery",
        target_profile="web",
    )

    # Stage 2: crawl + param discovery (parallel).
    crawl_result, param_result = await asyncio.gather(
        orch.run_tool_with_fallback(
            primary_tool="katana", target=target,
            objective="discovery", target_profile="web",
        ),
        orch.run_tool_with_fallback(
            primary_tool="arjun", target=target,
            objective="discovery", target_profile="web",
        ),
    )

    # Stage 3: template + XSS scans (parallel).
    nuclei_result, dalfox_result = await asyncio.gather(
        orch.run_tool_with_fallback(
            primary_tool="nuclei", target=target,
            objective="vuln_scan", target_profile="web",
        ),
        orch.run_tool_with_fallback(
            primary_tool="dalfox", target=target,
            objective="injection", target_profile="web",
        ),
    )

    findings: list[Any] = []
    for _, _, fs in (
        subdomain_result, httpx_result, crawl_result, param_result,
        nuclei_result, dalfox_result,
    ):
        findings.extend(fs)

    chains = orch.chain_planner.plan(findings)
    return {
        "workflow": "bug_bounty",
        "target": target,
        "stages": [
            {"name": "subdomain", "tool": subdomain_result[0]},
            {"name": "live_filter", "tool": httpx_result[0]},
            {"name": "crawl", "tool": crawl_result[0]},
            {"name": "param_discovery", "tool": param_result[0]},
            {"name": "template_scan", "tool": nuclei_result[0]},
            {"name": "xss", "tool": dalfox_result[0]},
        ],
        "findings": findings,
        "chains": [c.id for c in chains],
        "policy_versions": orch.policies.versions,
    }
