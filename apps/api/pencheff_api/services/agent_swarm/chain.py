"""Phase 3 — ChainAgent walks multi-step exploits across the merged
findings and produces the executive summary. ComplianceAgent runs in
parallel mapping findings to compliance controls."""
from __future__ import annotations

from typing import Any, Iterable

from ...config import get_settings
from .agent_loop import Agent, AgentOutcome, LogSink, _run_single_agent
from .prompts import build_chain_prompt
from .tools import chain_tools, select_tools


def _chain_budget(profile: str) -> int:
    s = get_settings()
    return {
        "quick": s.swarm_turns_chain_quick,
        "standard": s.swarm_turns_chain_standard,
        "deep": s.swarm_turns_chain_deep,
    }.get(profile, s.swarm_turns_chain_standard)


async def _run_chain_phase(
    *,
    master_session_id: str,
    target_url: str,
    profile: str,
    on_event: LogSink,
    scan_id: str | None = None,
    db_session_factory: Any = None,
    llm_override: tuple[str, str, str] | None = None,
) -> AgentOutcome:
    agent = Agent(
        name="ChainAgent",
        system_prompt=build_chain_prompt(),
        tools=select_tools(profile, chain_tools()),
        max_turns=_chain_budget(profile),
        # Block ``finish`` until every non-suppressed finding in the master
        # session has been touched by exploit_finding (status != unverified).
        require_per_finding_exploit=True,
    )
    return await _run_single_agent(
        agent=agent,
        session_id=master_session_id,
        target_url=target_url,
        credentials=None,
        profile=profile,
        scope=None,
        exclude_paths=None,
        on_event=on_event,
        session_prepopulated=True,
        scan_id=scan_id,
        db_session_factory=db_session_factory,
        llm_override=llm_override,
    )


def _compliance_budget(profile: str) -> int:
    """Reuse chain budget — compliance work is read-only triage."""
    return _chain_budget(profile)


async def _run_compliance_phase(
    *,
    master_session_id: str,
    target_url: str,
    profile: str,
    on_event: LogSink,
    scan_id: str | None = None,
    db_session_factory: Any = None,
    llm_override: tuple[str, str, str] | None = None,
) -> AgentOutcome:
    from .prompts import build_compliance_prompt
    agent = Agent(
        name="ComplianceAgent",
        system_prompt=build_compliance_prompt(),
        tools=select_tools(profile, ("get_findings", "finish")),
        max_turns=_compliance_budget(profile),
    )
    return await _run_single_agent(
        agent=agent,
        session_id=master_session_id,
        target_url=target_url,
        credentials=None,
        profile=profile,
        scope=None,
        exclude_paths=None,
        on_event=on_event,
        session_prepopulated=True,
        scan_id=scan_id,
        db_session_factory=db_session_factory,
        llm_override=llm_override,
    )


def _proof_budget(profile: str) -> int:
    """Reuse chain budget; proof-of-impact is read-only triage."""
    return _chain_budget(profile)


def _payload_budget(profile: str) -> int:
    """Smaller — pure synthesis, fewer turns needed."""
    return max(4, _chain_budget(profile) // 2)


async def _run_proof_of_impact_phase(
    *,
    master_session_id: str,
    target_url: str,
    profile: str,
    on_event: LogSink,
    scan_id: str | None = None,
    db_session_factory: Any = None,
    llm_override: tuple[str, str, str] | None = None,
) -> AgentOutcome:
    from .prompts import build_proof_of_impact_prompt
    agent = Agent(
        name="ProofOfImpactAgent",
        system_prompt=build_proof_of_impact_prompt(),
        tools=select_tools(profile, (
            "get_findings", "test_endpoint", "run_security_tool", "finish",
        )),
        max_turns=_proof_budget(profile),
    )
    return await _run_single_agent(
        agent=agent, session_id=master_session_id,
        target_url=target_url, credentials=None,
        profile=profile, scope=None, exclude_paths=None,
        on_event=on_event, session_prepopulated=True,
        scan_id=scan_id, db_session_factory=db_session_factory,
        llm_override=llm_override,
    )


async def _run_payload_crafting_phase(
    *,
    master_session_id: str,
    target_url: str,
    profile: str,
    on_event: LogSink,
    scan_id: str | None = None,
    db_session_factory: Any = None,
    llm_override: tuple[str, str, str] | None = None,
) -> AgentOutcome:
    from .prompts import build_payload_crafting_prompt
    agent = Agent(
        name="PayloadCraftingAgent",
        system_prompt=build_payload_crafting_prompt(),
        tools=select_tools(profile, ("get_findings", "finish")),
        max_turns=_payload_budget(profile),
    )
    return await _run_single_agent(
        agent=agent, session_id=master_session_id,
        target_url=target_url, credentials=None,
        profile=profile, scope=None, exclude_paths=None,
        on_event=on_event, session_prepopulated=True,
        scan_id=scan_id, db_session_factory=db_session_factory,
        llm_override=llm_override,
    )


def _evidence_budget(profile: str) -> int:
    """Mostly screenshot work; small budget."""
    return max(4, _chain_budget(profile) // 3)


def _admin_access_budget(profile: str) -> int:
    """Tiny — navigate, screenshot, enumerate, logout, finish = ~5 turns."""
    return 6


async def _run_evidence_capture_phase(
    *,
    master_session_id: str,
    target_url: str,
    profile: str,
    on_event: LogSink,
    scan_id: str | None = None,
    db_session_factory: Any = None,
    llm_override: tuple[str, str, str] | None = None,
) -> AgentOutcome:
    from .prompts import build_evidence_capture_prompt
    agent = Agent(
        name="EvidenceCaptureAgent",
        system_prompt=build_evidence_capture_prompt(),
        tools=select_tools(profile, ("get_findings", "capture_evidence", "finish")),
        max_turns=_evidence_budget(profile),
    )
    return await _run_single_agent(
        agent=agent,
        session_id=master_session_id,
        target_url=target_url,
        credentials=None,
        profile=profile,
        scope=None,
        exclude_paths=None,
        on_event=on_event,
        session_prepopulated=True,
        scan_id=scan_id,
        db_session_factory=db_session_factory,
        llm_override=llm_override,
    )


async def _run_admin_access_phase(
    *,
    master_session_id: str,
    target_url: str,
    profile: str,
    on_event: LogSink,
    scan_id: str | None = None,
    db_session_factory: Any = None,
    llm_override: tuple[str, str, str] | None = None,
) -> AgentOutcome:
    from .prompts import build_admin_access_prompt
    agent = Agent(
        name="AdminAccessAgent",
        system_prompt=build_admin_access_prompt(),
        tools=select_tools(profile, (
            "get_findings",
            "playwright_navigate",
            "playwright_screenshot",
            "playwright_enumerate_links",
            "playwright_logout",
            "finish",
        )),
        max_turns=_admin_access_budget(profile),
    )
    return await _run_single_agent(
        agent=agent,
        session_id=master_session_id,
        target_url=target_url,
        credentials=None,
        profile=profile,
        scope=None,
        exclude_paths=None,
        on_event=on_event,
        session_prepopulated=True,
        scan_id=scan_id,
        db_session_factory=db_session_factory,
        llm_override=llm_override,
    )


def _synthesise_summary_from_breakers(results: Iterable) -> str:
    """Fallback summary when ChainAgent crashes — formed mechanically
    from the BreakerResult list so the scan still ships an executive
    summary."""
    lines: list[str] = ["Swarm scan complete (ChainAgent unavailable)."]
    for r in results:
        if r.success:
            n = len(r.finding_ids)
            tag = f"{n} finding" if n == 1 else f"{n} findings"
            lines.append(f"- {r.agent_name}: {tag} — {r.summary}".rstrip(" —"))
        else:
            lines.append(f"- {r.agent_name}: failed ({r.error})")
    return "\n".join(lines)
