"""Swarm orchestrator: gather + retry + merge + chain + fallback gate.

The full design lives in
docs/superpowers/specs/2026-05-05-parallel-agent-swarm-design.md.
"""
from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

from ...config import get_settings
from .agent_loop import (
    Agent, AgentOutcome, _TransientLLMError, _run_single_agent, LogSink,
)
from .breakers import BreakerSpec, seed_breaker_session
from .snapshot import ReconSnapshot

log = logging.getLogger("pencheff.swarm.orchestrator")


@dataclass
class BreakerResult:
    agent_name: str
    success: bool
    finding_ids: tuple[str, ...]
    summary: str
    turns: int
    tool_calls: int
    error: str | None
    breaker_session_id: str | None  # for the merge step


def _prefix(prefix: str, sink: LogSink) -> LogSink:
    async def wrapped(line: str) -> None:
        await sink(f"{prefix}{line}")
    return wrapped


async def _run_breaker_with_retry(
    *,
    spec: BreakerSpec,
    agent: Agent,
    snapshot: ReconSnapshot,
    on_event: LogSink,
    target_url: str,
    credentials: dict[str, Any] | None,
    scope: list[str] | None,
    exclude_paths: list[str] | None,
    scan_id: str | None = None,
    db_session_factory: Any = None,
    llm_override: tuple[str, str, str] | None = None,
) -> BreakerResult:
    """Run one breaker with at most one whole-run retry on transient errors."""
    settings = get_settings()
    breaker_sid = await seed_breaker_session(snapshot)
    prefixed = _prefix(f"[{spec.name}] ", on_event)

    # AuthzAgent quiet-quit: its mandate is meaningless without an
    # authenticated session. Treat as success so the catastrophic
    # fallback gate doesn't trip on this skip alone (Spec §5).
    if spec.name == "AuthzAgent" and not snapshot.authenticated:
        await prefixed("skipped: no authenticated session")
        return BreakerResult(
            agent_name=spec.name, success=True,
            finding_ids=(), summary="skipped: no authenticated session",
            turns=0, tool_calls=0, error=None,
            breaker_session_id=breaker_sid,
        )

    max_attempts = 1 + max(0, settings.swarm_breaker_retry_attempts)
    last_transient: str | None = None
    for attempt in range(max_attempts):
        try:
            outcome: AgentOutcome = await _run_single_agent(
                agent=agent,
                session_id=breaker_sid,
                target_url=target_url,
                credentials=credentials,
                profile=snapshot.profile,
                scope=scope,
                exclude_paths=exclude_paths,
                on_event=prefixed,
                session_prepopulated=True,  # breakers see snapshot-seeded session
                scan_id=scan_id,
                db_session_factory=db_session_factory,
                llm_override=llm_override,
            )
            # Query the breaker's isolated session for findings produced
            # during the run. _run_single_agent doesn't track these — it
            # just drives the loop — so we ask pencheff directly.
            import pencheff.server as pencheff_server
            listing = await pencheff_server.get_findings(session_id=breaker_sid)
            finding_ids = tuple(
                f.get("id", "") for f in (listing.get("findings") or [])
                if f.get("id")
            )
            return BreakerResult(
                agent_name=spec.name,
                success=True,
                finding_ids=finding_ids,
                summary=outcome.summary,
                turns=outcome.turns,
                tool_calls=outcome.tool_calls,
                error=None,
                breaker_session_id=breaker_sid,
            )
        except _TransientLLMError as exc:
            last_transient = str(exc)
            if attempt < max_attempts - 1:
                await prefixed(f"transient error ({exc}); retrying once")
                await asyncio.sleep(settings.swarm_breaker_retry_backoff_sec)
                continue
            return BreakerResult(
                agent_name=spec.name, success=False,
                finding_ids=(), summary="", turns=0, tool_calls=0,
                error=f"transient_after_retry: {last_transient}",
                breaker_session_id=breaker_sid,
            )
        except Exception as exc:  # noqa: BLE001
            log.exception("breaker %s crashed", spec.name)
            return BreakerResult(
                agent_name=spec.name, success=False,
                finding_ids=(), summary="", turns=0, tool_calls=0,
                error=f"{type(exc).__name__}: {exc}",
                breaker_session_id=breaker_sid,
            )
    # Unreachable, but mypy-friendly:
    return BreakerResult(
        agent_name=spec.name, success=False,
        finding_ids=(), summary="", turns=0, tool_calls=0,
        error="exhausted_loop", breaker_session_id=breaker_sid,
    )


async def _merge_breaker_findings_into_master(
    *,
    master_session_id: str,
    breaker_results: list[BreakerResult],
    on_event: LogSink,
) -> None:
    """Copy each successful breaker's findings into the master session,
    tagging metadata with discovered_by_agent. Dedupes by (title, endpoint,
    parameter) across BOTH (a) the master's pre-existing findings (from the
    deterministic populator that ran during recon) AND (b) findings being
    copied in this merge call. Without (a), the populator's "Missing Security
    Header: x" and a breaker's re-discovery of the same issue both land as
    separate rows in the master."""
    import pencheff.server as srv

    seen: set[tuple[str, str, str]] = set()

    # Pre-seed with master's existing findings so populator-discovered
    # findings collide with breaker re-discoveries and the latter are dropped.
    try:
        master_listing = await srv.get_findings(session_id=master_session_id)
        for f in master_listing.get("findings") or []:
            seen.add((
                str(f.get("title") or "").strip().lower(),
                str(f.get("endpoint") or "").strip().lower(),
                str(f.get("parameter") or "").strip().lower(),
            ))
        if seen:
            await on_event(f"[Merge] pre-seeded dedup with {len(seen)} existing master findings")
    except Exception as exc:  # noqa: BLE001
        log.warning("master findings pre-seed failed (dedup degraded): %s", exc)

    for r in breaker_results:
        if not r.success or not r.finding_ids or not r.breaker_session_id:
            continue
        copied = 0
        skipped = 0
        # One fetch per breaker session so we can read each finding's
        # (title, endpoint, parameter) without hitting the slow per-id path.
        try:
            src_listing = await srv.get_findings(session_id=r.breaker_session_id)
        except Exception:
            src_listing = {"findings": []}
        src_by_id = {f.get("id"): f for f in (src_listing.get("findings") or []) if f.get("id")}

        for fid in r.finding_ids:
            f = src_by_id.get(fid) or {}
            key = (
                str(f.get("title") or "").strip().lower(),
                str(f.get("endpoint") or "").strip().lower(),
                str(f.get("parameter") or "").strip().lower(),
            )
            if key != ("", "", "") and key in seen:
                skipped += 1
                continue
            seen.add(key)
            await srv.copy_finding(
                src_session=r.breaker_session_id,
                dst_session=master_session_id,
                finding_id=fid,
                tag={"discovered_by_agent": r.agent_name},
            )
            copied += 1
        msg = f"[Merge] {r.agent_name}: {copied} findings merged"
        if skipped:
            msg += f" ({skipped} duplicate{'s' if skipped != 1 else ''} skipped)"
        await on_event(msg)


@dataclass
class SwarmOutcome:
    summary: str
    breaker_results: tuple[BreakerResult, ...]
    used_fallback: bool
    used_fallback_reason: str | None
    total_tool_calls: int
    total_turns: int


async def _catastrophic_fallback(
    *,
    reason: str,
    master_session_id: str,
    target_url: str,
    credentials: dict[str, Any] | None,
    profile: str,
    scope: list[str] | None,
    exclude_paths: list[str] | None,
    on_event: LogSink,
    session_prepopulated: bool,
    prior_context: str | None = None,
    llm_override: tuple[str, str, str] | None = None,
) -> SwarmOutcome:
    await on_event(f"[Swarm] {reason}; falling back to single-agent loop")
    from .. import agent_runner
    legacy = await agent_runner.run_agent(
        session_id=master_session_id,
        target_url=target_url,
        credentials=credentials,
        profile=profile,
        scope=scope,
        exclude_paths=exclude_paths,
        on_event=on_event,
        session_prepopulated=session_prepopulated,
        prior_context=prior_context,
        llm_override=llm_override,
    )
    return SwarmOutcome(
        summary=legacy.summary,
        breaker_results=(),
        used_fallback=True,
        used_fallback_reason=reason,
        total_tool_calls=legacy.tool_calls,
        total_turns=legacy.turns,
    )


async def run_swarm(
    *,
    master_session_id: str,
    target_url: str,
    credentials: dict[str, Any] | None,
    profile: str,
    scope: list[str] | None,
    exclude_paths: list[str] | None,
    on_event: LogSink,
    session_prepopulated: bool = False,
    scan_id: str | None = None,
    db_session_factory: Any = None,
    # Feature 001: optional Target.kind. When set + listed in
    # KIND_TO_BREAKER_NAMES, filters the breaker roster per spec §6.1.
    # When omitted, falls back to the legacy 13-breaker default.
    kind: str | None = None,
    # Re-scan priming: compact previous-scan findings appended to each
    # breaker's system prompt so they re-verify / prioritise known issues.
    # None on a first scan.
    prior_context: str | None = None,
    # Org-provider override: (base_url, api_key, model) triple for
    # OpenAI-compatible BYO-LLM providers.  None → Pencheff default.
    llm_override: tuple[str, str, str] | None = None,
) -> SwarmOutcome:
    from .recon import run_recon_phase
    from .breakers import _build_breakers
    from .chain import (
        _run_chain_phase,
        _run_compliance_phase,
        _run_proof_of_impact_phase,
        _run_payload_crafting_phase,
        _run_evidence_capture_phase,
        _run_admin_access_phase,
        _synthesise_summary_from_breakers,
    )
    from .snapshot import ReconFailed

    fallback_kwargs = dict(
        master_session_id=master_session_id,
        target_url=target_url,
        credentials=credentials,
        profile=profile,
        scope=scope,
        exclude_paths=exclude_paths,
        on_event=on_event,
        session_prepopulated=session_prepopulated,
        prior_context=prior_context,
        llm_override=llm_override,
    )

    # ── Phase 1 ───────────────────────────────────────────────
    try:
        snapshot = await run_recon_phase(
            master_session_id=master_session_id,
            target_url=target_url,
            credentials=credentials,
            profile=profile,
            scope=scope,
            exclude_paths=exclude_paths,
            on_event=_prefix("[Recon] ", on_event),
            scan_id=scan_id,
            db_session_factory=db_session_factory,
            llm_override=llm_override,
        )
    except ReconFailed as exc:
        return await _catastrophic_fallback(
            reason=f"recon_failed: {exc}", **fallback_kwargs,
        )

    # ── Phase 2 ───────────────────────────────────────────────
    # Feature 001: kind-filtered roster when ``kind`` is provided + known.
    pairs = _build_breakers(profile=profile, snapshot=snapshot, kind=kind, prior_context=prior_context)
    if kind is not None:
        await on_event(
            f"[Swarm] kind={kind} breakers={','.join(s.name for s, _ in pairs)}"
        )
    raw_results = await asyncio.gather(
        *[
            _run_breaker_with_retry(
                spec=spec, agent=agent, snapshot=snapshot,
                on_event=on_event, target_url=target_url,
                credentials=credentials, scope=scope,
                exclude_paths=exclude_paths,
                scan_id=scan_id,
                db_session_factory=db_session_factory,
                llm_override=llm_override,
            )
            for spec, agent in pairs
        ],
        return_exceptions=True,
    )
    breaker_results: list[BreakerResult] = []
    for raw, (spec, _agent) in zip(raw_results, pairs):
        if isinstance(raw, BreakerResult):
            breaker_results.append(raw)
        else:
            log.exception("breaker %s raised at gather edge: %s", spec.name, raw)
            breaker_results.append(BreakerResult(
                agent_name=spec.name, success=False,
                finding_ids=(), summary="", turns=0, tool_calls=0,
                error=f"gather_edge: {type(raw).__name__}: {raw}",
                breaker_session_id=None,
            ))

    breaker_sids = [r.breaker_session_id for r in breaker_results if r.breaker_session_id]

    try:
        if all(not r.success for r in breaker_results):
            return await _catastrophic_fallback(
                reason="all_breakers_failed", **fallback_kwargs,
            )

        # ── Merge ─────────────────────────────────────────────────
        await _merge_breaker_findings_into_master(
            master_session_id=master_session_id,
            breaker_results=breaker_results,
            on_event=on_event,
        )

        # ── Phase 3: Chain + Compliance + ProofOfImpact + PayloadCrafting
        #            + EvidenceCapture + AdminAccess  (6-way fan-out) ──
        chain_summary = ""
        chain_tool_calls = 0
        chain_turns = 0
        compliance_summary = ""
        compliance_tool_calls = 0
        compliance_turns = 0
        proof_summary = ""
        proof_tool_calls = 0
        proof_turns = 0
        payload_summary = ""
        payload_tool_calls = 0
        payload_turns = 0
        evidence_summary = ""
        evidence_tool_calls = 0
        evidence_turns = 0
        admin_summary = ""
        admin_tool_calls = 0
        admin_turns = 0

        chain_prefix = _prefix("[Chain] ", on_event)
        compliance_prefix = _prefix("[Compliance] ", on_event)
        proof_prefix = _prefix("[ProofOfImpact] ", on_event)
        payload_prefix = _prefix("[PayloadCrafting] ", on_event)
        evidence_prefix = _prefix("[EvidenceCapture] ", on_event)
        admin_prefix = _prefix("[AdminAccess] ", on_event)

        chain_task = _run_chain_phase(
            master_session_id=master_session_id,
            target_url=target_url,
            profile=profile,
            on_event=chain_prefix,
            scan_id=scan_id,
            db_session_factory=db_session_factory,
            llm_override=llm_override,
        )
        compliance_task = _run_compliance_phase(
            master_session_id=master_session_id,
            target_url=target_url,
            profile=profile,
            on_event=compliance_prefix,
            scan_id=scan_id,
            db_session_factory=db_session_factory,
            llm_override=llm_override,
        )
        proof_task = _run_proof_of_impact_phase(
            master_session_id=master_session_id,
            target_url=target_url,
            profile=profile,
            on_event=proof_prefix,
            scan_id=scan_id,
            db_session_factory=db_session_factory,
            llm_override=llm_override,
        )
        payload_task = _run_payload_crafting_phase(
            master_session_id=master_session_id,
            target_url=target_url,
            profile=profile,
            on_event=payload_prefix,
            scan_id=scan_id,
            db_session_factory=db_session_factory,
            llm_override=llm_override,
        )
        evidence_task = _run_evidence_capture_phase(
            master_session_id=master_session_id,
            target_url=target_url,
            profile=profile,
            on_event=evidence_prefix,
            scan_id=scan_id,
            db_session_factory=db_session_factory,
            llm_override=llm_override,
        )
        admin_task = _run_admin_access_phase(
            master_session_id=master_session_id,
            target_url=target_url,
            profile=profile,
            on_event=admin_prefix,
            scan_id=scan_id,
            db_session_factory=db_session_factory,
            llm_override=llm_override,
        )

        (
            chain_result,
            compliance_result,
            proof_result,
            payload_result,
            evidence_result,
            admin_result,
        ) = await asyncio.gather(
            chain_task, compliance_task, proof_task, payload_task,
            evidence_task, admin_task,
            return_exceptions=True,
        )

        if isinstance(chain_result, Exception):
            log.warning("chain phase failed: %s", chain_result)
            await on_event(f"[Chain] failed: {chain_result}; keeping breaker findings")
            chain_summary = _synthesise_summary_from_breakers(breaker_results)
        else:
            chain_summary = chain_result.summary
            chain_tool_calls = chain_result.tool_calls
            chain_turns = chain_result.turns

        if isinstance(compliance_result, Exception):
            log.warning("compliance phase failed: %s", compliance_result)
            await on_event(
                f"[Compliance] failed: {compliance_result}; skipping compliance section"
            )
        else:
            compliance_summary = compliance_result.summary
            compliance_tool_calls = compliance_result.tool_calls
            compliance_turns = compliance_result.turns

        if isinstance(proof_result, Exception):
            log.warning("proof_of_impact phase failed: %s", proof_result)
            await on_event(
                f"[ProofOfImpact] failed: {proof_result}; skipping proof-of-impact section"
            )
        else:
            proof_summary = proof_result.summary
            proof_tool_calls = proof_result.tool_calls
            proof_turns = proof_result.turns

        if isinstance(payload_result, Exception):
            log.warning("payload_crafting phase failed: %s", payload_result)
            await on_event(
                f"[PayloadCrafting] failed: {payload_result}; skipping reproducible PoCs section"
            )
        else:
            payload_summary = payload_result.summary
            payload_tool_calls = payload_result.tool_calls
            payload_turns = payload_result.turns

        if isinstance(evidence_result, Exception):
            log.warning("evidence_capture phase failed: %s", evidence_result)
            await on_event(
                f"[EvidenceCapture] failed: {evidence_result}; skipping evidence screenshots section"
            )
        else:
            evidence_summary = evidence_result.summary
            evidence_tool_calls = evidence_result.tool_calls
            evidence_turns = evidence_result.turns

        if isinstance(admin_result, Exception):
            log.warning("admin_access phase failed: %s", admin_result)
            await on_event(
                f"[AdminAccess] failed: {admin_result}; skipping admin panel access section"
            )
        else:
            admin_summary = admin_result.summary
            admin_tool_calls = admin_result.tool_calls
            admin_turns = admin_result.turns

        # Stitch the six section outputs into one operator summary.
        sections = [chain_summary] if chain_summary else []
        if compliance_summary:
            sections.append("## Compliance mapping\n\n" + compliance_summary)
        if proof_summary:
            sections.append("## Proof of Impact\n\n" + proof_summary)
        if payload_summary:
            sections.append("## Reproducible PoCs\n\n" + payload_summary)
        if evidence_summary:
            sections.append("## Evidence Screenshots\n\n" + evidence_summary)
        if admin_summary:
            sections.append("## Admin Panel Access (Verified)\n\n" + admin_summary)
        chain_summary = "\n\n".join(sections).strip()

        return SwarmOutcome(
            summary=chain_summary,
            breaker_results=tuple(breaker_results),
            used_fallback=False,
            used_fallback_reason=None,
            total_tool_calls=(
                sum(r.tool_calls for r in breaker_results)
                + chain_tool_calls + compliance_tool_calls
                + proof_tool_calls + payload_tool_calls
                + evidence_tool_calls + admin_tool_calls
            ),
            total_turns=(
                sum(r.turns for r in breaker_results)
                + chain_turns + compliance_turns
                + proof_turns + payload_turns
                + evidence_turns + admin_turns
            ),
        )
    finally:
        # Release per-breaker sessions regardless of how we exit.
        import pencheff.server as pencheff_server
        for bsid in breaker_sids:
            try:
                await pencheff_server.pentest_destroy(session_id=bsid)
            except Exception as exc:  # noqa: BLE001
                log.warning("failed to destroy breaker session %s: %s", bsid, exc)
