"""Telemetry helpers for the swarm — writes per-agent stats into the
existing Scan.summary JSON column so the scan-detail UI can surface
them later (Spec follow-up F1)."""
from __future__ import annotations

import logging
from typing import Any

from sqlalchemy import select

from ...db.models import Scan
from .orchestrator import BreakerResult, SwarmOutcome

log = logging.getLogger("pencheff.swarm.telemetry")


def build_swarm_summary_payload(outcome: SwarmOutcome) -> dict[str, Any]:
    return {
        "used_fallback": outcome.used_fallback,
        "used_fallback_reason": outcome.used_fallback_reason,
        "breakers": [
            {
                "agent": r.agent_name,
                "success": r.success,
                "findings": len(r.finding_ids),
                "turns": r.turns,
                "tool_calls": r.tool_calls,
                "error": r.error,
            }
            for r in outcome.breaker_results
        ],
    }


async def persist_swarm_telemetry(
    *, scan_id: str, outcome: SwarmOutcome, db_session_factory,
) -> None:
    """Merge the swarm payload into Scan.summary."""
    async with db_session_factory() as db:
        scan = (await db.execute(
            select(Scan).where(Scan.id == scan_id)
        )).scalar_one_or_none()
        if scan is None:
            log.warning("persist_swarm_telemetry: scan %s not found", scan_id)
            return
        merged = dict(scan.summary or {})
        merged["swarm"] = build_swarm_summary_payload(outcome)
        scan.summary = merged
        await db.commit()
