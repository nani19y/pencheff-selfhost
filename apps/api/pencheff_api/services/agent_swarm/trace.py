"""Shared detailed-log helpers for the kind orchestrators (cloud / network / host
/ identity / artifact). Turns a 1–2 line scan log into a per-finding trace so the
UI Assessment Log shows exactly what each scan surfaced — mirroring the per-probe
trace the voice module emits. One commit per call (bounded to 1000 lines)."""
from __future__ import annotations

from typing import Any

from sqlalchemy import select


def enqueue_validation(scan_id: str) -> None:
    """Queue AI-agent finding verification after an orchestrator scan completes —
    mirrors scan_runner._enqueue_validation so cloud/network/host/identity findings
    get the same 'hackable' verdict as web/API. Best-effort; never raises."""
    try:
        from ...tasks.validate_task import validate_findings
        validate_findings.delay(scan_id, "standard")
    except Exception:  # noqa: BLE001
        pass


async def log_scan_trace(Session: Any, scan_id: str, lines: list[str]) -> None:
    """Append trace lines to Scan.log in a single commit (never raises)."""
    from ...db.models import Scan
    if not lines:
        return
    try:
        async with Session() as db:
            s = (await db.execute(select(Scan).where(Scan.id == scan_id))).scalar_one()
            s.log = (list(s.log or []) + [str(x) for x in lines])[-1000:]
            await db.commit()
    except Exception:  # noqa: BLE001 — logging must never break a scan
        pass


def finding_lines(tag: str, kind: str, findings: list[dict], *, limit: int = 50) -> list[str]:
    """One line per finding: ``[tag] → SEV: title  (endpoint)``, plus a count
    header and a truncation note. Accepts the orchestrators' dict findings."""
    out = [f"[{tag}] {kind}: {len(findings)} finding(s)"
           + ("" if findings else " — clean")]
    for f in findings[:limit]:
        sev = str(f.get("severity", "?")).upper()
        title = str(f.get("title", ""))[:120]
        ep = str(f.get("endpoint") or "")
        out.append(f"[{tag}] → {sev}: {title}" + (f"  ({ep[:64]})" if ep else ""))
    if len(findings) > limit:
        out.append(f"[{tag}] … {len(findings) - limit} more finding(s) (see register)")
    return out
