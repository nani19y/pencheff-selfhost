"""Re-run a single finding's verification by invoking the exploit_finding
playbook against the finding's live endpoint.

Previously this module ran the original heavyweight scanner module (HeadersModule,
SQLiModule, etc.) keyed on a fine-grained ``finding.category`` like
``web.headers`` / ``injection.sqli``. In production, ~95% of findings carry
coarse categories (``misconfiguration``, ``crypto``, ``template``, ``logic``),
which CATEGORY_MODULES never matched — so every recheck landed in
``unsupported_category`` and the status field was useless.

The fix re-uses the ``exploit_finding`` MCP tool's category-specific playbooks
that we shipped for the scan path. Same playbooks (clickjacking PoC, header
capture, rate-limit burst, SQLi schema enumeration, etc.), now invoked
post-scan against a freshly-built minimal session scoped to the finding's
endpoint. Result:

- ``exploit_succeeded=True``  → recheck_status="true_positive" (still vulnerable)
- ``exploit_succeeded=False`` → recheck_status="fixed"           (no longer reproduces)
- Playbook raised / no signal → recheck_status="error"           (don't lie about status)

The captured request/response from the playbook is appended to the finding's
``evidence`` JSONB column, so a recheck UI can show the diff between original
scan evidence and the latest probe.
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from ..config import get_settings
from ..db.models import Finding as DbFinding, Scan, Target
from .credentials import decrypt_credentials

log = logging.getLogger(__name__)


async def recheck(finding_id: str) -> str:
    """Re-verify a finding via the exploit_finding playbook.

    Returns one of:
      ``true_positive`` — playbook reproduced the issue (still vulnerable).
      ``fixed``         — playbook ran but could not reproduce (likely patched).
      ``error``         — playbook errored or the finding is malformed.

    Side effects (one row updated in ``findings``):
      ``last_rechecked_at`` — set to now.
      ``recheck_status``    — set to the return value above.
      ``verification_status`` — synchronized to the new status when it's TP/FP.
      ``evidence``          — new playbook-captured Evidence entries appended.
    """
    from pencheff.core.findings import Finding as PFinding
    from pencheff.core.session import _sessions, create_session as pencheff_create_session
    from pencheff.config import Severity
    import pencheff.server as pencheff_srv

    settings = get_settings()
    engine = create_async_engine(settings.database_url, future=True)
    Session = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)

    # ── Load finding + scan + target ───────────────────────────────────────
    async with Session() as db:
        finding = (
            await db.execute(select(DbFinding).where(DbFinding.id == finding_id))
        ).scalar_one_or_none()
        if not finding:
            return "error"
        scan = (await db.execute(select(Scan).where(Scan.id == finding.scan_id))).scalar_one()
        target = (await db.execute(select(Target).where(Target.id == scan.target_id))).scalar_one()
        creds = decrypt_credentials(target.credentials_encrypted)

    # ── Build a minimal session scoped to this finding's endpoint ──────────
    # create_session registers the new session in _sessions, so the
    # ``exploit_finding`` MCP tool's _require_session call will find it.
    try:
        psession = pencheff_create_session(
            target_url=target.base_url,
            credentials=creds,
            scope=[target.base_url],
            exclude_paths=list(target.exclude_paths or []) or None,
            depth="quick",
        )
    except Exception as exc:  # noqa: BLE001
        log.warning("recheck session create failed for %s: %s", finding_id, exc)
        await _mark(finding_id, Session, status="error")
        return "error"

    # Reconstruct a pencheff Finding so exploit_finding can look it up by id.
    try:
        sev_val = (finding.severity or "info").lower()
        try:
            sev = Severity(sev_val)
        except Exception:  # noqa: BLE001
            sev = Severity.INFO
        pfinding = PFinding(
            title=finding.title or "",
            severity=sev,
            category=finding.category or "",
            owasp_category=finding.owasp_category or "",
            description=finding.description or "",
            remediation=finding.remediation or "",
            endpoint=finding.endpoint or target.base_url,
            parameter=finding.parameter,
        )
        psession.findings.add_force(pfinding)
    except Exception as exc:  # noqa: BLE001
        log.warning("recheck finding reconstruction failed for %s: %s", finding_id, exc)
        _sessions.pop(psession.id, None)
        await _mark(finding_id, Session, status="error")
        return "error"

    # ── Run the exploit_finding playbook ───────────────────────────────────
    try:
        result = await pencheff_srv.exploit_finding(
            session_id=psession.id, finding_id=pfinding.id
        )
    except Exception as exc:  # noqa: BLE001
        log.warning("recheck exploit_finding failed for %s: %s", finding_id, exc)
        result = {"exploit_succeeded": False, "error": f"{type(exc).__name__}: {exc}"}
    finally:
        _sessions.pop(psession.id, None)

    # ── Translate playbook result → recheck status ─────────────────────────
    if result.get("error"):
        new_status = "error"
    elif result.get("exploit_succeeded"):
        new_status = "true_positive"
    else:
        new_status = "fixed"

    # ── Persist: status timestamps + new evidence appended ─────────────────
    new_evidence = [e.to_dict() for e in pfinding.evidence]
    async with Session() as db:
        f = (await db.execute(select(DbFinding).where(DbFinding.id == finding_id))).scalar_one()
        f.last_rechecked_at = datetime.now(timezone.utc)
        f.recheck_status = new_status
        # Sync verification_status to match for TP / fixed; leave on error.
        if new_status == "true_positive":
            f.verification_status = "true_positive"
        elif new_status == "fixed":
            f.verification_status = "false_positive"
        if new_evidence:
            existing = list(f.evidence or [])
            f.evidence = existing + new_evidence
        await db.commit()
    return new_status


async def _mark(finding_id: str, Session, *, status: str) -> None:
    """Tiny helper for early-exit status writes (session-build failures, etc.)."""
    async with Session() as db:
        f = (
            await db.execute(select(DbFinding).where(DbFinding.id == finding_id))
        ).scalar_one_or_none()
        if f is not None:
            f.last_rechecked_at = datetime.now(timezone.utc)
            f.recheck_status = status
            await db.commit()


def recheck_sync(finding_id: str) -> str:
    return asyncio.run(recheck(finding_id))
