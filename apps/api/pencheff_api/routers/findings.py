import logging
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth.deps import get_active_workspace, require_scope
from ..db.base import get_session
from ..db.models import Finding, Scan, Workspace
from ..schemas.findings import (
    FindingOut,
    FindingTriageOut,
    StatusUpdate,
    SuppressRequest,
)
from ..services.ai_gate import org_has_ai
from ..services.llm_providers.resolver import resolve_chat_client
from ..services.triage_llm import TriageLLMClient
from ..services.worker_lifecycle import (
    ensure_worker_started_for_enqueue_sync,
    ensure_worker_started_or_503,
)
from ..tasks.integration_notify_task import notify_event
from ..tasks.recheck_task import recheck_finding

router = APIRouter(prefix="/findings", tags=["findings"])

_log = logging.getLogger("pencheff.findings")


def _fire_changed(scan_id: str | None, finding_id: str, change_summary: str) -> None:
    """Best-effort enqueue of a finding_changed lifecycle event. Failure
    must never propagate — the analyst's mutation has already committed
    and integration delivery is async/auxiliary."""
    if not scan_id:
        return
    try:
        ensure_worker_started_for_enqueue_sync()
        notify_event.delay(scan_id, "finding_changed",
                           finding_id=finding_id,
                           change_summary=change_summary)
    except Exception as exc:  # noqa: BLE001
        _log.warning("finding_changed enqueue failed: %s", exc)


def _triage_to_out(value: dict | None) -> FindingTriageOut | None:
    if not isinstance(value, dict):
        return None
    return FindingTriageOut(
        walkthrough=value.get("walkthrough") or None,
        blast_radius=value.get("blast_radius") or None,
        exploit_scenario=value.get("exploit_scenario") or None,
        fix_outline=value.get("fix_outline") or None,
        confidence=value.get("confidence") or None,
        model=value.get("model") or None,
    )


def _evidence_excerpt_for_llm(f: Finding) -> str | None:
    """Mirror of ``scan_runner._evidence_excerpt`` — kept here to avoid
    importing the worker-side module into the API process."""
    ev = f.evidence or []
    if not ev:
        return None
    first = ev[0] if isinstance(ev, list) else ev
    if not isinstance(first, dict):
        return None
    parts: list[str] = []
    if first.get("request_method") and first.get("request_url"):
        parts.append(f"{first['request_method']} {first['request_url']}")
    if first.get("response_status") is not None:
        parts.append(f"→ {first['response_status']}")
    headers = first.get("response_headers") or {}
    if isinstance(headers, dict):
        ctype = headers.get("content-type") or headers.get("Content-Type")
        if ctype:
            parts.append(f"content-type={ctype}")
    body = first.get("response_body_snippet")
    if body:
        parts.append(f"body: {str(body)[:400]}")
    elif first.get("description"):
        parts.append(str(first["description"])[:400])
    return " · ".join(p for p in parts if p)


def _to_out(f: Finding) -> FindingOut:
    return FindingOut(
        id=f.id, scan_id=f.scan_id, title=f.title, severity=f.severity,
        category=f.category, owasp_category=f.owasp_category, cwe_id=f.cwe_id,
        cvss_score=f.cvss_score, cvss_vector=f.cvss_vector, endpoint=f.endpoint,
        parameter=f.parameter, description=f.description, remediation=f.remediation,
        evidence=f.evidence, references=f.references_,
        verification_status=f.verification_status, hackable=f.hackable, suppressed=f.suppressed,
        suppress_reason=f.suppress_reason, last_rechecked_at=f.last_rechecked_at,
        recheck_status=f.recheck_status,
        ai_triage=_triage_to_out(f.ai_triage),
        risk_score=f.risk_score, ssvc_decision=f.ssvc_decision,
        reachability=f.reachability,
        epss=f.epss, kev=f.kev,
        created_at=f.created_at,
    )


async def _get_owned_finding(session: AsyncSession, finding_id: str, workspace_id: str) -> Finding:
    row = (await session.execute(
        select(Finding, Scan).join(Scan, Scan.id == Finding.scan_id)
        .where(Finding.id == finding_id, Scan.workspace_id == workspace_id)
    )).first()
    if not row:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "finding not found")
    return row[0]


@router.get(
    "",
    response_model=list[FindingOut],
    dependencies=[Depends(require_scope("findings:read"))],
)
async def list_findings(
    scan_id: str,
    severity: str | None = None,
    include_suppressed: bool = True,
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> list[FindingOut]:
    # Verify scan belongs to workspace
    scan = (await session.execute(
        select(Scan).where(Scan.id == scan_id, Scan.workspace_id == workspace.id)
    )).scalar_one_or_none()
    if not scan:
        # TEMP DIAG: the scan exists but not in the resolved workspace — surface
        # which workspace the request landed in vs where the scan actually lives.
        import logging as _lg
        owner = (await session.execute(
            select(Scan.workspace_id).where(Scan.id == scan_id)
        )).scalar_one_or_none()
        _lg.getLogger("pencheff_api.findings").warning(
            "DIAG list_findings 404: scan=%s resolved_ws=%s scan_ws=%s inc_suppressed=%s",
            scan_id, workspace.id, owner, include_suppressed)
        raise HTTPException(status.HTTP_404_NOT_FOUND, "scan not found")

    q = select(Finding).where(Finding.scan_id == scan_id)
    if severity:
        q = q.where(Finding.severity == severity.lower())
    if not include_suppressed:
        q = q.where(Finding.suppressed.is_(False))
    # Sort by Pencheff's unified priority score (CVSS × EPSS × KEV × SSVC).
    # NULL risk_scores (pre-prioritisation findings) sort last via NULLS LAST,
    # then severity, then chronological order so equally-prioritised findings
    # surface deterministically.
    q = q.order_by(Finding.risk_score.desc().nullslast(),
                   Finding.severity, Finding.created_at)
    rows = (await session.execute(q)).scalars().all()
    import logging as _lg
    _lg.getLogger("pencheff_api.findings").warning(
        "DIAG list_findings OK: scan=%s ws=%s inc_suppressed=%s rows=%d",
        scan_id, workspace.id, include_suppressed, len(rows))
    return [_to_out(f) for f in rows]


@router.get(
    "/{finding_id}",
    response_model=FindingOut,
    dependencies=[Depends(require_scope("findings:read"))],
)
async def get_finding(
    finding_id: str,
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> FindingOut:
    f = await _get_owned_finding(session, finding_id, workspace.id)
    return _to_out(f)


@router.post(
    "/{finding_id}/triage",
    response_model=FindingOut,
    dependencies=[Depends(require_scope("findings:write"))],
)
async def triage(
    finding_id: str,
    force: bool = False,
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> FindingOut:
    """Triage 2.0 — exploitability walkthrough.

    Idempotent: cached in ``finding.ai_triage`` after the first
    successful call. Pass ``force=true`` to regenerate (e.g. when the
    underlying evidence has been updated by a recheck).

    Pro-tier feature; gated through ``org_has_ai``.
    """
    f = await _get_owned_finding(session, finding_id, workspace.id)
    if f.ai_triage and not force:
        return _to_out(f)

    # Check whether the org has brought their own LLM provider.
    # If so, route through it and skip the Pencheff Pro gate — they are
    # supplying their own compute; quota/billing is on their provider.
    org_llm_client = await resolve_chat_client(workspace.org_id, session)

    if org_llm_client is None and not await org_has_ai(session, workspace.org_id):
        raise HTTPException(
            status.HTTP_402_PAYMENT_REQUIRED,
            "Triage walkthroughs require Pro. The deterministic finding, "
            "evidence, and remediation guidance remain free.",
        )

    # ponytail: CE is credit-free (single-tenant) — no AI credit gate.
    client = TriageLLMClient()
    if org_llm_client is not None:
        client.set_org_client(org_llm_client)
    elif not client.enabled:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "Triage backend not configured — set FIX_LLM_API_KEY to "
            "enable triage walkthroughs.",
        )

    try:
        result = await client.triage_finding(
            title=f.title,
            severity=(f.severity or "info").lower(),
            category=f.category or "",
            endpoint=f.endpoint,
            parameter=f.parameter,
            description=f.description,
            evidence_excerpt=_evidence_excerpt_for_llm(f) or "",
            cvss_score=f.cvss_score,
            reachability=f.reachability,
            epss=f.epss,
            kev=bool(f.kev),
            cwe_id=f.cwe_id,
            owasp_category=f.owasp_category,
        )
    except Exception as exc:  # noqa: BLE001
        _log.exception("triage call failed: %s", exc)
        raise HTTPException(
            status.HTTP_502_BAD_GATEWAY,
            "Triage LLM call failed — try again in a moment.",
        )

    if result is None:
        raise HTTPException(
            status.HTTP_502_BAD_GATEWAY,
            "Triage LLM returned no usable response — the provider may "
            "be rate-limited. Retry shortly.",
        )

    f.ai_triage = result.to_dict()
    # ponytail: CE is credit-free (single-tenant) — no credit debit.
    await session.commit()
    await session.refresh(f)
    return _to_out(f)


@router.post(
    "/{finding_id}/recheck",
    response_model=FindingOut,
    dependencies=[Depends(require_scope("findings:write"))],
)
async def recheck(
    finding_id: str,
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> FindingOut:
    f = await _get_owned_finding(session, finding_id, workspace.id)
    await ensure_worker_started_or_503()

    f.recheck_status = "queued"
    await session.commit()
    recheck_finding.delay(f.id)
    _fire_changed(f.scan_id, f.id, "recheck queued")
    await session.refresh(f)
    return _to_out(f)


@router.post(
    "/{finding_id}/status",
    response_model=FindingOut,
    dependencies=[Depends(require_scope("findings:write"))],
)
async def update_status(
    finding_id: str,
    body: StatusUpdate,
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> FindingOut:
    f = await _get_owned_finding(session, finding_id, workspace.id)
    prev = f.verification_status or "unverified"
    f.verification_status = body.verification_status
    await session.commit()
    # NOTE: Intentionally do NOT recompute the scan grade or summary here.
    # The grade is set once at scan completion (LLM-assigned or heuristic)
    # and stays fixed; annotating a finding with true_positive / fixed /
    # false_positive is analyst metadata, not a change in the underlying
    # assessment. The user explicitly requested that the grade not change
    # after the scan is done.
    if prev != body.verification_status:
        _fire_changed(f.scan_id, f.id,
                      f"verification_status: {prev} → {body.verification_status}")
    await session.refresh(f)
    return _to_out(f)


class _VerifyWithHumansBody(BaseModel):
    """Phase 4.2 — request body for ``POST /findings/{id}/verify-with-humans``.

    ``integration_kind`` must match a partner integration the
    workspace has configured (one of ``hackerone`` / ``bugcrowd`` /
    ``cobalt`` from Phase 1.2).
    """
    integration_kind: Literal["hackerone", "bugcrowd", "cobalt"]
    integration_id: str | None = None  # specific integration row to use; first match if omitted


class _VerifyWithHumansAck(BaseModel):
    ok: bool
    integration_kind: str
    submission_url: str | None = None
    error: str | None = None


@router.post(
    "/{finding_id}/verify-with-humans",
    response_model=_VerifyWithHumansAck,
    dependencies=[Depends(require_scope("findings:write"))],
)
async def verify_with_humans(
    finding_id: str,
    body: _VerifyWithHumansBody,
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> _VerifyWithHumansAck:
    """Submit a finding to a partner pentest platform for human triage.

    Reuses the Phase 1.2 ``integration_dispatch`` formatter pipeline —
    the partner sees a normal ``finding_new`` event for this single
    finding. When the triager confirms upstream, their platform's
    webhook calls back into ``POST /findings/{id}/verify-callback``,
    which flips the finding's ``verification_status`` to
    ``true_positive``.
    """
    from ..db.models import Integration  # local import — avoids ORM cost on cold reads
    from ..services import integration_dispatch

    f = await _get_owned_finding(session, finding_id, workspace.id)

    # Find the chosen integration row.
    q = select(Integration).where(
        Integration.workspace_id == workspace.id,
        Integration.kind == body.integration_kind,
    )
    if body.integration_id:
        q = q.where(Integration.id == body.integration_id)
    integration = (await session.execute(q.limit(1))).scalar_one_or_none()
    if integration is None:
        return _VerifyWithHumansAck(
            ok=False, integration_kind=body.integration_kind,
            error=(
                f"No {body.integration_kind!r} integration configured for "
                "this workspace. Add one under Settings → Integrations."
            ),
        )

    payload = {
        "event": "finding_new",
        "scan_id": f.scan_id,
        "finding": {
            "id": f.id,
            "title": f.title,
            "severity": f.severity,
            "description": f.description,
            "endpoint": f.endpoint,
            "cvss_score": f.cvss_score,
        },
    }
    result = await integration_dispatch.dispatch_event(
        kind=integration.kind,
        config=integration.config or {},
        payload=payload,
    )
    submission_url = (
        (result.get("response") or "")[:300] if isinstance(result.get("response"), str)
        else None
    )
    return _VerifyWithHumansAck(
        ok=bool(result.get("ok")),
        integration_kind=body.integration_kind,
        submission_url=submission_url,
        error=result.get("error"),
    )


class _VerifyCallbackBody(BaseModel):
    """Body the partner sends when a triager confirms upstream."""
    verdict: Literal["confirmed", "duplicate", "informative", "not-applicable"]
    triager: str | None = None
    triage_url: str | None = None
    notes: str | None = None


@router.post(
    "/{finding_id}/verify-callback",
    response_model=FindingOut,
    dependencies=[Depends(require_scope("findings:write"))],
)
async def verify_callback(
    finding_id: str,
    body: _VerifyCallbackBody,
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> FindingOut:
    """Partner-side callback — flips a finding's verification state
    based on the triager's verdict.

    Mapping:

    * ``confirmed``       → ``verification_status = true_positive``
    * ``duplicate``       → suppressed with reason ``duplicate``
    * ``informative``     → ``verification_status = false_positive``
    * ``not-applicable``  → suppressed with reason ``out_of_scope``
    """
    f = await _get_owned_finding(session, finding_id, workspace.id)
    prev_status = f.verification_status or "unverified"
    notes = body.notes or (
        f"Triaged by {body.triager or 'partner'}. "
        f"{body.triage_url or ''}".strip()
    )
    if body.verdict == "confirmed":
        f.verification_status = "true_positive"
    elif body.verdict == "informative":
        f.verification_status = "false_positive"
    elif body.verdict == "duplicate":
        f.suppressed = True
        f.suppress_reason = "duplicate"
        f.suppress_notes = notes
    elif body.verdict == "not-applicable":
        f.suppressed = True
        f.suppress_reason = "out_of_scope"
        f.suppress_notes = notes
    await session.commit()
    _fire_changed(
        f.scan_id, f.id,
        f"partner triage verdict={body.verdict} (was: {prev_status})",
    )
    await session.refresh(f)
    return _to_out(f)


@router.post(
    "/{finding_id}/suppress",
    response_model=FindingOut,
    dependencies=[Depends(require_scope("findings:write"))],
)
async def suppress(
    finding_id: str,
    body: SuppressRequest,
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> FindingOut:
    f = await _get_owned_finding(session, finding_id, workspace.id)
    f.suppressed = True
    f.suppress_reason = body.reason
    f.suppress_notes = body.notes
    await session.commit()
    # See note in update_status: grade is fixed once the scan completes.
    _fire_changed(f.scan_id, f.id,
                  f"suppressed (reason: {body.reason or 'unspecified'})")
    await session.refresh(f)
    return _to_out(f)


@router.post(
    "/{finding_id}/unsuppress",
    response_model=FindingOut,
    dependencies=[Depends(require_scope("findings:write"))],
)
async def unsuppress(
    finding_id: str,
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> FindingOut:
    f = await _get_owned_finding(session, finding_id, workspace.id)
    f.suppressed = False
    f.suppress_reason = None
    f.suppress_notes = None
    await session.commit()
    _fire_changed(f.scan_id, f.id, "unsuppressed")
    await session.refresh(f)
    return _to_out(f)
