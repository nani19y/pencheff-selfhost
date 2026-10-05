# SPDX-License-Identifier: AGPL-3.0-or-later
"""Per-target LLM guardrail configuration endpoints.

* ``GET /targets/{id}/guardrails`` — current config + the proxy URL
  the user should point their app at.
* ``PUT /targets/{id}/guardrails`` — replace the config.
* ``GET /scans/{id}/recommended-guardrails`` — compute recommended
  guardrails from the scan's per-OWASP-LLM failure breakdown.
* ``POST /scans/{id}/recommended-guardrails/apply`` — write the
  recommended config onto the scan's underlying target with one click.

Storage lives on ``Target.llm_config["guardrails"]``; the existing
``llm_config`` JSONB column is the canonical home (no migration).
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth.deps import get_active_workspace, require_scope
from ..config import get_settings
from ..db.base import get_session
from ..db.models import Finding, Scan, Target, Workspace
from ..services.agent_firewall import (
    default_firewall_config,
    firewall_metadata,
    normalize_firewall_config,
)
from ..services.guardrails import (
    PRESETS,
    default_guardrails,
    enforcement_metadata,
    normalize,
    recommended_for_summary,
)

router = APIRouter(tags=["guardrails"])


# ─── Response shapes ────────────────────────────────────────────────


class GuardrailsMetadataOut(BaseModel):
    # Returned target-less so the new-target form can render the
    # editor before a Target row exists. ``defaults`` matches the
    # ``balanced`` preset; the new-target form pre-fills with this.
    defaults: dict[str, Any]
    enforcement: dict[str, Any]
    presets: dict[str, Any]


class GuardrailsOut(BaseModel):
    target_id: str
    proxy_url: str | None
    guardrails: dict[str, Any]
    # Static metadata the UI uses to render the LLM01-LLM10 grid:
    # which categories are inline / scan-only / side-N/A / need an
    # external judge. Plus the list of named presets.
    enforcement: dict[str, Any] = {}
    presets: dict[str, Any] = {}


class GuardrailsIn(BaseModel):
    guardrails: dict[str, Any]


class RecommendationOut(BaseModel):
    category: str
    side: str
    detector: str
    value: Any
    rationale: str
    failure_count: int


class RecommendedGuardrailsOut(BaseModel):
    target_id: str
    scan_id: str
    target_name: str | None
    summary: dict[str, int]
    recommendations: list[RecommendationOut]
    suggested_config: dict[str, Any]


class _ApplyAck(BaseModel):
    ok: bool
    target_id: str
    applied_recommendations: int


# ─── Helpers ────────────────────────────────────────────────────────


def _proxy_url_for(request: Request, target_id: str) -> str:
    """Build the URL the user should point their app at.

    Falls back to the request's base URL when the deployment hasn't
    set ``proxy_base_url`` in settings — useful for self-hosted dev
    runs where the API is on ``localhost:8000``.
    """
    settings = get_settings()
    base = (
        getattr(settings, "proxy_base_url", "")
        or str(request.base_url).rstrip("/")
    )
    # The proxy router is mounted at ``/proxy`` on the API app root (see
    # main.py: include_router(llm_proxy.router) with prefix="/proxy"). The
    # API is served at its own host (api.pencheff.com) with no ``/api``
    # mount, so the advertised URL must NOT include ``/api``.
    return f"{base}/proxy/{target_id}"


async def _load_llm_target(
    session: AsyncSession, target_id: str, workspace_id: str,
) -> Target:
    target = await session.get(Target, target_id)
    if target is None or target.workspace_id != workspace_id:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND, "target not found",
        )
    if target.kind != "llm":
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "guardrails are only configurable on LLM targets "
            f"(this target is kind={target.kind!r}).",
        )
    return target


# ─── /guardrails/metadata ──────────────────────────────────────────


@router.get(
    "/guardrails/metadata",
    response_model=GuardrailsMetadataOut,
    dependencies=[Depends(require_scope("targets:read"))],
)
async def get_guardrails_metadata() -> GuardrailsMetadataOut:
    """Return the bits the editor needs without binding to a target.

    The new-target form renders the same editor before a Target row
    exists, so it can't hit ``/targets/{id}/guardrails``. This endpoint
    serves the static metadata (enforcement matrix, presets) plus the
    canonical default config the form should pre-fill with.
    """
    return GuardrailsMetadataOut(
        defaults=normalize(default_guardrails()),
        enforcement=enforcement_metadata(),
        presets=PRESETS,
    )


# ─── /targets/{id}/guardrails ──────────────────────────────────────


@router.get(
    "/targets/{target_id}/guardrails",
    response_model=GuardrailsOut,
    dependencies=[Depends(require_scope("targets:read"))],
)
async def get_target_guardrails(
    target_id: str,
    request: Request,
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> GuardrailsOut:
    target = await _load_llm_target(session, target_id, workspace.id)
    cfg = (target.llm_config or {}).get("guardrails")
    return GuardrailsOut(
        target_id=target_id,
        proxy_url=_proxy_url_for(request, target_id),
        guardrails=normalize(cfg),
        enforcement=enforcement_metadata(),
        presets=PRESETS,
    )


@router.put(
    "/targets/{target_id}/guardrails",
    response_model=GuardrailsOut,
    dependencies=[Depends(require_scope("targets:write"))],
)
async def put_target_guardrails(
    target_id: str,
    body: GuardrailsIn,
    request: Request,
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> GuardrailsOut:
    target = await _load_llm_target(session, target_id, workspace.id)
    next_cfg = normalize(body.guardrails)
    # Merge into existing llm_config so we don't blow away
    # provider / model / system_prompt / etc.
    llm_config = dict(target.llm_config or {})
    llm_config["guardrails"] = next_cfg
    target.llm_config = llm_config
    await session.commit()
    await session.refresh(target)
    return GuardrailsOut(
        target_id=target_id,
        proxy_url=_proxy_url_for(request, target_id),
        guardrails=normalize((target.llm_config or {}).get("guardrails")),
        enforcement=enforcement_metadata(),
        presets=PRESETS,
    )


# ─── /targets/{id}/firewall ────────────────────────────────────────


class FirewallOut(BaseModel):
    target_id: str
    proxy_url: str | None
    firewall: dict[str, Any]
    # {actions, default_rules} — static editor metadata.
    metadata: dict[str, Any] = {}


class FirewallIn(BaseModel):
    firewall: dict[str, Any]


@router.get(
    "/targets/{target_id}/firewall",
    response_model=FirewallOut,
    dependencies=[Depends(require_scope("targets:read"))],
)
async def get_target_firewall(
    target_id: str,
    request: Request,
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> FirewallOut:
    target = await _load_llm_target(session, target_id, workspace.id)
    cfg = (target.llm_config or {}).get("firewall")
    try:
        fw = normalize_firewall_config(cfg) if cfg else default_firewall_config()
    except ValueError:
        # Tolerate a hand-corrupted stored config on read; the editor lets
        # the operator re-save a valid one.
        fw = default_firewall_config()
    return FirewallOut(
        target_id=target_id,
        proxy_url=_proxy_url_for(request, target_id),
        firewall=fw,
        metadata=firewall_metadata(),
    )


@router.put(
    "/targets/{target_id}/firewall",
    response_model=FirewallOut,
    dependencies=[Depends(require_scope("targets:write"))],
)
async def put_target_firewall(
    target_id: str,
    body: FirewallIn,
    request: Request,
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> FirewallOut:
    target = await _load_llm_target(session, target_id, workspace.id)
    try:
        next_cfg = normalize_firewall_config(body.firewall)
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc))
    # Merge into existing llm_config so we don't clobber guardrails / provider.
    llm_config = dict(target.llm_config or {})
    llm_config["firewall"] = next_cfg
    target.llm_config = llm_config
    await session.commit()
    await session.refresh(target)
    return FirewallOut(
        target_id=target_id,
        proxy_url=_proxy_url_for(request, target_id),
        firewall=next_cfg,
        metadata=firewall_metadata(),
    )


# ─── /scans/{id}/recommended-guardrails ────────────────────────────


async def _by_category_from_findings(
    session: AsyncSession, scan_id: str
) -> dict[str, int]:
    """Derive the OWASP-LLM by-category breakdown from persisted findings.

    Used as a fallback when ``scan.summary['llm_redteam_by_category']`` is
    missing — older scans (pre-fix) never had the breakdown written into
    summary, but their findings carry ``owasp_category``. Recovers the
    recommendation set without forcing a re-scan.
    """
    rows = (
        await session.execute(
            select(Finding.owasp_category, func.count())
            .where(Finding.scan_id == scan_id)
            .where(Finding.suppressed.is_(False))
            .where(Finding.owasp_category.is_not(None))
            .group_by(Finding.owasp_category)
        )
    ).all()
    out: dict[str, int] = {}
    for cat, n in rows:
        if not cat:
            continue
        # owasp_category may carry a "LLM01: …" prefix or just "LLM01".
        code = str(cat).split(":", 1)[0].strip()
        if code.startswith("LLM"):
            out[code] = out.get(code, 0) + int(n)
    return out


@router.get(
    "/scans/{scan_id}/recommended-guardrails",
    response_model=RecommendedGuardrailsOut,
    dependencies=[Depends(require_scope("scans:read"))],
)
async def get_recommended_guardrails(
    scan_id: str,
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> RecommendedGuardrailsOut:
    scan = await session.get(Scan, scan_id)
    if scan is None or scan.workspace_id != workspace.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "scan not found")
    target = await session.get(Target, scan.target_id)
    if target is None or target.kind != "llm":
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "recommended guardrails are only computed for LLM red-team scans",
        )
    summary = dict(scan.summary or {})
    if not summary.get("llm_redteam_by_category"):
        derived = await _by_category_from_findings(session, scan_id)
        if derived:
            summary["llm_redteam_by_category"] = derived
    rec = recommended_for_summary(
        scan_id=scan_id, target_id=target.id,
        target_name=target.name, summary=summary,
    )
    return RecommendedGuardrailsOut(
        target_id=rec.target_id,
        scan_id=rec.scan_id,
        target_name=rec.target_name,
        summary=rec.summary,
        recommendations=[
            RecommendationOut(
                category=r.category, side=r.side,
                detector=r.detector, value=r.value,
                rationale=r.rationale,
                failure_count=r.failure_count,
            )
            for r in rec.recommendations
        ],
        suggested_config=rec.suggested_config,
    )


@router.post(
    "/scans/{scan_id}/recommended-guardrails/apply",
    response_model=_ApplyAck,
    dependencies=[Depends(require_scope("targets:write"))],
)
async def apply_recommended_guardrails(
    scan_id: str,
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> _ApplyAck:
    scan = await session.get(Scan, scan_id)
    if scan is None or scan.workspace_id != workspace.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "scan not found")
    target = await session.get(Target, scan.target_id)
    if target is None or target.kind != "llm":
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "recommended guardrails are only applicable to LLM targets",
        )
    summary = dict(scan.summary or {})
    if not summary.get("llm_redteam_by_category"):
        derived = await _by_category_from_findings(session, scan_id)
        if derived:
            summary["llm_redteam_by_category"] = derived
    rec = recommended_for_summary(
        scan_id=scan_id, target_id=target.id,
        target_name=target.name, summary=summary,
    )
    llm_config = dict(target.llm_config or {})
    llm_config["guardrails"] = rec.suggested_config
    target.llm_config = llm_config
    await session.commit()
    return _ApplyAck(
        ok=True,
        target_id=target.id,
        applied_recommendations=len(rec.recommendations),
    )
