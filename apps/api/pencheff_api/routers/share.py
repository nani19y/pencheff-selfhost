"""Share-by-link route for LLM red-team scans.

A scan owner generates a token via ``POST /scans/{id}/share`` (auth
required); the token is a Fernet-encrypted JSON payload containing
``{scan_id, expires_at}``. The public ``GET /share/llm/{token}``
route decrypts, validates expiry, loads the scan + findings, and
renders the LLM-flavored summary as either Markdown or self-contained
HTML.

No new DB table is needed — the encrypted token IS the credential.
This means revocation is "let it expire" rather than "delete a
share row"; for v1 that's an acceptable tradeoff. A `?download=html`
query param emits the HTML renderer for offline-share use.
"""
from __future__ import annotations

import json
import logging
import time
from typing import Any

from cryptography.fernet import Fernet, InvalidToken
from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth.deps import get_active_workspace, get_current_user
from ..db.base import get_session
from ..db.models import Finding as DbFinding, Scan, Target, User, Workspace
from ..services.credentials import _fernet  # reuse the existing fernet key

log = logging.getLogger(__name__)

router = APIRouter(tags=["share"])

# Token TTL caps: the issuer can pick anything up to 90 days.
_MAX_TTL_SECONDS = 90 * 24 * 3600


def _encode_token(scan_id: str, ttl_seconds: int) -> str:
    ttl = min(max(int(ttl_seconds or 0), 60), _MAX_TTL_SECONDS)
    payload = {"scan_id": scan_id, "expires_at": int(time.time()) + ttl}
    return _fernet().encrypt(json.dumps(payload, separators=(",", ":")).encode()).decode()


def _decode_token(token: str) -> dict[str, Any]:
    try:
        payload = _fernet().decrypt(token.encode())
    except InvalidToken as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "share link invalid or expired") from exc
    try:
        data = json.loads(payload.decode())
    except (json.JSONDecodeError, ValueError) as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "share link malformed") from exc
    expires = int(data.get("expires_at") or 0)
    if expires < int(time.time()):
        raise HTTPException(status.HTTP_410_GONE, "share link expired")
    return data


# ── Issue a share link (auth required) ──────────────────────────────


@router.post("/scans/{scan_id}/share")
async def create_share(
    scan_id: str,
    ttl_seconds: int = Query(default=7 * 24 * 3600, ge=60, le=_MAX_TTL_SECONDS),
    workspace: Workspace = Depends(get_active_workspace),
    user: User = Depends(get_current_user),  # noqa: ARG001 — auth gate only
    session: AsyncSession = Depends(get_session),
) -> dict:
    scan = (await session.execute(
        select(Scan).where(Scan.id == scan_id, Scan.workspace_id == workspace.id)
    )).scalar_one_or_none()
    if not scan:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "scan not found")
    target = (await session.execute(
        select(Target).where(Target.id == scan.target_id)
    )).scalar_one_or_none()
    if not target or target.kind != "llm":
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "share-by-link only available for LLM red-team scans (kind='llm')",
        )
    token = _encode_token(scan.id, ttl_seconds)
    return {"token": token, "expires_in": ttl_seconds, "url_path": f"/share/llm/{token}"}


# ── Public render — no auth ─────────────────────────────────────────


@router.get("/share/llm/{token}")
async def render_share(
    token: str,
    download: str | None = Query(default=None, description="html | markdown | json"),
    session: AsyncSession = Depends(get_session),
) -> Response:
    data = _decode_token(token)
    scan_id = data["scan_id"]
    scan = (await session.execute(select(Scan).where(Scan.id == scan_id))).scalar_one_or_none()
    if not scan:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "scan not found")
    findings = (await session.execute(
        select(DbFinding).where(
            DbFinding.scan_id == scan_id, DbFinding.suppressed.is_(False)
        )
    )).scalars().all()
    payload = [
        {
            "id": f.id, "title": f.title, "severity": f.severity,
            "category": f.category, "owasp_category": f.owasp_category,
            "endpoint": f.endpoint, "parameter": f.parameter,
            "description": f.description, "remediation": f.remediation,
            "cwe_id": f.cwe_id,
        }
        for f in findings
    ]

    from pencheff.modules.llm_red_team.reporting import (
        build_red_team_summary,
        render_red_team_markdown,
    )
    from pencheff.modules.llm_red_team.reporting_extras import render_csv, render_html

    summary = build_red_team_summary(payload)
    fmt = (download or "html").lower()
    if fmt == "json":
        return Response(
            content=json.dumps({"summary": summary, "findings": payload}, indent=2),
            media_type="application/json",
        )
    if fmt == "csv":
        return Response(content=render_csv(payload), media_type="text/csv")
    if fmt == "markdown":
        return Response(
            content=render_red_team_markdown(summary),
            media_type="text/markdown; charset=utf-8",
        )
    # default: self-contained HTML
    meta = (
        f"Scan {scan_id[:8]} · profile {scan.profile} · "
        f"grade {scan.grade or '—'} · {scan.created_at.isoformat()[:19].replace('T', ' ')}"
    )
    return Response(
        content=render_html(payload, summary=summary, meta=meta),
        media_type="text/html; charset=utf-8",
    )
