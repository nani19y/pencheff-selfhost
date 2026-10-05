"""Browser-extension ingest endpoint.

The extension authenticates with a per-engagement bearer token. Every batch
of captured flows is bulk-inserted into ``proxy_traffic`` with size-capped
bodies. The tsvector ``fts_doc`` column is generated; the search router
(``traffic.py``) queries it.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

from fastapi import APIRouter, Header, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi import Depends

from ..db.base import get_session
from ..db.models import EngagementIngestToken, ProxyTraffic

router = APIRouter(prefix="/ingest/extension", tags=["ingest"])

REQUEST_BODY_CAP = 256 * 1024
RESPONSE_BODY_CAP = 1024 * 1024


def _hash_token(t: str) -> str:
    return hashlib.sha256(t.encode()).hexdigest()


def _truncate(body: str | None, cap: int) -> tuple[str | None, bool]:
    if body is None:
        return None, False
    if len(body) <= cap:
        return body, False
    return body[:cap], True


class FlowIn(BaseModel):
    method: str
    url: str
    request_headers: dict[str, str] | None = None
    request_body: str | None = None
    response_status: int | None = None
    response_headers: dict[str, str] | None = None
    response_body: str | None = None
    response_size: int | None = None
    duration_ms: int | None = None
    captured_at: datetime | None = None
    tab_id: int | None = None
    frame_id: int | None = None
    initiator: str | None = None
    body_capture: str = "full"  # full | limited
    ws_frames: list[dict[str, Any]] | None = None


class IngestBatch(BaseModel):
    flows: list[FlowIn] = Field(default_factory=list)


class IngestBatchOut(BaseModel):
    accepted: int
    rejected: int


async def _resolve_token(
    authorization: str | None, session: AsyncSession
) -> EngagementIngestToken:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "missing bearer token")
    raw = authorization[7:].strip()
    row = (await session.execute(
        select(EngagementIngestToken).where(
            EngagementIngestToken.token_hash == _hash_token(raw),
            EngagementIngestToken.revoked_at.is_(None),
        )
    )).scalar_one_or_none()
    if row is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid token")
    return row


@router.post("/batch", response_model=IngestBatchOut)
async def ingest_batch(
    body: IngestBatch,
    authorization: str | None = Header(default=None),
    session: AsyncSession = Depends(get_session),
) -> IngestBatchOut:
    token = await _resolve_token(authorization, session)
    accepted = 0
    rejected = 0
    now = datetime.now(timezone.utc)

    for flow in body.flows:
        try:
            parsed = urlparse(flow.url)
            host = parsed.hostname or ""
            path = parsed.path or "/"
            query = dict([
                tuple(q.split("=", 1)) if "=" in q else (q, "")
                for q in (parsed.query or "").split("&") if q
            ])
            req_body, req_trunc = _truncate(flow.request_body, REQUEST_BODY_CAP)
            res_body, res_trunc = _truncate(flow.response_body, RESPONSE_BODY_CAP)
            session.add(ProxyTraffic(
                engagement_id=token.engagement_id,
                workspace_id=token.workspace_id,
                source="extension",
                method=flow.method.upper()[:16],
                url=flow.url,
                host=host[:512],
                path=path,
                query=query or None,
                request_headers=flow.request_headers,
                request_body=req_body,
                request_body_truncated=req_trunc,
                response_status=flow.response_status,
                response_headers=flow.response_headers,
                response_body=res_body,
                response_body_truncated=res_trunc,
                response_size=flow.response_size,
                duration_ms=flow.duration_ms,
                captured_at=flow.captured_at or now,
                tab_id=flow.tab_id,
                frame_id=flow.frame_id,
                initiator=flow.initiator,
                body_capture=flow.body_capture,
                ws_frames=flow.ws_frames,
            ))
            accepted += 1
        except Exception:
            rejected += 1

    token.last_used_at = now
    await session.commit()
    return IngestBatchOut(accepted=accepted, rejected=rejected)
