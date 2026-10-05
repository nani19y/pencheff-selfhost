# SPDX-License-Identifier: AGPL-3.0-or-later
"""Runtime-protection trace ingest + read API.

* ``POST /v1/traces``        — SDK ingest: store a submitted span tree.
* ``GET  /traces``           — list recent traces in the workspace.
* ``GET  /traces/{trace_id}``— all spans in one trace (the viewer's detail).

Spans from the hosted gateway are written directly by ``services.tracing``;
this router is the SDK-facing ingest plus the read side the web viewer uses.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth.deps import get_active_workspace, require_scope
from ..db.base import get_session
from ..db.models import RuntimeSpan, Workspace
from ..services.tracing import normalize_ingested_spans, persist_ingested_spans

router = APIRouter(tags=["traces"])


# ─── shapes ─────────────────────────────────────────────────────────


class IngestAck(BaseModel):
    trace_id: str
    ingested: int


class SpanOut(BaseModel):
    span_id: str
    trace_id: str
    parent_span_id: str | None
    name: str
    kind: str
    status: str
    source: str
    target_id: str | None
    start_time: datetime
    end_time: datetime | None
    duration_ms: int | None
    attributes: dict[str, Any] | None


class TraceSummary(BaseModel):
    trace_id: str
    name: str
    kind: str
    status: str
    source: str
    target_id: str | None
    started_at: datetime
    duration_ms: int | None
    span_count: int
    model: str | None = None


class TraceDetail(BaseModel):
    trace_id: str
    spans: list[SpanOut]


def _span_out(s: RuntimeSpan) -> SpanOut:
    return SpanOut(
        span_id=s.id, trace_id=s.trace_id, parent_span_id=s.parent_span_id,
        name=s.name, kind=s.kind, status=s.status, source=s.source,
        target_id=s.target_id, start_time=s.start_time, end_time=s.end_time,
        duration_ms=s.duration_ms, attributes=s.attributes,
    )


# ─── ingest (SDK) ───────────────────────────────────────────────────


@router.post(
    "/v1/traces",
    response_model=IngestAck,
    dependencies=[Depends(require_scope("proxy:write"))],
)
async def ingest_traces(
    body: dict[str, Any],
    workspace: Workspace = Depends(get_active_workspace),
) -> IngestAck:
    try:
        spans = normalize_ingested_spans(body, workspace_id=workspace.id)
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc))
    written = await persist_ingested_spans(spans)
    return IngestAck(trace_id=spans[0]["trace_id"], ingested=written)


# ─── read (viewer) ──────────────────────────────────────────────────


@router.get(
    "/traces",
    response_model=list[TraceSummary],
    dependencies=[Depends(require_scope("proxy:read"))],
)
async def list_traces(
    limit: int = 50,
    target_id: str | None = None,
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> list[TraceSummary]:
    limit = max(1, min(limit, 200))
    # Each trace is represented by its root span (parent_span_id IS NULL).
    q = (
        select(RuntimeSpan)
        .where(RuntimeSpan.workspace_id == workspace.id)
        .where(RuntimeSpan.parent_span_id.is_(None))
    )
    if target_id:
        q = q.where(RuntimeSpan.target_id == target_id)
    roots = (
        await session.execute(
            q.order_by(RuntimeSpan.created_at.desc()).limit(limit)
        )
    ).scalars().all()
    if not roots:
        return []
    trace_ids = [r.trace_id for r in roots]
    count_rows = (
        await session.execute(
            select(RuntimeSpan.trace_id, func.count())
            .where(RuntimeSpan.workspace_id == workspace.id)
            .where(RuntimeSpan.trace_id.in_(trace_ids))
            .group_by(RuntimeSpan.trace_id)
        )
    ).all()
    counts = {tid: n for tid, n in count_rows}
    out: list[TraceSummary] = []
    for r in roots:
        attrs = r.attributes or {}
        out.append(TraceSummary(
            trace_id=r.trace_id, name=r.name, kind=r.kind, status=r.status,
            source=r.source, target_id=r.target_id, started_at=r.start_time,
            duration_ms=r.duration_ms, span_count=counts.get(r.trace_id, 1),
            model=attrs.get("model") if isinstance(attrs, dict) else None,
        ))
    return out


@router.get(
    "/traces/{trace_id}",
    response_model=TraceDetail,
    dependencies=[Depends(require_scope("proxy:read"))],
)
async def get_trace(
    trace_id: str,
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> TraceDetail:
    spans = (
        await session.execute(
            select(RuntimeSpan)
            .where(RuntimeSpan.workspace_id == workspace.id)
            .where(RuntimeSpan.trace_id == trace_id)
            .order_by(RuntimeSpan.start_time.asc())
        )
    ).scalars().all()
    if not spans:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "trace not found")
    return TraceDetail(trace_id=trace_id, spans=[_span_out(s) for s in spans])
