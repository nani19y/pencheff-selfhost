"""Read endpoints powering the /observability/* web UI pages.

Five surfaces:

* ``GET /scans/{scan_id}/trace`` — nested span tree for the trace
  waterfall viewer.
* ``GET /observability/slo`` — RED + USE summary cards.
* ``GET /observability/audit`` — paginated audit-log table.
* ``GET /observability/audit/verify`` — hash-chain integrity check.
* ``GET /observability/cost`` — LLM token spend grouped by model.

All endpoints short-circuit with 503 when ``observability_enabled``
is False, so vanilla deployments don't expose stub UIs.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth.deps import get_current_user
from ..config import get_settings
from ..db.base import get_session
from ..db.models import User
from ..middleware.audit import verify_chain

router = APIRouter(prefix="/observability", tags=["observability"])


def _require_enabled() -> None:
    settings = get_settings()
    if not settings.observability_enabled:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Observability is disabled. Set PENCHEFF_OBSERVABILITY_ENABLED=true to enable.",
        )


# --------------------------------------------------------------------- #
# Trace waterfall
# --------------------------------------------------------------------- #


@router.get("/scans/{scan_id}/trace")
async def scan_trace(
    scan_id: str,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(get_current_user),
) -> dict[str, Any]:
    _require_enabled()

    rows = (
        await session.execute(
            text(
                """
                SELECT
                    started_at, ended_at, duration_ns,
                    encode(trace_id, 'hex')        AS trace_id,
                    encode(span_id, 'hex')         AS span_id,
                    encode(parent_span_id, 'hex')  AS parent_span_id,
                    name, kind, status_code, status_message,
                    service_name, scope_name,
                    attributes, resource
                FROM otel_spans
                WHERE scan_id = :scan_id
                ORDER BY started_at ASC
                """
            ),
            {"scan_id": scan_id},
        )
    ).mappings().all()

    if not rows:
        return {"scan_id": scan_id, "spans": [], "tree": []}

    flat = [dict(r) for r in rows]

    # Convert to nested tree by parent_span_id. Multiple roots are
    # possible (e.g. when a Celery task runs without an upstream
    # context), so the result is a list of roots.
    by_id: dict[str, dict[str, Any]] = {row["span_id"]: {**row, "children": []} for row in flat}
    roots: list[dict[str, Any]] = []
    for row in flat:
        parent = row["parent_span_id"]
        if parent and parent in by_id:
            by_id[parent]["children"].append(by_id[row["span_id"]])
        else:
            roots.append(by_id[row["span_id"]])

    return {"scan_id": scan_id, "span_count": len(flat), "tree": roots}


# --------------------------------------------------------------------- #
# SLO dashboard
# --------------------------------------------------------------------- #


@router.get("/slo")
async def slo_summary(
    window_minutes: int = Query(60, ge=5, le=1440),
    session: AsyncSession = Depends(get_session),
    user: User = Depends(get_current_user),
) -> dict[str, Any]:
    _require_enabled()

    cutoff = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)

    # RED: requests, errors, duration. Uses HTTP server spans (kind=1)
    # which cover every FastAPI request via FastAPIInstrumentor.
    red = (
        await session.execute(
            text(
                """
                SELECT
                    count(*)                                                AS req_total,
                    count(*) FILTER (WHERE status_code = 2)                 AS req_error,
                    percentile_cont(0.50) WITHIN GROUP (
                        ORDER BY duration_ns
                    ) / 1e6                                                  AS p50_ms,
                    percentile_cont(0.95) WITHIN GROUP (
                        ORDER BY duration_ns
                    ) / 1e6                                                  AS p95_ms,
                    percentile_cont(0.99) WITHIN GROUP (
                        ORDER BY duration_ns
                    ) / 1e6                                                  AS p99_ms
                FROM otel_spans
                WHERE kind = 1
                  AND started_at >= :cutoff
                """
            ),
            {"cutoff": cutoff},
        )
    ).mappings().one()

    # Active scans + queue depth from a recent point-in-time read.
    scan_status = (
        await session.execute(
            text(
                """
                SELECT
                    count(*) FILTER (WHERE status = 'running')   AS active,
                    count(*) FILTER (WHERE status = 'queued')    AS queued
                FROM scans
                WHERE created_at >= NOW() - INTERVAL '24 hours'
                """
            )
        )
    ).mappings().one()

    return {
        "window_minutes": window_minutes,
        "request_count": int(red["req_total"] or 0),
        "error_count": int(red["req_error"] or 0),
        "error_rate": (
            float(red["req_error"]) / float(red["req_total"])
            if red["req_total"]
            else 0.0
        ),
        "p50_ms": float(red["p50_ms"] or 0.0),
        "p95_ms": float(red["p95_ms"] or 0.0),
        "p99_ms": float(red["p99_ms"] or 0.0),
        "active_scans": int(scan_status["active"] or 0),
        "queued_scans": int(scan_status["queued"] or 0),
    }


# --------------------------------------------------------------------- #
# Audit log browser
# --------------------------------------------------------------------- #


@router.get("/audit")
async def audit_list(
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    actor: str | None = None,
    action_prefix: str | None = None,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(get_current_user),
) -> dict[str, Any]:
    _require_enabled()

    where = ["true"]
    params: dict[str, Any] = {"limit": limit, "offset": offset}
    if actor:
        where.append("user_id::text = :actor")
        params["actor"] = actor
    if action_prefix:
        where.append("action ILIKE :action_prefix")
        params["action_prefix"] = action_prefix + "%"

    rows = (
        await session.execute(
            text(
                f"""
                SELECT
                    id, user_id, org_id, workspace_id, action,
                    entity_type, entity_id, meta, created_at,
                    encode(trace_id, 'hex')   AS trace_id,
                    request_ip, user_agent,
                    (row_hash IS NOT NULL)    AS hashed
                FROM audit_logs
                WHERE {' AND '.join(where)}
                ORDER BY created_at DESC
                LIMIT :limit OFFSET :offset
                """
            ),
            params,
        )
    ).mappings().all()

    return {
        "items": [dict(r) for r in rows],
        "limit": limit,
        "offset": offset,
    }


@router.get("/audit/verify")
async def audit_verify(
    limit: int = Query(10000, ge=1, le=100000),
    session: AsyncSession = Depends(get_session),
    user: User = Depends(get_current_user),
) -> dict[str, Any]:
    _require_enabled()
    return await verify_chain(session, limit=limit)


# --------------------------------------------------------------------- #
# Cost dashboard
# --------------------------------------------------------------------- #


@router.get("/cost")
async def llm_cost(
    window_hours: int = Query(168, ge=1, le=720),
    session: AsyncSession = Depends(get_session),
    user: User = Depends(get_current_user),
) -> dict[str, Any]:
    _require_enabled()

    cutoff = datetime.now(timezone.utc) - timedelta(hours=window_hours)

    rows = (
        await session.execute(
            text(
                """
                SELECT
                    attributes->>'gen_ai.request.model'        AS model,
                    sum(
                        coalesce(
                            (attributes->>'gen_ai.usage.input_tokens')::bigint, 0
                        )
                    ) AS input_tokens,
                    sum(
                        coalesce(
                            (attributes->>'gen_ai.usage.output_tokens')::bigint, 0
                        )
                    ) AS output_tokens,
                    count(*) AS calls
                FROM otel_spans
                WHERE name = 'gen_ai.completion'
                  AND started_at >= :cutoff
                GROUP BY 1
                ORDER BY 4 DESC
                """
            ),
            {"cutoff": cutoff},
        )
    ).mappings().all()

    return {
        "window_hours": window_hours,
        "by_model": [dict(r) for r in rows],
    }
