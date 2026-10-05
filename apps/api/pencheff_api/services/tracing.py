# SPDX-License-Identifier: AGPL-3.0-or-later
"""Runtime-protection tracing — span persistence + SDK-ingest normalization.

Two producers feed ``runtime_spans``:

  * the hosted gateway (``routers.llm_proxy``) — emits a small per-request
    trace (a ``proxy.request`` root + one ``llm.chat`` / block child) via
    :func:`record_request_trace`.
  * the embeddable SDK — POSTs full span trees to ``/v1/traces``; those are
    validated by :func:`normalize_ingested_spans` and stored by
    :func:`persist_ingested_spans`.

Persistence always uses its OWN session (``SessionLocal``) and is strictly
best-effort: a trace-write failure must never break a proxied request.
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from ..db.base import SessionLocal
from ..db.models import RuntimeSpan

log = logging.getLogger("pencheff.tracing")

_VALID_KINDS = {"request", "llm", "tool", "firewall", "detector", "other"}
_VALID_STATUS = {"ok", "blocked", "error"}
_MAX_INGEST_SPANS = 500


def new_trace_id() -> str:
    return uuid4().hex


def _now() -> datetime:
    return datetime.now(timezone.utc)


def build_request_spans(
    *,
    workspace_id: str,
    target_id: str | None,
    duration_ms: int,
    status: str,
    model: str | None = None,
    llm_attrs: dict[str, Any] | None = None,
    block_attrs: dict[str, Any] | None = None,
) -> list[RuntimeSpan]:
    """Build a small gateway trace: a ``proxy.request`` root plus one child —
    an ``llm.chat`` span on success, or a firewall/detector block span when
    ``block_attrs`` is set.

    IDs are generated explicitly: ``RuntimeSpan.id`` has a column default that
    only fires at flush, so ``root.id`` would be ``None`` at construction and
    the child's ``parent_span_id`` would be orphaned. We set both here so the
    parent→child link is correct before persistence.
    """
    end = _now()
    start = end  # request-level wall-clock is carried by duration_ms
    trace_id = new_trace_id()
    root_id = uuid4().hex
    root = RuntimeSpan(
        id=root_id, workspace_id=workspace_id, trace_id=trace_id,
        parent_span_id=None, name="proxy.request", kind="request",
        status=status, source="gateway", target_id=target_id,
        start_time=start, end_time=end, duration_ms=duration_ms,
        attributes={"model": model} if model else {},
    )
    spans = [root]
    if block_attrs:
        kind = block_attrs.get("kind") or "detector"
        spans.append(RuntimeSpan(
            id=uuid4().hex, workspace_id=workspace_id, trace_id=trace_id,
            parent_span_id=root_id, name=f"{kind}.block", kind=kind,
            status="blocked", source="gateway", target_id=target_id,
            start_time=start, end_time=end, duration_ms=duration_ms,
            attributes=block_attrs,
        ))
    elif llm_attrs is not None:
        spans.append(RuntimeSpan(
            id=uuid4().hex, workspace_id=workspace_id, trace_id=trace_id,
            parent_span_id=root_id, name="llm.chat", kind="llm", status="ok",
            source="gateway", target_id=target_id, start_time=start,
            end_time=end, duration_ms=duration_ms,
            attributes={"model": model, **(llm_attrs or {})},
        ))
    return spans


async def _persist_spans(spans: list[RuntimeSpan]) -> None:
    """Persist via an isolated session. Best-effort; never raises."""
    try:
        async with SessionLocal() as db:
            for s in spans:
                db.add(s)
            await db.commit()
    except Exception as exc:  # noqa: BLE001 — tracing must never break a request
        log.warning("span persist failed: %s", exc)


# Keep strong refs to in-flight background tasks so they aren't GC'd before
# they finish (asyncio only holds weak refs to tasks).
_BG_TASKS: set[asyncio.Task] = set()


def schedule_request_trace(
    *,
    workspace_id: str,
    target_id: str | None,
    duration_ms: int,
    status: str,
    model: str | None = None,
    llm_attrs: dict[str, Any] | None = None,
    block_attrs: dict[str, Any] | None = None,
) -> None:
    """Fire-and-forget: build the trace synchronously (cheap) and persist it
    in the background so tracing adds ZERO latency to the proxy response.
    Safe to call from inside the request handler — persistence uses its own
    session, independent of the request lifecycle."""
    spans = build_request_spans(
        workspace_id=workspace_id, target_id=target_id, duration_ms=duration_ms,
        status=status, model=model, llm_attrs=llm_attrs, block_attrs=block_attrs,
    )
    try:
        task = asyncio.get_running_loop().create_task(_persist_spans(spans))
    except RuntimeError:
        return  # no running loop (e.g. unit test) — skip background persist
    _BG_TASKS.add(task)
    task.add_done_callback(_BG_TASKS.discard)


def _parse_ts(value: Any) -> datetime | None:
    if isinstance(value, (int, float)):
        # epoch seconds or millis
        secs = value / 1000.0 if value > 1e12 else float(value)
        return datetime.fromtimestamp(secs, tz=timezone.utc)
    if isinstance(value, str) and value.strip():
        try:
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except ValueError:
            return None
    return None


def normalize_ingested_spans(
    payload: dict[str, Any], *, workspace_id: str,
) -> list[dict[str, Any]]:
    """Validate + coerce an SDK trace-ingest payload into RuntimeSpan kwargs.

    Shape: ``{"trace_id": "...", "spans": [{span_id, parent_span_id, name,
    kind, status, start_time, end_time, duration_ms, attributes}, ...]}``.
    Raises ``ValueError`` on a malformed payload.
    """
    trace_id = str(payload.get("trace_id") or "").strip() or new_trace_id()
    raw_spans = payload.get("spans")
    if not isinstance(raw_spans, list) or not raw_spans:
        raise ValueError("payload must include a non-empty 'spans' list")
    if len(raw_spans) > _MAX_INGEST_SPANS:
        raise ValueError(f"too many spans (max {_MAX_INGEST_SPANS})")

    out: list[dict[str, Any]] = []
    for i, s in enumerate(raw_spans):
        if not isinstance(s, dict):
            raise ValueError(f"span #{i + 1} must be an object")
        name = str(s.get("name") or "").strip()
        if not name:
            raise ValueError(f"span #{i + 1} is missing a name")
        kind = str(s.get("kind") or "other")
        if kind not in _VALID_KINDS:
            kind = "other"
        status = str(s.get("status") or "ok")
        if status not in _VALID_STATUS:
            status = "ok"
        start = _parse_ts(s.get("start_time")) or _now()
        end = _parse_ts(s.get("end_time"))
        duration = s.get("duration_ms")
        try:
            duration = int(duration) if duration is not None else None
        except (TypeError, ValueError):
            duration = None
        if duration is None and end is not None:
            duration = max(0, int((end - start).total_seconds() * 1000))
        attrs = s.get("attributes")
        out.append({
            "id": str(s.get("span_id") or uuid4().hex),
            "workspace_id": workspace_id,
            "trace_id": trace_id,
            "parent_span_id": (str(s["parent_span_id"]) if s.get("parent_span_id") else None),
            "name": name[:128],
            "kind": kind,
            "status": status,
            "source": "sdk",
            "target_id": None,
            "start_time": start,
            "end_time": end,
            "duration_ms": duration,
            "attributes": attrs if isinstance(attrs, dict) else None,
        })
    return out


async def persist_ingested_spans(spans: list[dict[str, Any]]) -> int:
    """Persist normalized SDK spans. Returns the count written. Raises on
    DB error (the ingest endpoint surfaces it as 500)."""
    async with SessionLocal() as db:
        for kw in spans:
            db.add(RuntimeSpan(**kw))
        await db.commit()
    return len(spans)
