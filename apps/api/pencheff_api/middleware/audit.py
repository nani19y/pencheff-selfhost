"""Tamper-evident audit middleware.

Fires on every mutating request (POST / PUT / PATCH / DELETE) AFTER
the route handler runs, so ``request.state`` has been populated by
the auth dependency (see ``auth/deps.py:203``). Each row carries a
sha256 hash chain — ``row_hash = sha256(prev_hash || canonical_json(row))``
— so any after-the-fact modification of a historical row breaks every
subsequent hash and the verifier endpoint surfaces the tamper.

A Postgres advisory transaction lock (``pg_advisory_xact_lock``)
serialises concurrent inserts so two parallel mutations don't both
read the same ``prev_hash`` and produce a forked chain.

No-op when ``settings.observability_enabled`` is False — vanilla
deployments pay zero overhead.
"""
from __future__ import annotations

import hashlib
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import Request, Response
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

log = logging.getLogger("pencheff.audit")

# A stable 64-bit lock key for ``pg_advisory_xact_lock``. The literal
# value is arbitrary; what matters is that every audit-write call
# uses the SAME key so the lock actually serialises.
_AUDIT_LOCK_KEY = 7639824510102026

_MUTATING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

# Path prefixes the audit middleware should NOT log. Health checks and
# the OTLP receivers themselves shouldn't fill the audit table.
_SKIP_PATH_PREFIXES = (
    "/health",
    "/v1/traces",
    "/v1/logs",
    "/v1/metrics",
)


class AuditMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: ASGIApp):
        super().__init__(app)
        self._engine = None
        self._session_factory = None

    async def _get_session(self):
        if self._session_factory is None:
            from ..config import get_settings
            settings = get_settings()
            self._engine = create_async_engine(settings.database_url)
            self._session_factory = async_sessionmaker(
                self._engine, expire_on_commit=False
            )
        return self._session_factory()

    async def dispatch(self, request: Request, call_next):
        from ..config import get_settings

        settings = get_settings()
        if not settings.observability_enabled:
            return await call_next(request)

        if request.method not in _MUTATING_METHODS:
            return await call_next(request)
        if any(request.url.path.startswith(p) for p in _SKIP_PATH_PREFIXES):
            return await call_next(request)

        # Run the route first so ``request.state`` is populated by the
        # auth dependency. We accept that an audit row only lands for
        # successful auth + handler completion — failed auth requests
        # don't carry an actor, and FastAPI returns before our state
        # is meaningful.
        response = await call_next(request)

        # Best-effort write. Audit failure must NEVER fail the request.
        try:
            await self._write_audit(request, response)
        except Exception as exc:  # noqa: BLE001
            log.warning("audit row write failed: %s", exc)

        return response

    async def _write_audit(self, request: Request, response: Response) -> None:
        actor = _extract_actor(request)
        if actor.get("user_id") is None and actor.get("api_key_id") is None:
            # Unauthed mutation (or auth failed before request.state was
            # populated). Skip — nothing meaningful to audit.
            return

        trace_id = _current_trace_id()
        action = f"{request.method} {request.url.path}"
        request_ip = _request_ip(request)
        user_agent = (request.headers.get("user-agent") or "")[:1024]

        async with await self._get_session() as session:
            await session.execute(
                text("SELECT pg_advisory_xact_lock(:k)"),
                {"k": _AUDIT_LOCK_KEY},
            )
            prev_hash = await _previous_hash(session)

            row_id = str(uuid.uuid4())
            ts = datetime.now(timezone.utc)

            row_payload = {
                "id": row_id,
                "user_id": actor.get("user_id"),
                "org_id": actor.get("org_id"),
                "workspace_id": actor.get("workspace_id"),
                "action": action,
                "entity_type": None,
                "entity_id": None,
                "meta": {
                    "status_code": response.status_code,
                    "auth_kind": actor.get("auth_kind"),
                    "api_key_id": actor.get("api_key_id"),
                },
                "trace_id": trace_id.hex() if trace_id else None,
                "request_ip": request_ip,
                "user_agent": user_agent,
                "request_body_diff": None,
                "created_at": ts.isoformat(),
            }
            row_hash = _compute_hash(prev_hash, row_payload)

            await session.execute(
                text(
                    """
                    INSERT INTO audit_logs (
                        id, user_id, org_id, workspace_id, action,
                        entity_type, entity_id, meta, created_at,
                        prev_hash, row_hash, trace_id,
                        request_ip, user_agent, request_body_diff
                    ) VALUES (
                        :id, :user_id, :org_id, :workspace_id, :action,
                        :entity_type, :entity_id, :meta::jsonb, :created_at,
                        :prev_hash, :row_hash, :trace_id,
                        :request_ip, :user_agent, :request_body_diff
                    )
                    """
                ),
                {
                    "id": row_id,
                    "user_id": actor.get("user_id"),
                    "org_id": actor.get("org_id"),
                    "workspace_id": actor.get("workspace_id"),
                    "action": action,
                    "entity_type": None,
                    "entity_id": None,
                    "meta": json.dumps(row_payload["meta"]),
                    "created_at": ts,
                    "prev_hash": prev_hash,
                    "row_hash": row_hash,
                    "trace_id": trace_id,
                    "request_ip": request_ip,
                    "user_agent": user_agent,
                    "request_body_diff": None,
                },
            )
            await session.commit()


# --------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------- #


def _extract_actor(request: Request) -> dict[str, Any]:
    state = request.state
    return {
        "user_id": getattr(state, "user_id", None),
        "org_id": getattr(state, "org_id", None)
        or getattr(state, "api_key_org_id", None),
        "workspace_id": getattr(state, "workspace_id", None)
        or getattr(state, "api_key_workspace_id", None),
        "auth_kind": getattr(state, "auth_kind", None),
        "api_key_id": getattr(state, "api_key_id", None),
    }


def _current_trace_id() -> bytes | None:
    try:
        from opentelemetry import trace
        span = trace.get_current_span()
        ctx = span.get_span_context()
        if ctx.trace_id == 0:
            return None
        return ctx.trace_id.to_bytes(16, "big")
    except Exception:
        return None


def _request_ip(request: Request) -> str | None:
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    client = request.client
    return client.host if client else None


async def _previous_hash(session) -> bytes | None:
    res = await session.execute(
        text(
            "SELECT row_hash FROM audit_logs "
            "WHERE row_hash IS NOT NULL "
            "ORDER BY created_at DESC LIMIT 1"
        )
    )
    row = res.first()
    return row[0] if row else None


def _compute_hash(prev_hash: bytes | None, payload: dict[str, Any]) -> bytes:
    h = hashlib.sha256()
    if prev_hash is not None:
        h.update(prev_hash)
    payload_minus_hash = {k: v for k, v in payload.items() if k != "row_hash"}
    h.update(
        json.dumps(payload_minus_hash, sort_keys=True, default=str).encode("utf-8")
    )
    return h.digest()


async def verify_chain(session, limit: int | None = None) -> dict[str, Any]:
    """Walk the chain start-to-end. Returns ``{ok, checked, broken_at}``.

    ``broken_at`` is the ``audit_logs.id`` of the first row whose
    recomputed hash doesn't match the stored ``row_hash``. ``ok=True``
    means every (non-null) hash matches its predecessor.
    """
    q = (
        "SELECT id, user_id, org_id, workspace_id, action, entity_type, "
        "entity_id, meta, created_at, prev_hash, row_hash, trace_id, "
        "request_ip, user_agent, request_body_diff "
        "FROM audit_logs "
        "WHERE row_hash IS NOT NULL "
        "ORDER BY created_at ASC"
    )
    if limit:
        q += f" LIMIT {int(limit)}"
    rows = (await session.execute(text(q))).mappings().all()

    expected_prev: bytes | None = None
    checked = 0
    for row in rows:
        payload = {
            "id": str(row["id"]),
            "user_id": str(row["user_id"]) if row["user_id"] else None,
            "org_id": str(row["org_id"]) if row["org_id"] else None,
            "workspace_id": (
                str(row["workspace_id"]) if row["workspace_id"] else None
            ),
            "action": row["action"],
            "entity_type": row["entity_type"],
            "entity_id": row["entity_id"],
            "meta": row["meta"],
            "trace_id": (
                row["trace_id"].hex() if row["trace_id"] else None
            ),
            "request_ip": str(row["request_ip"]) if row["request_ip"] else None,
            "user_agent": row["user_agent"],
            "request_body_diff": row["request_body_diff"],
            "created_at": (
                row["created_at"].isoformat() if row["created_at"] else None
            ),
        }
        # The stored ``prev_hash`` should equal what we expect. The
        # stored ``row_hash`` should equal sha256(stored_prev || payload).
        if row["prev_hash"] != expected_prev:
            return {"ok": False, "checked": checked, "broken_at": str(row["id"])}
        recomputed = _compute_hash(row["prev_hash"], payload)
        if recomputed != row["row_hash"]:
            return {"ok": False, "checked": checked, "broken_at": str(row["id"])}
        expected_prev = row["row_hash"]
        checked += 1
    return {"ok": True, "checked": checked, "broken_at": None}
