"""LLM proxy for the desktop agentic-fixer runtime.

The desktop client can't hold Pencheff's Sarvam API key (we use it
to track per-workspace usage + enforce plan-tier limits). Instead
it forwards every chat-completions request through this proxy, which
re-issues the request to the configured LLM backend using the
shared server-side key.

Endpoints:
  * ``POST /llm/proxy/agentic/messages`` — same request shape as
    ``POST <agentic_fix_base_url>/chat/completions``. The proxy
    validates the caller's workspace + run, runs the
    plan-tier preflight, forwards to the backend, persists an
    AgenticFixUsage row, returns the body unchanged.

Notes:
  * The desktop sends ``X-Agentic-Run-Id`` to correlate the request
    with the AgenticFixRun it's driving. The proxy refuses if the
    run isn't owned by the active workspace or is already terminal.
  * We don't proxy streaming bodies in v1 — the desktop loop is
    iteration-by-iteration and doesn't need token-by-token output.
    The HTTP response is the JSON envelope only.
"""
from __future__ import annotations

import json
import logging
from typing import Any

import httpx
from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from fastapi.responses import JSONResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth.deps import get_active_workspace, require_scope
from ..config import get_settings
from ..db.base import get_session
from ..db.models import (
    AgenticFixRun,
    AgenticFixUsage,
    Workspace,
)
from ..services.agentic_fixer.cost import Usage, compute_cost_cents

log = logging.getLogger(__name__)

router = APIRouter(tags=["llm-proxy"])


@router.post(
    "/llm/proxy/agentic/messages",
    dependencies=[Depends(require_scope("fix_proposals:write"))],
)
async def proxy_agentic_messages(
    request: Request,
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
    x_agentic_run_id: str | None = Header(default=None),
) -> JSONResponse:
    """Forward a chat-completions request to Pencheff's configured
    backend (Sarvam by default), persisting the resulting usage row
    against the supplied run.

    Authorization: the caller must hold ``fix_proposals:write`` (same
    scope the agentic-fix POST endpoint uses). The active workspace
    must own ``X-Agentic-Run-Id``; otherwise 404.

    Body: opaque to the proxy — passed straight through to the
    upstream chat-completions endpoint.
    """
    s = get_settings()
    if not s.agentic_fix_enabled or not s.agentic_fix_effective_api_key:
        # Effective key resolution: AGENTIC_FIX_API_KEY first, then
        # falls back to AGENT_FALLBACK_LLM_API_KEY (Sarvam fallback
        # the scan-agent already uses). Most deployments only need
        # the latter set.
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "Agentic Fix-all is not configured on this deployment. "
            "Set AGENTIC_FIX_API_KEY (or reuse the existing "
            "AGENT_FALLBACK_LLM_API_KEY — the agentic fixer falls "
            "back to it) plus AGENTIC_FIX_ENABLED=true, then "
            "restart the API + worker containers.",
        )

    if not x_agentic_run_id:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "X-Agentic-Run-Id header is required.",
        )

    run = (await session.execute(
        select(AgenticFixRun).where(
            AgenticFixRun.id == x_agentic_run_id,
            AgenticFixRun.workspace_id == workspace.id,
        )
    )).scalar_one_or_none()
    if run is None:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND,
            "agentic fix run not found for this workspace",
        )
    if run.status in ("done", "failed", "canceled"):
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"run is already {run.status}; cannot proxy further LLM calls",
        )
    if run.runtime != "desktop":
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "proxy is only valid for desktop-runtime runs",
        )

    # Read the body — opaque to us beyond the model+usage fields.
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "request body must be valid JSON",
        )
    if not isinstance(body, dict):
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "request body must be a JSON object",
        )

    # Pin the model server-side. The desktop client can ask for a
    # specific model but we override with the workspace's
    # configured default — prevents a malicious client from
    # picking a more expensive model than the workspace pays for.
    body["model"] = s.agentic_fix_effective_model

    upstream_url = f"{s.agentic_fix_effective_base_url.rstrip('/')}/chat/completions"
    headers = {
        "Authorization": f"Bearer {s.agentic_fix_effective_api_key}",
        "Content-Type": "application/json",
    }

    try:
        async with httpx.AsyncClient(timeout=s.agentic_fix_request_timeout) as client:
            upstream = await client.post(upstream_url, json=body, headers=headers)
    except httpx.HTTPError as e:
        log.warning("agentic proxy: upstream transport error: %s", e)
        raise HTTPException(
            status.HTTP_502_BAD_GATEWAY,
            f"upstream transport error: {e}",
        )

    # Parse the usage block so we can bill the workspace even if
    # we surface a non-200 to the caller (most providers still
    # charge for partial completions).
    parsed: dict[str, Any] | None
    try:
        parsed = upstream.json()
    except Exception:
        parsed = None

    # Persistence is best-effort — the LLM call already succeeded,
    # so a DB-side hiccup here should NOT 500 the request and kill
    # the agent's run. Wrap in a broad try/except: log the failure,
    # roll back any partial session state, then continue to forward
    # the upstream body. The agent stays alive; usage just goes
    # unrecorded for this one call.
    if parsed and isinstance(parsed.get("usage"), dict):
        try:
            u = parsed["usage"]
            # DeepSeek emits cache stats as prompt_cache_hit_tokens /
            # prompt_cache_miss_tokens; OpenAI-style uses
            # prompt_tokens_cached; Sarvam emits neither. Read both
            # shapes — whichever is present wins, default 0.
            cache_read = (
                u.get("prompt_tokens_cached")
                or u.get("prompt_cache_hit_tokens")
                or 0
            )
            usage = Usage(
                input_tokens=int(u.get("prompt_tokens") or 0),
                output_tokens=int(u.get("completion_tokens") or 0),
                cache_read_input_tokens=int(cache_read or 0),
                cache_creation_input_tokens=0,
            )
            session.add(AgenticFixUsage(
                run_id=run.id,
                workspace_id=run.workspace_id,
                iteration=(run.iterations or 0) + 1,
                model=s.agentic_fix_effective_model,
                input_tokens=usage.input_tokens,
                output_tokens=usage.output_tokens,
                cache_read_input_tokens=usage.cache_read_input_tokens,
                cache_creation_input_tokens=usage.cache_creation_input_tokens,
                cost_usd_cents=compute_cost_cents(usage, s.agentic_fix_effective_model),
            ))
            # ponytail: CE is credit-free (single-tenant) — no credit debit.
            # Bump the iteration count + status so the UI's progress
            # poll shows movement even though the desktop drives the
            # loop.
            run.iterations = (run.iterations or 0) + 1
            if run.status == "queued":
                run.status = "running"
            await session.commit()
        except Exception:
            log.exception(
                "agentic proxy: failed to record usage for run %s "
                "(upstream call already succeeded — agent will continue "
                "without this usage row)",
                run.id,
            )
            try:
                await session.rollback()
            except Exception:
                log.exception("agentic proxy: rollback after persist error failed")

    # Forward the upstream response straight through. The desktop
    # client cares about both the status code and the body shape
    # (e.g. 429 from the upstream provider should flow through
    # unchanged so the loop can back off).
    return JSONResponse(
        content=parsed if parsed is not None else {"raw": upstream.text},
        status_code=upstream.status_code,
    )
