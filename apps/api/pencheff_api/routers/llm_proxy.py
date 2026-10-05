# SPDX-License-Identifier: AGPL-3.0-or-later
"""Hosted LLM-guardrail proxy.

User registers an LLM target (already supported), configures
guardrails on it (Phase 1 of this surface), and then points their
application at:

    POST {pencheff-base-url}/api/proxy/{target_id}/v1/chat/completions
    Authorization: Bearer <PENCHEFF_API_KEY>

The proxy:

1. Resolves the inbound ``Authorization`` to a Pencheff API key →
   workspace.
2. Confirms the target belongs to that workspace and is ``kind="llm"``.
3. Loads the target's ``llm_config["guardrails"]`` (or defaults).
4. Runs prompt-side detectors on the merged user/system/tool content;
   blocks with ``403 sentry_blocked`` on a violation.
5. Forwards the request to the target's stored upstream endpoint
   using the target's stored credentials (decrypted with the
   workspace Fernet key).
6. Runs response-side detectors on the assistant text; blocks with
   ``403 sentry_blocked_response`` when the model returned PII /
   unsafe HTML / exceeds the token ceiling.
7. Forwards the upstream response verbatim otherwise.

Same OWASP-LLM-Top-10 taxonomy as the offline scanner. Reuses the
``pencheff_sentry.core`` detector library — no duplicated regex.

The route lives under the existing ``require_scope("scans:write")``
since we treat the proxy as "actively running a guardrail engagement"
on the user's behalf — same scope an interactive scan needs.

Streaming SSE responses are forwarded verbatim today — the response-
side detector chain runs only when the upstream returns a parseable
JSON chat-completion payload (the buffered, non-streaming path).
Streaming-mode evaluation is on the v0.8 roadmap.
"""
from __future__ import annotations

import json
import logging
import time
from typing import Any

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth.deps import get_active_workspace, require_scope
from ..db.base import get_session
from ..db.models import Target, Workspace
from ..services.credentials import decrypt_credentials
from ..services.agent_firewall import firewall_enabled, gate_response_tool_calls
from ..services.guardrails import (
    evaluate_prompt_with_config,
    evaluate_response_with_config,
)
from ..services.tracing import schedule_request_trace

log = logging.getLogger(__name__)

router = APIRouter(prefix="/proxy", tags=["llm-proxy"])


def _extract_prompt(messages: list[dict[str, Any]]) -> str:
    """Concatenate the prompt-side text from a chat-completions body."""
    parts: list[str] = []
    for m in messages or []:
        role = m.get("role", "")
        if role in {"system", "user", "tool"}:
            content = m.get("content")
            if isinstance(content, str):
                parts.append(content)
            elif isinstance(content, list):
                for p in content:
                    if isinstance(p, dict) and p.get("type") == "text":
                        parts.append(str(p.get("text") or ""))
    return "\n".join(parts)


def _extract_response_text(payload: dict[str, Any]) -> str:
    parts: list[str] = []
    for choice in payload.get("choices") or []:
        msg = (choice or {}).get("message") or {}
        content = msg.get("content")
        if isinstance(content, str):
            parts.append(content)
        elif isinstance(content, list):
            for p in content:
                if isinstance(p, dict) and p.get("type") == "text":
                    parts.append(str(p.get("text") or ""))
    return "\n".join(parts)


def _output_tokens(payload: dict[str, Any]) -> int | None:
    usage = payload.get("usage") or {}
    val = usage.get("completion_tokens") or usage.get("output_tokens")
    try:
        return int(val) if val is not None else None
    except (TypeError, ValueError):
        return None


def _upstream_auth_header(creds: dict[str, Any] | None) -> dict[str, str]:
    """Build the auth header to forward to the upstream provider.

    Targets register one of:
      * ``token`` — sent as ``Authorization: Bearer <token>``
      * ``api_key`` — sent as ``X-Api-Key: <key>`` for providers that
        prefer that shape (Cobalt-style)
      * ``headers`` — verbatim dict the user supplied at target-creation
        time, takes precedence
    """
    creds = creds or {}
    headers: dict[str, str] = {}
    extra = creds.get("headers")
    if isinstance(extra, dict):
        for k, v in extra.items():
            if isinstance(v, str):
                headers[k] = v
        if headers:
            return headers
    if creds.get("token"):
        headers["Authorization"] = f"Bearer {creds['token']}"
    elif creds.get("api_key"):
        headers["X-Api-Key"] = str(creds["api_key"])
    return headers


def _block_response(*, side: str, decision: dict[str, Any]) -> Response:
    """Render a uniform 403 body when a guardrail trips."""
    code = "sentry_blocked" if side == "prompt" else "sentry_blocked_response"
    body = json.dumps({
        "error": {
            "message": f"Pencheff Sentry blocked: {decision['reason']}",
            "type": "guardrail_block",
            "code": code,
            "pencheff_sentry": {
                "category": decision["category"],
                "detector": decision["detector"],
                "side": side,
            },
        },
    })
    return Response(content=body, status_code=403, media_type="application/json")


# ─── The proxy route ───────────────────────────────────────────────


@router.post(
    "/{target_id}/v1/chat/completions",
    dependencies=[Depends(require_scope("scans:write"))],
)
async def chat_completions_proxy(
    target_id: str,
    request: Request,
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> Response:
    target = await session.get(Target, target_id)
    if target is None or target.workspace_id != workspace.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "target not found")
    if target.kind != "llm":
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            f"proxy is only available for LLM targets (this target is kind={target.kind!r}).",
        )

    try:
        body = await request.json()
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, f"invalid JSON body: {exc}",
        )

    guardrails = (target.llm_config or {}).get("guardrails") or {}
    messages = body.get("messages") or []
    prompt_text = _extract_prompt(messages)

    # Tracing: best-effort, never breaks the request. Each runtime outcome
    # records a small trace (root request span + an llm / block child).
    t0 = time.monotonic()
    model = body.get("model") if isinstance(body, dict) else None

    def _elapsed_ms() -> int:
        return int((time.monotonic() - t0) * 1000)

    # ── Prompt-side gate ────────────────────────────────────────
    decision = evaluate_prompt_with_config(prompt_text, guardrails=guardrails)
    if decision is not None:
        schedule_request_trace(
            workspace_id=workspace.id, target_id=target_id,
            duration_ms=_elapsed_ms(), status="blocked", model=model,
            block_attrs={"kind": "detector", "side": "prompt", **decision},
        )
        return _block_response(side="prompt", decision=decision)

    # ── Forward to upstream ─────────────────────────────────────
    upstream_url = (target.llm_config or {}).get("endpoint") or target.base_url
    if not upstream_url:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "target is missing an upstream URL (set ``base_url`` or ``llm_config.endpoint``).",
        )
    creds = decrypt_credentials(target.credentials_encrypted) or {}
    forward_headers = {"Content-Type": "application/json"}
    forward_headers.update(_upstream_auth_header(creds))

    # Some providers want the path appended; others have it baked into
    # ``base_url`` already. We append ``/v1/chat/completions`` only
    # when the configured URL doesn't already point at one.
    if "chat/completions" not in upstream_url:
        upstream_url = upstream_url.rstrip("/") + "/v1/chat/completions"

    async with httpx.AsyncClient(timeout=60.0) as c:
        try:
            upstream = await c.post(upstream_url, json=body, headers=forward_headers)
        except httpx.HTTPError as exc:
            log.warning("llm proxy upstream error for target %s: %s", target_id, exc)
            return Response(
                content=json.dumps({
                    "error": {
                        "message": f"Pencheff proxy: upstream unreachable ({type(exc).__name__})",
                        "type": "upstream_error",
                    },
                }),
                status_code=502,
                media_type="application/json",
            )

    if upstream.status_code >= 400:
        # Forward upstream error verbatim so the user sees the real cause.
        return Response(
            content=upstream.content,
            status_code=upstream.status_code,
            media_type=upstream.headers.get("content-type", "application/json"),
        )

    # Streaming responses (text/event-stream) bypass response-side
    # evaluation today — see module docstring.
    content_type = upstream.headers.get("content-type") or ""
    if "event-stream" in content_type:
        return Response(
            content=upstream.content,
            status_code=upstream.status_code,
            media_type=content_type,
        )

    try:
        payload = upstream.json()
    except json.JSONDecodeError:
        return Response(
            content=upstream.content,
            status_code=upstream.status_code,
            media_type=content_type or "application/json",
        )

    response_text = _extract_response_text(payload)
    decision = evaluate_response_with_config(
        prompt_text, response_text,
        guardrails=guardrails,
        output_tokens=_output_tokens(payload),
    )
    if decision is not None:
        schedule_request_trace(
            workspace_id=workspace.id, target_id=target_id,
            duration_ms=_elapsed_ms(), status="blocked", model=model,
            block_attrs={"kind": "detector", "side": "response", **decision},
        )
        return _block_response(side="response", decision=decision)

    # ── Agent-firewall: gate the model's tool calls (response side) ──
    # Default-off per target. Refuses a dangerous/approval-gated tool call
    # so the app never receives it; masks credential-shaped args in place.
    # Same buffered-only limitation as the response detectors above —
    # streaming returned earlier. See ``services.agent_firewall``.
    firewall_cfg = (target.llm_config or {}).get("firewall") or {}
    if firewall_enabled(firewall_cfg):
        fw_decision = gate_response_tool_calls(payload, firewall_cfg=firewall_cfg)
        if fw_decision is not None:
            schedule_request_trace(
                workspace_id=workspace.id, target_id=target_id,
                duration_ms=_elapsed_ms(), status="blocked", model=model,
                block_attrs={"kind": "firewall", **fw_decision},
            )
            return _block_response(side="response", decision=fw_decision)

    usage = payload.get("usage") or {}
    schedule_request_trace(
        workspace_id=workspace.id, target_id=target_id,
        duration_ms=_elapsed_ms(), status="ok", model=model,
        llm_attrs={
            "prompt_tokens": usage.get("prompt_tokens"),
            "completion_tokens": _output_tokens(payload),
        },
    )
    return Response(
        content=json.dumps(payload),
        status_code=upstream.status_code,
        media_type="application/json",
    )
