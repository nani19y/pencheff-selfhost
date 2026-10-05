# SPDX-License-Identifier: AGPL-3.0-or-later
"""HTTP proxy sidecar — drops between an app and an OpenAI-compatible upstream.

Pattern: the application changes its OpenAI base URL from
``https://api.openai.com/v1`` to ``http://sentry:4242`` and gets the
same chat-completions API back, with the detector chain inline.

Per-request flow:

    client → Sentry  (prompt-side evaluate; BLOCK → 403)
    Sentry → upstream (verbatim forward of the chat body)
    upstream → Sentry (response-side evaluate; BLOCK → 403, PROMPT-replaced)
    Sentry → client (forwarded response, possibly sanitised)

Sentry never persists prompts or responses by default — auditors
asking "did you log my customer's prompt?" get a clean answer. A
``--audit-log path.jsonl`` flag turns on opt-in JSONL logging that
records *only* decisions (verdict, detector, category) plus a hash
of the prompt — never the prompt body itself.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx
from fastapi import FastAPI, HTTPException, Request, Response

from .core import GuardrailConfig, evaluate_prompt, evaluate_response

log = logging.getLogger("pencheff_sentry.proxy")


@dataclass
class ProxySettings:
    upstream: str            # e.g. "https://api.openai.com/v1"
    audit_log: Path | None = None
    config: GuardrailConfig | None = None
    timeout_s: float = 60.0


def _hash_text(text: str) -> str:
    return hashlib.sha256((text or "").encode("utf-8")).hexdigest()[:16]


def _audit(settings: ProxySettings, record: dict[str, Any]) -> None:
    if settings.audit_log is None:
        return
    try:
        settings.audit_log.parent.mkdir(parents=True, exist_ok=True)
        with settings.audit_log.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
    except OSError as exc:
        log.warning("sentry: audit log write failed: %s", exc)


def _extract_prompt(messages: list[dict[str, Any]]) -> str:
    """Concatenate the prompt-side text from a chat-completions body.

    System + user + tool messages are evaluated together — a model can
    be jailbroken via any of those slots.
    """
    parts: list[str] = []
    for m in messages or []:
        role = m.get("role", "")
        if role in {"system", "user", "tool"}:
            content = m.get("content")
            if isinstance(content, str):
                parts.append(content)
            elif isinstance(content, list):
                # OpenAI multi-modal content shape: list[{type, text|image_url}]
                for p in content:
                    if isinstance(p, dict) and p.get("type") == "text":
                        parts.append(str(p.get("text") or ""))
    return "\n".join(parts)


def _extract_response_text(payload: dict[str, Any]) -> str:
    """Pull the assistant-text from an OpenAI chat-completions response."""
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


def build_app(settings: ProxySettings) -> FastAPI:
    """Construct the FastAPI app. Exposed so tests can drive it via
    ``httpx.AsyncClient(app=app)`` without booting a TCP socket."""
    app = FastAPI(title="Pencheff Sentry", version="0.1.0")

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/v1/chat/completions")
    async def chat_completions(request: Request) -> Response:
        try:
            body = await request.json()
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(400, f"invalid JSON body: {exc}")

        messages = body.get("messages") or []
        prompt_text = _extract_prompt(messages)

        decision = evaluate_prompt(prompt_text, config=settings.config)
        if decision.verdict.value == "block":
            _audit(settings, {
                "ts": datetime.now(timezone.utc).isoformat(),
                "side": "prompt",
                "verdict": decision.verdict.value,
                "category": decision.category,
                "detector": decision.detector,
                "reason": decision.reason,
                "prompt_hash": _hash_text(prompt_text),
            })
            return Response(
                content=json.dumps({
                    "error": {
                        "message": f"Pencheff Sentry blocked: {decision.reason}",
                        "type": "guardrail_block",
                        "code": "sentry_blocked",
                        "pencheff_sentry": {
                            "category": decision.category,
                            "detector": decision.detector,
                        },
                    },
                }),
                status_code=403,
                media_type="application/json",
            )

        # Forward to upstream verbatim. Auth header and body pass
        # through untouched — Sentry never strips credentials.
        upstream_url = f"{settings.upstream.rstrip('/')}/chat/completions"
        forward_headers = {
            k: v for k, v in request.headers.items()
            if k.lower() not in {"host", "content-length"}
        }
        async with httpx.AsyncClient(timeout=settings.timeout_s) as c:
            try:
                upstream = await c.post(
                    upstream_url, json=body, headers=forward_headers,
                )
            except httpx.HTTPError as exc:
                raise HTTPException(502, f"upstream error: {exc}") from exc

        if upstream.status_code >= 400:
            return Response(
                content=upstream.content,
                status_code=upstream.status_code,
                media_type=upstream.headers.get("content-type", "application/json"),
            )

        # Response-side evaluation. We only apply when the body is
        # JSON we can parse as chat-completions; streaming responses
        # are forwarded as-is (Phase 3.1 stretch goal: streaming-mode
        # SSE evaluation).
        try:
            payload = upstream.json()
        except json.JSONDecodeError:
            return Response(
                content=upstream.content,
                status_code=upstream.status_code,
                media_type=upstream.headers.get("content-type"),
            )

        response_text = _extract_response_text(payload)
        decision = evaluate_response(
            prompt_text, response_text,
            config=settings.config,
            output_tokens=_output_tokens(payload),
        )
        if decision.verdict.value == "block":
            _audit(settings, {
                "ts": datetime.now(timezone.utc).isoformat(),
                "side": "response",
                "verdict": decision.verdict.value,
                "category": decision.category,
                "detector": decision.detector,
                "reason": decision.reason,
                "prompt_hash": _hash_text(prompt_text),
                "response_hash": _hash_text(response_text),
            })
            return Response(
                content=json.dumps({
                    "error": {
                        "message": f"Pencheff Sentry blocked response: {decision.reason}",
                        "type": "guardrail_block",
                        "code": "sentry_blocked_response",
                        "pencheff_sentry": {
                            "category": decision.category,
                            "detector": decision.detector,
                        },
                    },
                }),
                status_code=403,
                media_type="application/json",
            )

        # Allowed — forward upstream payload verbatim.
        return Response(
            content=json.dumps(payload),
            status_code=upstream.status_code,
            media_type="application/json",
        )

    return app


def serve(
    upstream: str,
    *,
    host: str = "0.0.0.0",
    port: int = 4242,
    audit_log: str | None = None,
    config: GuardrailConfig | None = None,
) -> None:
    import uvicorn  # type: ignore[import-not-found]
    settings = ProxySettings(
        upstream=upstream,
        audit_log=Path(audit_log).expanduser() if audit_log else None,
        config=config,
    )
    app = build_app(settings)
    log.info(
        "Pencheff Sentry listening on %s:%d → upstream %s",
        host, port, upstream,
    )
    uvicorn.run(app, host=host, port=port, log_level=os.environ.get("SENTRY_LOG_LEVEL", "info"))
