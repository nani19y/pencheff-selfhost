"""Shared helpers for outbound integrations — HMAC signing, retry, timeout."""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from typing import Any

import httpx


async def post_json(
    url: str,
    payload: dict[str, Any],
    headers: dict[str, str] | None = None,
    hmac_secret: str | None = None,
    timeout: float = 10.0,
    retries: int = 2,
) -> tuple[bool, int, str]:
    """POST ``payload`` as JSON with optional HMAC signing + limited retries."""
    body = json.dumps(payload).encode()
    headers = dict(headers or {})
    headers.setdefault("Content-Type", "application/json")
    if hmac_secret:
        sig = hmac.new(hmac_secret.encode(), body, hashlib.sha256).hexdigest()
        headers["X-Pencheff-Signature"] = f"sha256={sig}"
        headers["X-Pencheff-Timestamp"] = str(int(time.time()))

    last_status, last_body = 0, ""
    async with httpx.AsyncClient(timeout=timeout) as client:
        for attempt in range(retries + 1):
            try:
                r = await client.post(url, content=body, headers=headers)
                last_status, last_body = r.status_code, r.text[:500]
                if 200 <= r.status_code < 300:
                    return True, r.status_code, r.text[:500]
                if r.status_code in {429} or r.status_code >= 500:
                    import asyncio
                    await asyncio.sleep(1.5 ** attempt)
                    continue
                return False, r.status_code, r.text[:500]
            except Exception as e:  # noqa: BLE001
                last_body = f"{type(e).__name__}: {e}"
                import asyncio
                await asyncio.sleep(1.5 ** attempt)
    return False, last_status, last_body
