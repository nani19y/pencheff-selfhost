"""Dependency health checks for the /ready readiness endpoint. Each check is
timeout-bounded and fails closed to a reason string — never raises, never hangs."""
from __future__ import annotations

import asyncio

from sqlalchemy import text

_TIMEOUT = 2.0


async def check_db(session) -> str:
    try:
        await asyncio.wait_for(session.execute(text("SELECT 1")), _TIMEOUT)
        return "ok"
    except Exception as exc:  # noqa: BLE001 — any failure = not ready
        return f"down: {type(exc).__name__}: {exc}"[:200]


async def check_redis(redis_url: str) -> str:
    import redis.asyncio as aioredis

    client = aioredis.from_url(redis_url)
    try:
        await asyncio.wait_for(client.ping(), _TIMEOUT)
        return "ok"
    except Exception as exc:  # noqa: BLE001
        return f"down: {type(exc).__name__}: {exc}"[:200]
    finally:
        try:
            await client.aclose()
        except Exception:  # noqa: BLE001
            pass
