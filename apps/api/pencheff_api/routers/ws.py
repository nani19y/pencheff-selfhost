"""Engagement-scoped WebSocket — presence + live updates.

Subscribes to the engagement's Redis pub/sub channel. Every WebSocket
client receives every event published with ``publish_engagement_event``,
plus presence broadcasts from peers connected to the same engagement.

CE (no-auth): connects as the seeded single-tenant user unconditionally.
"""
from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from fastapi import APIRouter, Depends, Query, WebSocket, WebSocketDisconnect, status
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth.single_tenant import seed_ids
from ..db.base import get_session
from ..db.models import Engagement, EngagementMember, OrgMember, User
from ..events import async_subscriber, engagement_channel, publish_engagement_event

router = APIRouter(prefix="/ws", tags=["ws"])
log = logging.getLogger("pencheff.ws")


async def _get_seeded_user(session: AsyncSession) -> User | None:
    """Return the single-tenant seeded user (CE: no token required)."""
    from sqlalchemy import select
    ids = await seed_ids(session)
    return (await session.execute(select(User).where(User.id == ids["user_id"]))).scalar_one_or_none()


async def _can_access_engagement(
    session: AsyncSession, user: User, engagement_id: str
) -> Engagement | None:
    e = await session.get(Engagement, engagement_id)
    if e is None:
        return None
    from sqlalchemy import select
    member = (await session.execute(
        select(OrgMember).where(
            OrgMember.user_id == user.id, OrgMember.org_id == e.org_id
        )
    )).scalar_one_or_none()
    if member is None:
        return None
    return e


@router.websocket("/engagements/{engagement_id}")
async def engagement_ws(
    websocket: WebSocket,
    engagement_id: str,
    session: AsyncSession = Depends(get_session),
):
    user = await _get_seeded_user(session)
    if user is None:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return
    eng = await _can_access_engagement(session, user, engagement_id)
    if eng is None:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    await websocket.accept()
    presence_id = str(uuid4())
    user_label = user.name or user.email.split("@", 1)[0]

    publish_engagement_event(engagement_id, {
        "type": "presence_join",
        "presence_id": presence_id,
        "user_id": user.id,
        "user_label": user_label,
        "ts": datetime.now(timezone.utc).isoformat(),
    })

    redis_client = async_subscriber()
    pubsub = redis_client.pubsub()
    await pubsub.subscribe(engagement_channel(engagement_id))

    async def reader_task():
        try:
            while True:
                msg = await pubsub.get_message(ignore_subscribe_messages=True, timeout=10.0)
                if msg and msg.get("type") == "message":
                    await websocket.send_text(msg["data"])
        except Exception:
            pass

    reader = asyncio.create_task(reader_task())

    try:
        while True:
            data = await websocket.receive_text()
            try:
                msg: dict[str, Any] = json.loads(data)
            except json.JSONDecodeError:
                continue
            kind = msg.get("type")
            if kind == "presence_cursor":
                publish_engagement_event(engagement_id, {
                    "type": "presence_cursor",
                    "presence_id": presence_id,
                    "user_id": user.id,
                    "user_label": user_label,
                    "tab": msg.get("tab"),
                    "selector": msg.get("selector"),
                    "ts": datetime.now(timezone.utc).isoformat(),
                })
            elif kind == "ping":
                await websocket.send_text(json.dumps({"type": "pong"}))
            else:
                # Forward everything else; the server-side writers (REST
                # endpoints) are authoritative — clients use this channel
                # for fire-and-forget UX events like cursor presence.
                publish_engagement_event(engagement_id, {
                    **msg,
                    "presence_id": presence_id,
                    "user_id": user.id,
                    "user_label": user_label,
                })
    except WebSocketDisconnect:
        pass
    except Exception as exc:  # noqa: BLE001
        log.warning("ws error: %s", exc)
    finally:
        reader.cancel()
        try:
            await pubsub.unsubscribe(engagement_channel(engagement_id))
            await pubsub.close()
            await redis_client.close()
        except Exception:
            pass
        publish_engagement_event(engagement_id, {
            "type": "presence_leave",
            "presence_id": presence_id,
            "user_id": user.id,
            "user_label": user_label,
            "ts": datetime.now(timezone.utc).isoformat(),
        })
