"""Nightly retention pass — prunes old proxy_traffic per engagement policy
and reaps OAST containers tied to closed engagements.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from ..config import get_settings
from ..db.models import Engagement
from ..services.engagement_oast import revoke_oast
from .celery_app import celery_app


async def _prune_traffic_async() -> int:
    settings = get_settings()
    engine = create_async_engine(settings.database_url)
    Session = async_sessionmaker(engine, expire_on_commit=False)
    deleted = 0
    try:
        async with Session() as session:
            engagements = (await session.execute(select(Engagement))).scalars().all()
            for eng in engagements:
                cutoff = datetime.now(timezone.utc) - timedelta(days=eng.retention_days)
                res = await session.execute(
                    text("""
                        DELETE FROM proxy_traffic
                        WHERE engagement_id = :eid AND captured_at < :cutoff
                    """),
                    {"eid": eng.id, "cutoff": cutoff},
                )
                deleted += res.rowcount or 0
            await session.commit()
    finally:
        await engine.dispose()
    return deleted


async def _reap_oast_async() -> int:
    settings = get_settings()
    engine = create_async_engine(settings.database_url)
    Session = async_sessionmaker(engine, expire_on_commit=False)
    reaped = 0
    cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
    try:
        async with Session() as session:
            rows = (await session.execute(
                select(Engagement).where(
                    Engagement.status == "closed",
                    Engagement.oast_container_id.is_not(None),
                    Engagement.closed_at < cutoff,
                )
            )).scalars().all()
            for eng in rows:
                revoke_oast(eng)
                eng.oast_container_id = None
                reaped += 1
            await session.commit()
    finally:
        await engine.dispose()
    return reaped


@celery_app.task(name="pencheff.retention.prune_traffic")
def prune_old_traffic() -> dict[str, int]:
    return {"deleted_rows": asyncio.run(_prune_traffic_async())}


@celery_app.task(name="pencheff.retention.reap_oast")
def reap_closed_engagement_oast() -> dict[str, int]:
    return {"reaped": asyncio.run(_reap_oast_async())}
