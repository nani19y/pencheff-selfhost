"""Async correlation pass — runs after every scan + repo scan completion."""
from __future__ import annotations

import asyncio

from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from ..config import get_settings
from ..services.finding_correlation import correlate_engagement_findings
from .celery_app import celery_app


async def _run(engagement_id: str) -> int:
    settings = get_settings()
    engine = create_async_engine(settings.database_url)
    Session = async_sessionmaker(engine, expire_on_commit=False)
    async with Session() as session:
        return await correlate_engagement_findings(session, engagement_id)


@celery_app.task(name="pencheff.correlation.run")
def run_correlation(engagement_id: str) -> dict[str, int]:
    return {"edges_added": asyncio.run(_run(engagement_id))}
