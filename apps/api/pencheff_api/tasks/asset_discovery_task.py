"""Trigger passive asset discovery for an org and persist the results."""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from ..config import get_settings
from ..db.models import Asset
from .celery_app import celery_app


@celery_app.task(name="pencheff_api.tasks.asset_discovery_task.run_discovery")
def run_discovery(org_id: str, workspace_id: str, root_domain: str) -> dict[str, int]:
    """Run the pencheff ASM discovery module and upsert into the assets table."""
    # Import pencheff plugin code at task time (not at module load) so the
    # API process stays fast and avoids pulling in MCP server imports.
    import sys
    sys.path.insert(0, "/app/plugins/pencheff")  # container path for the plugin
    try:
        from pencheff.modules.asm.continuous_discovery import discover
        from pencheff.modules.asm import asset_inventory
    except Exception:  # noqa: BLE001
        return {"error": "pencheff plugin not importable"}

    counts = asyncio.run(discover(org_id, root_domain))

    settings = get_settings()
    engine = create_engine(settings.database_url.replace("+asyncpg", ""), future=True)
    new_count = 0
    with Session(engine) as db:
        for a in asset_inventory.list_assets(org_id):
            existing = db.execute(
                select(Asset).where(
                    Asset.workspace_id == workspace_id,
                    Asset.type == a.type,
                    Asset.value == a.value,
                )
            ).scalar_one_or_none()
            now = datetime.now(timezone.utc)
            if existing:
                existing.last_seen = now
                existing.meta = a.metadata
            else:
                db.add(Asset(
                    org_id=org_id, workspace_id=workspace_id,
                    type=a.type, value=a.value,
                    meta=a.metadata, first_seen=now, last_seen=now,
                ))
                new_count += 1
        db.commit()
    return {**counts, "new_in_db": new_count}
