"""The CE workspaces list returns exactly the one seeded workspace."""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from types import SimpleNamespace

import pencheff_api.auth.single_tenant as st
from pencheff_api.db.models import Workspace
from pencheff_api.routers import workspaces as ws_router


class FakeSession:
    def __init__(self, ws):
        self._ws = ws

    async def get(self, model, pk):
        return self._ws if pk == self._ws.id else None


def setup_function():
    st._seed_ids.update(org_id="org-1", user_id="user-1", workspace_id="ws-1")


def teardown_function():
    st._seed_ids.clear()


def test_list_returns_single_workspace():
    ws = Workspace(
        id="ws-1", org_id="org-1", name="Default", slug="default",
        created_at=datetime(2024, 1, 1, tzinfo=timezone.utc),
    )
    user = SimpleNamespace(id="user-1")
    result = asyncio.run(ws_router.list_workspaces(user=user, session=FakeSession(ws)))
    items = result if isinstance(result, list) else result.items
    assert len(items) == 1
    assert items[0].id == "ws-1"
