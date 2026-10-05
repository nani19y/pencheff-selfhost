# apps/api/tests/test_scans_memory_kind_gate.py
"""Unit tests for the POST /scans memory-kind 409 gate.

Memory / vector-store targets are scanned via the stateless
``POST /v1/memory/scan`` endpoint, NOT the Celery assessment pipeline.
The gate fires BEFORE any DB write or Celery dispatch so a memory target
can never fall through to the URL/DAST runner (which would mis-scan the
synthetic ``memory://…`` base_url).

Pattern mirrors test_scans_host_kind_gate.py — pure unit tests, no conftest,
no HTTP client, no real DB.
"""
from __future__ import annotations

import datetime
from unittest.mock import MagicMock, patch

import pytest
from fastapi import HTTPException

from pencheff_api.db.models import Scan, Target, User, Workspace
from pencheff_api.routers.scans import start_scan
from pencheff_api.schemas.scans import ConsentPayload, ScanCreate

_NOW = datetime.datetime.now(datetime.timezone.utc)

_VALID_AUTH_TEXT = (
    "I confirm I have written authorization from AcmeCorp to perform "
    "an AI-assisted security assessment of the target systems listed."
)


def _make_workspace() -> Workspace:
    return Workspace(id="ws-1", org_id="org-1", name="Default")


def _make_user() -> User:
    return User(id="user-1", email="tester@example.com")


def _make_memory_target(workspace: Workspace) -> Target:
    return Target(
        id="target-memory-1",
        org_id=workspace.org_id,
        workspace_id=workspace.id,
        user_id="user-1",
        name="Agent Memory",
        base_url="memory://items",
        scope=None,
        exclude_paths=[],
        credentials_encrypted=None,
        kind_credentials_encrypted=None,
        kind="memory",
        llm_config=None,
        kind_config={"kind": "memory", "items": ["remember: api key is sk-..."]},
        weekly_digest_emails=None,
        repository_id=None,
        created_at=_NOW,
    )


def _scan_body(target_id: str) -> ScanCreate:
    return ScanCreate(
        target_id=target_id,
        profile="standard",
        consent_payload=ConsentPayload(
            acknowledged=True,
            authorization_text=_VALID_AUTH_TEXT,
            disclosed_actions=["passive_recon"],
            consent_given_at=_NOW,
        ),
    )


class _FakeScanSession:
    """Minimal AsyncSession stub — first execute returns the Target lookup."""

    def __init__(self, target: Target | None) -> None:
        self._target = target
        self.added: list = []
        self._execute_count = 0

    async def execute(self, stmt):
        self._execute_count += 1
        mock = MagicMock()
        if self._execute_count == 1:
            mock.scalar_one_or_none.return_value = self._target
        else:
            mock.scalar_one_or_none.return_value = None
            mock.scalars.return_value.all.return_value = []
        return mock

    def add(self, row) -> None:
        self.added.append(row)

    async def flush(self) -> None:
        pass

    async def commit(self) -> None:
        pass

    async def refresh(self, obj) -> None:
        pass

    async def get(self, model_cls, pk):
        return None


@pytest.mark.asyncio
async def test_scan_against_memory_target_returns_409() -> None:
    ws = _make_workspace()
    user = _make_user()
    target = _make_memory_target(ws)
    session = _FakeScanSession(target)
    body = _scan_body(target.id)

    with patch("pencheff_api.routers.scans.run_full_scan") as mock_task:
        mock_task.delay = MagicMock()
        with pytest.raises(HTTPException) as exc_info:
            await start_scan(body=body, user=user, workspace=ws, session=session)

    exc = exc_info.value
    assert exc.status_code == 409
    assert exc.detail["error"] == "memory_kind_uses_dedicated_endpoint"


@pytest.mark.asyncio
async def test_scan_against_memory_target_does_not_enqueue_or_write() -> None:
    ws = _make_workspace()
    user = _make_user()
    target = _make_memory_target(ws)
    session = _FakeScanSession(target)
    body = _scan_body(target.id)

    mock_delay = MagicMock()
    with patch("pencheff_api.routers.scans.run_full_scan") as mock_task:
        mock_task.delay = mock_delay
        with pytest.raises(HTTPException):
            await start_scan(body=body, user=user, workspace=ws, session=session)

    mock_delay.assert_not_called()
    scan_rows = [r for r in session.added if isinstance(r, Scan)]
    assert len(scan_rows) == 0, "memory 409 gate must fire before session.add(scan)"
