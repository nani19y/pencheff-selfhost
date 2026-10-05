# apps/api/tests/test_scans_host_kind_gate.py
"""Unit tests for the POST /scans host-kind 409 gate (Task 8).

The gate fires BEFORE any DB write or Celery dispatch so that no Scan row
is created and no task is enqueued when the target kind is "host".

Pattern: pure unit tests — no conftest, no HTTP client, no real DB.
We call ``start_scan`` directly with hand-built fakes, mirroring the pattern
from test_targets_host_kind.py and test_scans_router_kind_aware.py.
"""
from __future__ import annotations

import datetime
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from fastapi import HTTPException

from pencheff_api.db.models import Org, Scan, Target, User, Workspace
from pencheff_api.routers.scans import start_scan
from pencheff_api.schemas.scans import ConsentPayload, ScanCreate


# ---------------------------------------------------------------------------
# Constants / shared data
# ---------------------------------------------------------------------------

_NOW = datetime.datetime.now(datetime.timezone.utc)

_VALID_AUTH_TEXT = (
    "I confirm I have written authorization from AcmeCorp to perform "
    "an AI-assisted security assessment of the target systems listed."
)

_HOST_DISCLOSED_ACTIONS = [
    "passive_recon",
    "active_recon",
    "host_os_exploitation",
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_workspace() -> Workspace:
    return Workspace(id="ws-1", org_id="org-1", name="Default")


def _make_user() -> User:
    return User(id="user-1", email="tester@example.com")


def _make_host_target(workspace: Workspace) -> Target:
    """A host-kind Target row — what the DB returns after creation."""
    return Target(
        id="target-host-1",
        org_id=workspace.org_id,
        workspace_id=workspace.id,
        user_id="user-1",
        name="My Servers",
        base_url="https://placeholder.invalid",
        scope=None,
        exclude_paths=[],
        credentials_encrypted=None,
        kind_credentials_encrypted=None,
        kind="host",
        llm_config=None,
        kind_config={"kind": "host", "hosts": ["10.0.0.1"], "is_private_target": False},
        weekly_digest_emails=None,
        repository_id=None,
        created_at=_NOW,
    )


def _make_url_target(workspace: Workspace) -> Target:
    """A url-kind Target — used in negative tests (gate must NOT fire)."""
    return Target(
        id="target-url-1",
        org_id=workspace.org_id,
        workspace_id=workspace.id,
        user_id="user-1",
        name="My App",
        base_url="https://example.com",
        scope=None,
        exclude_paths=[],
        credentials_encrypted=None,
        kind_credentials_encrypted=None,
        kind="url",
        llm_config=None,
        kind_config=None,
        weekly_digest_emails=None,
        repository_id=None,
        created_at=_NOW,
    )


def _valid_consent(disclosed_actions: list[str] | None = None) -> ConsentPayload:
    return ConsentPayload(
        acknowledged=True,
        authorization_text=_VALID_AUTH_TEXT,
        disclosed_actions=disclosed_actions or _HOST_DISCLOSED_ACTIONS,
        consent_given_at=_NOW,
    )


def _scan_body(target_id: str, disclosed_actions: list[str] | None = None) -> ScanCreate:
    return ScanCreate(
        target_id=target_id,
        profile="standard",
        consent_payload=_valid_consent(disclosed_actions),
    )


class _FakeScanSession:
    """Minimal AsyncSession stub for the start_scan handler.

    The first ``execute`` call is the ``SELECT Target`` lookup; subsequent
    calls are for engagement resolution and similar. All secondary calls
    return empty / None results.
    """

    def __init__(self, target: Target | None) -> None:
        self._target = target
        self.added: list = []
        self._execute_count = 0

    async def execute(self, stmt):
        self._execute_count += 1
        mock = MagicMock()
        if self._execute_count == 1:
            # First execute: SELECT Target WHERE id = ... AND workspace_id = ...
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


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_scan_against_host_target_returns_409() -> None:
    """POST /scans with a host-kind target must return HTTP 409.

    The gate must fire BEFORE any consent parsing side-effects so that
    the operator receives a clear error and can retry once the OSExploitAgent
    (sub-project B) is available.
    """
    ws = _make_workspace()
    user = _make_user()
    target = _make_host_target(ws)
    session = _FakeScanSession(target)
    body = _scan_body(target.id)

    with (
        patch("pencheff_api.tasks.scan_task.run_full_scan") as mock_task,
    ):
        mock_task.delay = MagicMock()
        with pytest.raises(HTTPException) as exc_info:
            await start_scan(body=body, user=user, workspace=ws, session=session)

    exc = exc_info.value
    assert exc.status_code == 409
    assert exc.detail["error"] == "host_kind_scanning_not_yet_available"


@pytest.mark.asyncio
async def test_scan_against_host_target_does_not_enqueue_task() -> None:
    """POST /scans for a host-kind target must NOT enqueue any Celery task.

    The 409 must fire before ``run_full_scan.delay()`` is called.
    """
    ws = _make_workspace()
    user = _make_user()
    target = _make_host_target(ws)
    session = _FakeScanSession(target)
    body = _scan_body(target.id)

    mock_delay = MagicMock()

    with (
        patch("pencheff_api.routers.scans.run_full_scan") as mock_task,
    ):
        mock_task.delay = mock_delay
        with pytest.raises(HTTPException):
            await start_scan(body=body, user=user, workspace=ws, session=session)

    mock_delay.assert_not_called()


@pytest.mark.asyncio
async def test_scan_against_host_target_does_not_write_scan_row() -> None:
    """POST /scans for a host-kind target must NOT add a Scan row to the session.

    No DB write must occur before the 409 is raised.
    """
    ws = _make_workspace()
    user = _make_user()
    target = _make_host_target(ws)
    session = _FakeScanSession(target)
    body = _scan_body(target.id)

    with (
        patch("pencheff_api.routers.scans.run_full_scan"),
    ):
        with pytest.raises(HTTPException):
            await start_scan(body=body, user=user, workspace=ws, session=session)

    scan_rows = [r for r in session.added if isinstance(r, Scan)]
    assert len(scan_rows) == 0, (
        f"Expected 0 Scan rows in session, got {len(scan_rows)}. "
        "The 409 gate must fire before session.add(scan)."
    )


@pytest.mark.asyncio
async def test_scan_against_non_host_target_is_not_blocked() -> None:
    """The 409 gate must NOT fire for a url-kind target.

    Sanity check: the gate is kind-specific and doesn't break existing kinds.
    This call will fail for unrelated reasons (engagement resolution, etc.),
    but the error must NOT be a 409 from the host gate.
    """
    ws = _make_workspace()
    user = _make_user()
    target = _make_url_target(ws)
    session = _FakeScanSession(target)
    body = _scan_body(
        target.id,
        disclosed_actions=["passive_recon", "active_recon", "exploitation"],
    )

    with (
        patch("pencheff_api.routers.scans.run_full_scan"),
        patch(
            "pencheff_api.services.threat_model.generate_threat_model",
            return_value={"method": "dread", "categories": []},
        ),
        patch(
            "pencheff_api.services.threat_model.module_priority_bias",
            return_value=[],
        ),
    ):
        try:
            await start_scan(body=body, user=user, workspace=ws, session=session)
        except HTTPException as exc:
            # Any HTTPException here is acceptable EXCEPT a 409 from the host gate.
            assert not (
                exc.status_code == 409
                and isinstance(exc.detail, dict)
                and exc.detail.get("error") == "host_kind_scanning_not_yet_available"
            ), "The 409 host gate fired for a url-kind target — it must only fire for kind=='host'."
        except Exception:
            # Non-HTTPException errors (e.g. ValidationError from the fake session
            # not populating Scan fields after refresh) are fine — they prove the
            # handler advanced PAST the host gate and reached later handler logic.
            pass
