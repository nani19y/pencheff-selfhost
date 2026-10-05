# apps/api/tests/test_targets_host_kind.py
"""Unit tests for the host-kind branch added to POST /targets and PATCH /targets/{id}.

Convention: pure unit tests — no conftest, no HTTP client, no real DB.
We call `create_target` / `update_target` directly with hand-built fakes,
mirroring the pattern established by test_repo_targets.py and
test_scans_router_kind_aware.py.

AuditLog field-name adaptations (spec vs model):
  spec said         | actual db/models.py column
  ------------------|---------------------------
  event_type        | action
  metadata          | meta
  actor_user_id     | user_id
  actor_ip          | request_ip
  actor_user_agent  | user_agent
"""
from __future__ import annotations

import datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException

from pencheff_api.db.models import AuditLog, Org, Target, User, Workspace
from pencheff_api.routers.targets import create_target, update_target
from pencheff_api.schemas.targets import HostKindConfig, TargetCreate, TargetUpdate


# ---------------------------------------------------------------------------
# Helpers / fakes
# ---------------------------------------------------------------------------

_NOW = datetime.datetime.now(datetime.timezone.utc)


def _make_org(*, allow_private_targets: bool = False) -> Org:
    return Org(id="org-1", name="Test Org", plan="free",
               allow_private_targets=allow_private_targets)


def _make_workspace(org: Org) -> Workspace:
    return Workspace(id="workspace-1", org_id=org.id, name="Default")


def _make_user() -> User:
    return User(id="user-1", email="tester@example.com")


def _make_target_row(workspace: Workspace, hosts: list[str], is_private: bool) -> Target:
    """Minimal Target row as returned after session.flush() + session.refresh()."""
    return Target(
        id="target-99",
        org_id=workspace.org_id,
        workspace_id=workspace.id,
        user_id="user-1",
        name="My Hosts",
        base_url="https://placeholder.invalid",
        scope=None,
        exclude_paths=[],
        credentials_encrypted=None,
        kind_credentials_encrypted=None,
        kind="host",
        llm_config=None,
        kind_config={"kind": "host", "hosts": hosts, "is_private_target": is_private},
        weekly_digest_emails=None,
        repository_id=None,
        created_at=_NOW,
    )


class _FakeSession:
    """AsyncSession stub that captures add() calls."""

    def __init__(self, target_row: Target, org: Org) -> None:
        self._target_row = target_row
        self._org = org
        self.added: list = []

    async def execute(self, stmt):
        mock = MagicMock()
        mock.scalars.return_value.all.return_value = []
        mock.all.return_value = []
        return mock

    def add(self, row) -> None:
        self.added.append(row)

    async def flush(self) -> None:
        pass

    async def commit(self) -> None:
        pass

    async def refresh(self, obj) -> None:
        # Patch in the stored kind_config so _to_out can round-trip it.
        if isinstance(obj, Target):
            obj.id = self._target_row.id
            obj.org_id = self._target_row.org_id
            obj.workspace_id = self._target_row.workspace_id
            obj.user_id = self._target_row.user_id
            obj.name = self._target_row.name
            obj.base_url = self._target_row.base_url
            obj.scope = self._target_row.scope
            obj.exclude_paths = self._target_row.exclude_paths
            obj.credentials_encrypted = self._target_row.credentials_encrypted
            obj.kind_credentials_encrypted = self._target_row.kind_credentials_encrypted
            obj.kind = self._target_row.kind
            obj.llm_config = self._target_row.llm_config
            obj.kind_config = self._target_row.kind_config
            obj.weekly_digest_emails = self._target_row.weekly_digest_emails
            obj.repository_id = self._target_row.repository_id
            obj.created_at = self._target_row.created_at

    async def get(self, model_cls, pk):
        """Return the org when asked for it by PK."""
        if model_cls is Org and pk == self._org.id:
            return self._org
        return None


def _make_request(*, client_host: str = "203.0.113.1") -> SimpleNamespace:
    return SimpleNamespace(
        client=SimpleNamespace(host=client_host),
        headers={"user-agent": "pytest/1.0"},
    )


def _host_target_body(hosts: list[str] | None = None) -> TargetCreate:
    if hosts is None:
        hosts = ["example.com", "1.2.3.4"]
    return TargetCreate(
        name="My Hosts",
        base_url="https://placeholder.invalid",
        kind="host",
        kind_config=HostKindConfig(kind="host", hosts=hosts),
    )


async def _call_create_target(
    body: TargetCreate,
    *,
    org: Org,
    expected_hosts: list[str] | None = None,
    expected_is_private: bool = False,
) -> tuple[object, _FakeSession]:
    """Call the router function with all deps replaced by fakes."""
    ws = _make_workspace(org)
    user = _make_user()
    hosts_for_row = expected_hosts or (body.kind_config.hosts if body.kind_config else [])
    target_row = _make_target_row(ws, hosts_for_row, expected_is_private)
    session = _FakeSession(target_row, org)

    with (
        patch("pencheff_api.routers.targets.check_target_quota", new_callable=AsyncMock),
        patch("pencheff_api.routers.targets.encrypt_credentials", return_value=None),
    ):
        req = _make_request()
        result = await create_target(
            body, request=req, user=user, workspace=ws, session=session
        )

    return result, session


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_create_host_target_with_public_hosts_succeeds() -> None:
    """POST with two public hosts — resolves OK, 201, is_private_target=False."""
    org = _make_org(allow_private_targets=False)
    body = _host_target_body(["example.com", "1.2.3.4"])

    def fake_resolve(host: str) -> str:
        return {"example.com": "93.184.216.34", "1.2.3.4": "1.2.3.4"}[host]

    with patch(
        "pencheff_api.services.host_validation.resolve_host",
        side_effect=fake_resolve,
    ):
        result, _session = await _call_create_target(
            body, org=org, expected_hosts=["example.com", "1.2.3.4"],
            expected_is_private=False,
        )

    assert result.kind == "host"
    assert result.kind_config is not None
    assert result.kind_config.hosts == ["example.com", "1.2.3.4"]
    assert result.kind_config.is_private_target is False


@pytest.mark.asyncio
async def test_create_host_target_with_private_host_blocked_by_default() -> None:
    """Private IP + allow_private_targets=False → 422 with error code."""
    org = _make_org(allow_private_targets=False)
    body = _host_target_body(["internal.corp"])

    def fake_resolve(host: str) -> str:
        return "10.0.0.5"

    ws = _make_workspace(org)
    user = _make_user()
    target_row = _make_target_row(ws, ["internal.corp"], False)
    session = _FakeSession(target_row, org)

    with (
        patch("pencheff_api.routers.targets.check_target_quota", new_callable=AsyncMock),
        patch("pencheff_api.routers.targets.encrypt_credentials", return_value=None),
        patch("pencheff_api.services.host_validation.resolve_host", side_effect=fake_resolve),
    ):
        with pytest.raises(HTTPException) as exc_info:
            await create_target(body, request=_make_request(), user=user, workspace=ws, session=session)

    exc = exc_info.value
    assert exc.status_code == 422
    assert exc.detail["error"] == "host_kind_private_targets_disabled"
    offending = exc.detail["offending_hosts"]
    assert "internal.corp" in offending


@pytest.mark.asyncio
async def test_create_host_target_with_private_host_allowed_when_flag_on() -> None:
    """Same private host but org.allow_private_targets=True → 201, is_private_target=True."""
    org = _make_org(allow_private_targets=True)
    body = _host_target_body(["internal.corp"])

    def fake_resolve(host: str) -> str:
        return "10.0.0.5"

    with patch(
        "pencheff_api.services.host_validation.resolve_host",
        side_effect=fake_resolve,
    ):
        result, _session = await _call_create_target(
            body, org=org, expected_hosts=["internal.corp"], expected_is_private=True,
        )

    assert result.kind == "host"
    assert result.kind_config is not None
    assert result.kind_config.is_private_target is True


@pytest.mark.asyncio
async def test_create_host_target_resolution_failure_returns_422() -> None:
    """DNS resolution failure → 422 with error=host_kind_resolution_failed."""
    from pencheff_api.services.host_validation import HostResolutionError

    org = _make_org()
    body = _host_target_body(["unresolvable.invalid"])
    ws = _make_workspace(org)
    user = _make_user()
    target_row = _make_target_row(ws, ["unresolvable.invalid"], False)
    session = _FakeSession(target_row, org)

    def fake_resolve(host: str) -> str:
        raise HostResolutionError(host, "NXDOMAIN")

    with (
        patch("pencheff_api.routers.targets.check_target_quota", new_callable=AsyncMock),
        patch("pencheff_api.routers.targets.encrypt_credentials", return_value=None),
        patch("pencheff_api.services.host_validation.resolve_host", side_effect=fake_resolve),
    ):
        with pytest.raises(HTTPException) as exc_info:
            await create_target(body, request=_make_request(), user=user, workspace=ws, session=session)

    exc = exc_info.value
    assert exc.status_code == 422
    assert exc.detail["error"] == "host_kind_resolution_failed"


@pytest.mark.asyncio
async def test_create_host_target_writes_audit_log() -> None:
    """Successful host-target creation adds an AuditLog row to the session."""
    org = _make_org(allow_private_targets=False)
    hosts = ["box.example.com"]
    body = _host_target_body(hosts)

    def fake_resolve(host: str) -> str:
        return "93.184.216.34"

    with patch(
        "pencheff_api.services.host_validation.resolve_host",
        side_effect=fake_resolve,
    ):
        result, session = await _call_create_target(
            body, org=org, expected_hosts=hosts, expected_is_private=False,
        )

    audit_rows = [r for r in session.added if isinstance(r, AuditLog)]
    assert len(audit_rows) == 1, f"Expected 1 AuditLog row, got {len(audit_rows)}"

    row = audit_rows[0]
    assert row.action == "target.host.create"
    assert row.meta is not None
    assert row.meta["hosts"] == hosts
    assert row.meta["is_private_target"] is False


# ---------------------------------------------------------------------------
# PATCH helpers / fakes
# ---------------------------------------------------------------------------


class _FakePatchSession(_FakeSession):
    """_FakeSession subclass for PATCH tests.

    Overrides execute() so that the initial SELECT for the target row
    returns the pre-PATCH existing target object via scalar_one_or_none(),
    while attachment-lookup calls still return empty lists.
    """

    def __init__(self, existing_target: Target, post_patch_target: Target, org: Org) -> None:
        # Pass the post-patch row to the parent so refresh() returns it.
        super().__init__(post_patch_target, org)
        self._existing_target = existing_target
        self._execute_count = 0

    async def execute(self, stmt):
        self._execute_count += 1
        if self._execute_count == 1:
            # First call: the PATCH handler's SELECT to load the target row.
            mock = MagicMock()
            mock.scalar_one_or_none.return_value = self._existing_target
            mock.scalars.return_value.all.return_value = []
            mock.all.return_value = []
            return mock
        # Subsequent calls (e.g. _attached_repo_ids): return empty.
        mock = MagicMock()
        mock.scalars.return_value.all.return_value = []
        mock.scalar_one_or_none.return_value = None
        mock.all.return_value = []
        return mock


def _host_update_body(hosts: list[str]) -> TargetUpdate:
    return TargetUpdate(kind_config=HostKindConfig(kind="host", hosts=hosts))


# ---------------------------------------------------------------------------
# PATCH tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_patch_host_target_adds_new_public_host_succeeds() -> None:
    """PATCH with an additional public host — resolves OK, 200, both hosts present."""
    org = _make_org(allow_private_targets=False)
    ws = _make_workspace(org)
    user = _make_user()

    # The existing target has a single public host.
    existing = _make_target_row(ws, ["1.2.3.4"], False)
    # After the PATCH the row should have both hosts, still public.
    post_patch = _make_target_row(ws, ["1.2.3.4", "1.2.3.5"], False)

    body = _host_update_body(["1.2.3.4", "1.2.3.5"])
    session = _FakePatchSession(existing, post_patch, org)

    def fake_resolve(host: str) -> str:
        return {"1.2.3.4": "1.2.3.4", "1.2.3.5": "1.2.3.5"}[host]

    with patch(
        "pencheff_api.services.host_validation.resolve_host",
        side_effect=fake_resolve,
    ):
        result = await update_target(
            target_id=existing.id,
            body=body,
            workspace=ws,
            session=session,
        )

    assert result.kind == "host"
    assert result.kind_config is not None
    assert result.kind_config.hosts == ["1.2.3.4", "1.2.3.5"]
    assert result.kind_config.is_private_target is False


@pytest.mark.asyncio
async def test_patch_host_target_adding_private_host_rejected_when_flag_off() -> None:
    """PATCH adding a private IP while allow_private_targets=False → 422."""
    org = _make_org(allow_private_targets=False)
    ws = _make_workspace(org)
    user = _make_user()

    existing = _make_target_row(ws, ["1.2.3.4"], False)
    # post_patch row is never reached — we expect a 422 before commit.
    post_patch = _make_target_row(ws, ["1.2.3.4", "10.0.0.5"], False)

    body = _host_update_body(["1.2.3.4", "10.0.0.5"])
    session = _FakePatchSession(existing, post_patch, org)

    def fake_resolve(host: str) -> str:
        return {"1.2.3.4": "1.2.3.4", "10.0.0.5": "10.0.0.5"}[host]

    with patch(
        "pencheff_api.services.host_validation.resolve_host",
        side_effect=fake_resolve,
    ):
        with pytest.raises(HTTPException) as exc_info:
            await update_target(
                target_id=existing.id,
                body=body,
                workspace=ws,
                session=session,
            )

    exc = exc_info.value
    assert exc.status_code == 422
    assert exc.detail["error"] == "host_kind_private_targets_disabled"
    assert "10.0.0.5" in exc.detail["offending_hosts"]
