# apps/api/tests/test_repo_integration_purge.py
"""Regression tests for GitHub-App uninstall / disconnect repo cleanup.

Bug: uninstalling the GitHub App (or hitting "Disconnect") soft-removed the
RepoIntegration but left its Repository rows behind, so they kept listing in
/repos and /targets forever. Fix: hard-delete the integration's repos on
``installation.deleted`` and on manual disconnect.

Convention: pure unit tests — no conftest, no HTTP client, no real DB. We call
the helpers directly with hand-built fakes (mirrors test_repo_targets.py).

The DB-level ON DELETE CASCADE that removes the mirror Target / RepoScan /
RepoFinding / RepoSbom rows is enforced by the FK definitions in models.py and
is not re-tested here; these tests cover the only non-trivial app logic:
detaching the RESTRICT-FK target_repositories rows before deleting the repos,
and the deleted-vs-suspend branch in the webhook handler.
"""
from __future__ import annotations

import asyncio
from typing import Any

import pytest
from sqlalchemy.sql import Delete, Select

from pencheff_api.db.models import RepoIntegration
from pencheff_api.routers import repos as repos_router
from pencheff_api.routers.repos import purge_integration_repos
from pencheff_api.routers.github_webhooks import _handle_installation


# ── purge_integration_repos ───────────────────────────────────────────────

class _ScalarsResult:
    def __init__(self, rows: list[Any]) -> None:
        self._rows = rows

    def scalars(self) -> "_ScalarsResult":
        return self

    def all(self) -> list[Any]:
        return self._rows


class _FakePurgeSession:
    """Records which tables DELETE statements target, in order."""

    def __init__(self, repo_ids: list[str]) -> None:
        self._repo_ids = repo_ids
        self.deleted_tables: list[str] = []
        self.committed = False

    async def execute(self, stmt: Any) -> Any:
        if isinstance(stmt, Select):
            return _ScalarsResult(self._repo_ids)
        if isinstance(stmt, Delete):
            self.deleted_tables.append(stmt.table.name)
            return None
        raise AssertionError(f"unexpected statement: {stmt!r}")

    async def commit(self) -> None:
        self.committed = True


def test_purge_detaches_url_targets_before_deleting_repos():
    session = _FakePurgeSession(repo_ids=["repo-1", "repo-2"])

    count = asyncio.run(purge_integration_repos(session, "integ-1"))

    assert count == 2
    # target_repositories (RESTRICT FK) MUST be detached before the repos are
    # deleted, otherwise the repo delete is blocked by the constraint.
    assert session.deleted_tables == ["target_repositories", "repositories"]
    # Helper does not own the transaction — the caller commits.
    assert session.committed is False


def test_purge_is_a_noop_when_integration_has_no_repos():
    session = _FakePurgeSession(repo_ids=[])

    count = asyncio.run(purge_integration_repos(session, "integ-empty"))

    assert count == 0
    assert session.deleted_tables == []


# ── webhook installation.deleted vs suspend ───────────────────────────────

class _SingleResult:
    def __init__(self, obj: Any) -> None:
        self._obj = obj

    def scalar_one_or_none(self) -> Any:
        return self._obj


class _FakeWebhookSession:
    def __init__(self, integ: RepoIntegration) -> None:
        self._integ = integ
        self.committed = False

    async def execute(self, _stmt: Any) -> Any:
        return _SingleResult(self._integ)

    async def commit(self) -> None:
        self.committed = True


def _integ() -> RepoIntegration:
    i = RepoIntegration(
        id="integ-1", org_id="org-1", workspace_id="ws-1",
        provider="github", installation_id="138643043",
        account_login="octo", account_type="User",
    )
    i.removed_at = None
    return i


def test_webhook_deleted_marks_removed_and_purges_repos(monkeypatch):
    integ = _integ()
    session = _FakeWebhookSession(integ)
    calls: list[str] = []

    async def _spy(_session, integration_id):
        calls.append(integration_id)
        return 5

    # Handler imports purge_integration_repos from .repos at call time, so
    # patching the attribute on the repos module is what gets picked up.
    monkeypatch.setattr(repos_router, "purge_integration_repos", _spy)

    result = asyncio.run(_handle_installation(
        session, {"installation": {"id": 138643043}, "action": "deleted"}))

    assert result == "integration-removed"
    assert integ.removed_at is not None
    assert calls == ["integ-1"]
    assert session.committed is True


def test_webhook_suspend_marks_removed_but_keeps_repos(monkeypatch):
    integ = _integ()
    session = _FakeWebhookSession(integ)
    calls: list[str] = []

    async def _spy(_session, integration_id):
        calls.append(integration_id)
        return 0

    monkeypatch.setattr(repos_router, "purge_integration_repos", _spy)

    result = asyncio.run(_handle_installation(
        session, {"installation": {"id": 138643043}, "action": "suspend"}))

    assert result == "integration-removed"
    assert integ.removed_at is not None
    # Suspend is reversible — repos stay.
    assert calls == []
    assert session.committed is True
