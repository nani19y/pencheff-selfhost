import asyncio
from datetime import datetime, timezone

import pytest
from fastapi import HTTPException

from pencheff_api.db.models import Repository, Target
from pencheff_api.routers import repos as repos_router
from pencheff_api.routers.repos import RepositoryUpdate, _mirror_as_target, update_repo
from pencheff_api.routers.targets import _to_out
from pencheff_api.services import github_app


class FakeSession:
    def __init__(self) -> None:
        self.added = []

    def add(self, row) -> None:
        self.added.append(row)


def test_repo_mirror_target_is_created_as_repo_kind():
    db = FakeSession()
    repo = Repository(
        id="repo-1",
        org_id="org-1",
        workspace_id="workspace-1",
        integration_id=None,
        provider="github",
        provider_repo_id="123",
        owner="octo",
        name="private-repo",
        full_name="octo/private-repo",
        default_branch="main",
        private=True,
        html_url="https://github.com/octo/private-repo",
        language="Python",
    )

    _mirror_as_target(db, repo)

    assert len(db.added) == 1
    target = db.added[0]
    assert target.repository_id == "repo-1"
    assert target.kind == "repo"


def test_repo_backed_target_serializes_as_repo_even_if_stored_kind_is_stale():
    target = Target(
        id="target-1",
        org_id="org-1",
        workspace_id="workspace-1",
        name="octo/private-repo",
        base_url="https://github.com/octo/private-repo",
        repository_id="repo-1",
        kind="url",
        created_at=datetime.now(timezone.utc),
    )

    out = _to_out(target)

    assert out.repository_id == "repo-1"
    assert out.kind == "repo"


def test_clone_with_token_does_not_put_pat_in_git_arguments(monkeypatch, tmp_path):
    calls = []
    secret = "ghp_full_permission_secret"

    def fake_run_git(args, *, env=None, timeout):
        calls.append((args, env, timeout))

    monkeypatch.setattr(github_app, "_run_git", fake_run_git)

    github_app.clone_with_token(secret, "octo/private-repo", str(tmp_path / "src"))

    assert calls
    assert all(secret not in " ".join(args) for args, _env, _timeout in calls)
    assert calls[0][0] == [
        "git",
        "clone",
        "--depth",
        "1",
        "https://github.com/octo/private-repo.git",
        str(tmp_path / "src"),
    ]


def test_missing_git_error_is_clear(monkeypatch):
    monkeypatch.setattr(github_app.shutil, "which", lambda _cmd: None)

    with pytest.raises(github_app.GitUnavailableError) as exc:
        github_app._run_git(["git", "--version"], timeout=5)

    assert "git is not installed in the worker image" in str(exc.value)


def test_repo_scanner_reports_missing_sast_binaries_as_skipped(monkeypatch, tmp_path):
    """The SAST replacement pack (Phase 0.1) should treat each missing
    binary as a per-tool skip, not a fatal error. Probes Semgrep
    specifically; the same shape applies to Bandit / gosec / Brakeman /
    ESLint runners since they all wrap ``_run_sast_tool``."""
    from pencheff_api.tasks import repo_scan_task

    monkeypatch.setattr(repo_scan_task, "_which", lambda _cmd: None)

    findings, meta = repo_scan_task._run_semgrep(str(tmp_path), str(tmp_path))

    assert findings == []
    assert meta == {"skipped": "no semgrep binary"}


# ── auto_scan_on_push: off by default, per-repo opt-in ────────────────────

class _FakeWorkspace:
    id = "workspace-1"


class _AsyncNoopSession:
    async def commit(self) -> None:
        pass

    async def refresh(self, _obj) -> None:
        pass


def _app_installed_repo(**overrides) -> Repository:
    """A GitHub-App-installed repo (provider=github, integration_id set)."""
    r = Repository(
        id="repo-1",
        org_id="org-1",
        workspace_id="workspace-1",
        integration_id="integ-1",
        provider="github",
        provider_repo_id="123",
        owner="octo",
        name="r",
        full_name="octo/r",
        default_branch="main",
        private=True,
        html_url="https://github.com/octo/r",
        language="Python",
    )
    r.auto_scan_on_push = False
    r.last_scan_id = None
    r.last_scan_at = None
    r.local_path = None
    for k, v in overrides.items():
        setattr(r, k, v)
    return r


def test_repo_auto_scan_on_push_defaults_off():
    assert Repository.__table__.c.auto_scan_on_push.default.arg is False


def test_patch_auto_scan_allowed_on_app_installed_repo(monkeypatch):
    repo = _app_installed_repo()

    async def fake_load(_session, _repo_id, _ws_id):
        return repo

    monkeypatch.setattr(repos_router, "_load_repo", fake_load)

    out = asyncio.run(
        update_repo(
            "repo-1",
            RepositoryUpdate(auto_scan_on_push=True),
            workspace=_FakeWorkspace(),
            session=_AsyncNoopSession(),
        )
    )

    assert repo.auto_scan_on_push is True
    assert out.auto_scan_on_push is True


def test_patch_drift_field_still_rejected_on_app_installed_repo(monkeypatch):
    repo = _app_installed_repo()

    async def fake_load(_session, _repo_id, _ws_id):
        return repo

    monkeypatch.setattr(repos_router, "_load_repo", fake_load)

    with pytest.raises(HTTPException) as exc:
        asyncio.run(
            update_repo(
                "repo-1",
                RepositoryUpdate(default_branch="dev"),
                workspace=_FakeWorkspace(),
                session=_AsyncNoopSession(),
            )
        )

    assert exc.value.status_code == 400
    # Validation runs before any mutation — branch untouched.
    assert repo.default_branch == "main"
