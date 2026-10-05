from __future__ import annotations

import datetime as dt
from pathlib import Path

import pytest

from pencheff_api.db.models import AgenticFixRun, Finding, Repository, Scan, Target
from pencheff_api.tasks import agentic_fix_task


class _ScalarRows:
    def __init__(self, rows: list[object]) -> None:
        self._rows = rows

    def all(self) -> list[object]:
        return self._rows


class _Result:
    def __init__(self, rows: list[object]) -> None:
        self._rows = rows

    def scalar_one_or_none(self):
        return self._rows[0] if self._rows else None

    def scalars(self) -> _ScalarRows:
        return _ScalarRows(self._rows)


class _FakeSession:
    def __init__(
        self,
        *,
        run: AgenticFixRun,
        scan: Scan,
        target: Target,
        repos: list[Repository],
        findings: list[Finding],
    ) -> None:
        self.run = run
        self.scan = scan
        self.target = target
        self.repos = repos
        self.findings = findings
        self.execute_calls = 0

    async def get(self, model_cls, pk):
        if model_cls is AgenticFixRun and pk == self.run.id:
            return self.run
        if model_cls is Target and pk == self.target.id:
            return self.target
        return None

    async def execute(self, _stmt):
        self.execute_calls += 1
        if self.execute_calls == 1:
            return _Result([self.scan])
        if self.execute_calls == 2:
            return _Result(self.repos)
        if self.execute_calls == 3:
            return _Result(self.findings)
        return _Result([])


def _run() -> AgenticFixRun:
    return AgenticFixRun(
        id="run-1",
        org_id="org-1",
        workspace_id="workspace-1",
        user_id="user-1",
        scan_id="scan-1",
        repo_scan_id=None,
        runtime="server",
        status="queued",
        findings_count=1,
        iterations=0,
        model="test-model",
        max_iterations=30,
    )


def _scan(target: Target) -> Scan:
    return Scan(
        id="scan-1",
        org_id="org-1",
        workspace_id="workspace-1",
        user_id="user-1",
        target_id=target.id,
        profile="standard",
        status="done",
        progress_pct=100,
        current_stage="complete",
        summary={"critical": 1},
        score=75,
        grade="C",
        created_at=dt.datetime.now(dt.timezone.utc),
    )


def _target() -> Target:
    return Target(
        id="target-1",
        org_id="org-1",
        workspace_id="workspace-1",
        user_id="user-1",
        name="Sarvam",
        base_url="https://api.sarvam.ai/v1/chat/completions",
        kind="llm",
        llm_config={"provider": "custom", "model": "sarvam-m"},
        repository_id=None,
        created_at=dt.datetime.now(dt.timezone.utc),
    )


def _repo() -> Repository:
    return Repository(
        id="repo-1",
        org_id="org-1",
        workspace_id="workspace-1",
        provider="github",
        full_name="acme/chat-service",
        html_url="https://github.com/acme/chat-service",
        default_branch="main",
        created_at=dt.datetime.now(dt.timezone.utc),
    )


def _finding() -> Finding:
    return Finding(
        id="finding-1",
        scan_id="scan-1",
        title="Prompt overrides host system prompt",
        severity="critical",
        category="llm06",
        owasp_category="LLM06",
        endpoint="https://api.sarvam.ai/v1/chat/completions",
        parameter=None,
        description="The target accepts a hostile instruction override.",
        remediation="Keep system policy server-side and reject hostile instructions.",
        suppressed=False,
        verification_status="unverified",
    )


@pytest.mark.asyncio
async def test_scan_agentic_fix_materializes_exactly_one_attached_repo(monkeypatch) -> None:
    target = _target()
    run = _run()
    session = _FakeSession(
        run=run,
        scan=_scan(target),
        target=target,
        repos=[_repo()],
        findings=[_finding()],
    )

    cloned: dict[str, object] = {}

    async def fake_git_clone(clone_url: str, into: Path, *, branch: str | None = None) -> None:
        cloned["url"] = clone_url
        cloned["branch"] = branch
        into.mkdir(parents=True, exist_ok=True)

    monkeypatch.setattr(agentic_fix_task, "_git_clone", fake_git_clone)

    ctx = await agentic_fix_task._materialize_workspace(session, run.id)

    assert ctx.repo_full_name == "acme/chat-service"
    assert ctx.default_branch == "main"
    assert cloned == {
        "url": "https://github.com/acme/chat-service",
        "branch": "main",
    }
    assert [f.kind for f in ctx.findings] == ["dast"]
    assert ctx.findings[0].title == "Prompt overrides host system prompt"
