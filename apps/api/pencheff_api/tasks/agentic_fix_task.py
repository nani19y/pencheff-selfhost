"""Celery task that drives one server-side agentic fix run.

The router (``routers/agentic_fix.py``) creates the AgenticFixRun row
in ``queued`` state and enqueues us with the run id. We:

1. Load the row + verify it's still pending.
2. Materialise the workspace:
   * cloud-provider repos → ``git clone`` into a temp dir
   * local-provider repos → in-place at ``repository.local_path``
     (only valid when the worker host shares the filesystem; rare)
3. Load findings and convert to ``FindingForAgent``.
4. Build callbacks that persist per-step + per-iteration state.
5. Drive ``AgenticFixer.run()``.
6. On success: branch + commit + push + open PR.
7. Persist terminal status + cleanup the temp workspace.

This file owns I/O. The pure agent logic lives in
``services/agentic_fixer/agent_loop.py``.

PR creation (gh CLI + GitHub API fallback) lives in a separate
helper module (``services/agentic_fixer/pr_creator.py``) that ships
in task #38; for now ``_finalize_pr`` is a stub that records the
branch name and returns.
"""
from __future__ import annotations

import asyncio
import logging
import shutil
import tempfile
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import NullPool

from ..config import get_settings
from ..db.models import (
    AgenticFixRun,
    AgenticFixStep,
    AgenticFixUsage,
    AuditLog,
    Finding as DbFinding,
    RepoFinding,
    RepoIntegration,
    RepoScan,
    Repository,
    Scan,
    Target,
    TargetRepository,
)
from ..services import github_app
from ..services.agentic_fixer import (
    AgenticFixer,
    AgentStuck,
    AgentCanceled,
    FindingForAgent,
    IterationOutcome,
)
from ..services.agentic_fixer.cost import Usage, compute_cost_cents
from ..services.agentic_fixer.extra_tools import clear_call_history, clear_todo_state
from ..services.agentic_fixer.file_tools import ToolResult
from ..services.agentic_fixer.pr_creator import (
    PRCreationError,
    build_pr_body,
    create_pr_for_run,
)
from ..services.agentic_fixer.redaction import redact
from .celery_app import celery_app

log = logging.getLogger("pencheff.agentic_fix_task")

# Dedicated worker engine for agentic-fix runs.
#
# Celery invokes ``run_agentic_fix_task`` via ``asyncio.run()``, which
# spins up a fresh event loop per task. SQLAlchemy's default pool caches
# asyncpg connections bound to the loop that first opened them, so the
# second run in a worker process raised
#   RuntimeError: got Future ... attached to a different loop
# (and borrowing the shared ``db.base`` engine made it worse — any other
# task could poison its pool first). NullPool opens + closes a connection
# per checkout, always in the currently-running loop, which is loop-safe
# across asyncio.run() calls. A fix run is minutes long, so per-run
# connection churn is irrelevant.
_settings = get_settings()
_engine = create_async_engine(
    _settings.database_url, poolclass=NullPool, future=True
)
_Session = async_sessionmaker(_engine, expire_on_commit=False, class_=AsyncSession)


@celery_app.task(name="pencheff_api.tasks.agentic_fix_task.run_agentic_fix_task")
def run_agentic_fix_task(run_id: str) -> dict:
    """Sync entry-point Celery invokes. Bridges to the async driver."""
    return asyncio.run(_run_async(run_id))


async def _run_async(run_id: str) -> dict:
    db_factory = _Session
    async with db_factory() as session:
        run = await session.get(AgenticFixRun, run_id)
        if run is None:
            log.error("agentic-fix: run %s not found", run_id)
            return {"ok": False, "reason": "not_found"}
        if run.status not in ("queued",):
            log.warning(
                "agentic-fix: run %s already %s; skipping",
                run_id, run.status,
            )
            return {"ok": False, "reason": "not_queued"}
        if run.runtime != "server":
            log.error(
                "agentic-fix: refusing to run desktop-runtime run %s server-side",
                run_id,
            )
            return {"ok": False, "reason": "wrong_runtime"}

        # Mark started + audit-log the run start so the chain
        # captures kick-off + later terminal flip + every tool call.
        run.status = "cloning"
        run.started_at = datetime.utcnow()
        session.add(AuditLog(
            user_id=run.user_id,
            org_id=run.org_id,
            workspace_id=run.workspace_id,
            action="agentic_fix.run.started",
            entity_type="agentic_fix_run",
            entity_id=run.id,
            meta={
                "runtime": run.runtime,
                "findings_count": run.findings_count,
                "model": run.model,
                "scan_id": run.scan_id,
                "repo_scan_id": run.repo_scan_id,
            },
        ))
        await session.commit()
        await session.refresh(run)

    try:
        async with db_factory() as session:
            ctx = await _materialize_workspace(session, run_id)
        try:
            await _drive_loop(
                db_factory=db_factory,
                run_id=run_id,
                ctx=ctx,
            )
        finally:
            if ctx.cleanup_path is not None and Path(ctx.cleanup_path).exists():
                shutil.rmtree(ctx.cleanup_path, ignore_errors=True)
            # Drop the per-run scratch state — process-local stores
            # for TodoWrite + repeat-call detection.
            clear_todo_state(run_id)
            clear_call_history(run_id)
    except Exception as e:  # noqa: BLE001
        log.exception("agentic-fix run %s failed unexpectedly", run_id)
        async with db_factory() as session:
            row = await session.get(AgenticFixRun, run_id)
            if row is not None and row.status not in ("done", "canceled", "failed"):
                row.status = "failed"
                row.error = f"unexpected: {e!s}"
                row.completed_at = datetime.utcnow()
                await session.commit()
        return {"ok": False, "reason": "unexpected_error"}

    return {"ok": True, "run_id": run_id}


@dataclass(slots=True)
class _RepoContext:
    """All the per-run repo state the rest of the task needs.

    Returned from ``_materialize_workspace`` so the loop driver and
    the PR creator can share the resolved values (token + default
    branch + repo full_name) without re-running the DB lookups.
    """
    findings: list[FindingForAgent]
    repo_full_name: str | None
    default_branch: str | None
    github_token: str | None
    workspace_root: Path
    cleanup_path: str | None
    # True for source="upload" targets: no git remote — the fixer zips the
    # edited tree to R2 (fixes/<run_id>/fixed.zip) instead of opening a PR.
    is_upload: bool = False


async def _materialize_workspace(
    session: AsyncSession,
    run_id: str,
) -> _RepoContext:
    """Resolve the repo + findings for this run and stage the
    workspace.

    For github-provider repos with an integration we mint an
    installation token; for PAT-stored repos we decrypt the stored
    PAT; for public-URL repos we proceed without a token (the agent
    can edit + commit locally but the final push will refuse).

    The clone URL embeds the token so subsequent ``git push`` calls
    from inside the workspace work without further env tinkering.
    """
    run = await session.get(AgenticFixRun, run_id)
    assert run is not None

    if run.scan_id is not None:
        scan = (await session.execute(
            select(Scan).where(Scan.id == run.scan_id)
        )).scalar_one_or_none()
        if scan is None:
            raise RuntimeError("scan vanished mid-run")
        target = await session.get(Target, scan.target_id)
        if target is None:
            raise RuntimeError("target vanished mid-run")

        _cfg = dict(target.kind_config or {})
        if target.kind == "source_code" and _cfg.get("source") == "upload":
            finding_stmt = select(DbFinding).where(
                DbFinding.scan_id == run.scan_id,
                DbFinding.suppressed.is_(False),
            )
            if run.selected_finding_ids is not None:
                finding_stmt = finding_stmt.where(
                    DbFinding.id.in_(run.selected_finding_ids)
                )
            rows = (await session.execute(finding_stmt)).scalars().all()

            def _split_ep(ep: str | None):
                if ep and ":" in ep and ep.rsplit(":", 1)[1].isdigit():
                    p, ln = ep.rsplit(":", 1)
                    return p, int(ln)
                return ep, None

            findings = []
            for r in rows:
                fp, ln = _split_ep(r.endpoint)
                findings.append(FindingForAgent(
                    id=r.id, kind="repo", severity=r.severity, title=r.title,
                    description=r.description or r.remediation,
                    file_path=fp, line_start=ln, line_end=None,
                    code_snippet=None, cve=None, package=None,
                    installed_version=None, fixed_version=None,
                    rule_id=r.owasp_category or r.cwe_id or r.category,
                ))
            return await _materialize_upload_context(_cfg, findings)

        repo_stmt = (
            select(Repository)
            .join(TargetRepository, TargetRepository.repository_id == Repository.id)
            .where(TargetRepository.target_id == target.id)
            .order_by(Repository.full_name)
        )
        if getattr(run, "repository_id", None):
            repo_stmt = repo_stmt.where(Repository.id == run.repository_id)
        repos = (await session.execute(repo_stmt)).scalars().all()
        if not repos:
            raise RuntimeError(
                "agentic-fix: scan target has no attached source repository"
            )
        if len(repos) > 1:
            raise RuntimeError(
                "agentic-fix: scan target has multiple attached repositories; "
                "start the run with repository_id"
            )
        repo = repos[0]

        finding_stmt = select(DbFinding).where(
            DbFinding.scan_id == run.scan_id,
            DbFinding.suppressed.is_(False),
        )
        if run.selected_finding_ids is not None:
            finding_stmt = finding_stmt.where(
                DbFinding.id.in_(run.selected_finding_ids)
            )
        rows = (await session.execute(finding_stmt)).scalars().all()
        findings = [
            FindingForAgent(
                id=r.id,
                kind="dast",
                severity=r.severity,
                title=r.title,
                description=r.description or r.remediation,
                file_path=None,
                line_start=None,
                line_end=None,
                code_snippet=None,
                cve=None,
                package=None,
                installed_version=None,
                fixed_version=None,
                rule_id=r.owasp_category or r.cwe_id or r.category,
            )
            for r in rows
        ]
        return await _materialize_repository_context(repo, findings, session)

    rs = (await session.execute(
        select(RepoScan).where(RepoScan.id == run.repo_scan_id)
    )).scalar_one_or_none()
    if rs is None:
        raise RuntimeError("repo scan vanished mid-run")
    repo = (await session.execute(
        select(Repository).where(Repository.id == rs.repository_id)
    )).scalar_one_or_none()
    if repo is None:
        raise RuntimeError("repo vanished mid-run")

    # Load findings.
    finding_stmt = select(RepoFinding).where(
        RepoFinding.repo_scan_id == run.repo_scan_id,
        RepoFinding.suppressed.is_(False),
    )
    if run.selected_finding_ids is not None:
        finding_stmt = finding_stmt.where(
            RepoFinding.id.in_(run.selected_finding_ids)
        )
    rows = (await session.execute(finding_stmt)).scalars().all()
    findings = [
        FindingForAgent(
            id=r.id, kind="repo", severity=r.severity,
            title=r.title, description=r.description,
            file_path=r.file_path,
            line_start=r.line_start, line_end=r.line_end,
            code_snippet=r.code_snippet,
            cve=r.cve, package=r.package,
            installed_version=r.installed_version,
            fixed_version=r.fixed_version,
            rule_id=r.rule_id,
        )
        for r in rows
    ]

    return await _materialize_repository_context(repo, findings, session)


async def _materialize_upload_context(
    cfg: dict,
    findings: list[FindingForAgent],
) -> _RepoContext:
    """source='upload' target: fetch the archive from R2 and extract it into a
    scratch dir the agent edits in place. No git remote (is_upload=True)."""
    import tempfile

    from starlette.concurrency import run_in_threadpool

    from ..services import upload_storage

    key = cfg.get("upload_key")
    if not key:
        raise RuntimeError("agentic-fix: upload target missing upload_key")
    data = await run_in_threadpool(upload_storage.get_bytes, key)
    scratch = tempfile.mkdtemp(prefix="pencheff-fix-upload-")
    workspace_root = Path(scratch) / "src"
    await run_in_threadpool(upload_storage.extract_archive, data, workspace_root)
    return _RepoContext(
        findings=findings,
        repo_full_name=None,
        default_branch=None,
        github_token=None,
        workspace_root=workspace_root,
        cleanup_path=scratch,
        is_upload=True,
    )


async def _materialize_repository_context(
    repo: Repository,
    findings: list[FindingForAgent],
    session: AsyncSession,
) -> _RepoContext:
    if repo.provider == "local":
        # Server-runtime + local-provider is rejected by the router;
        # this branch is defensive.
        raise RuntimeError(
            "agentic-fix: server runtime cannot operate on local-provider repos"
        )
    if not repo.html_url or "github.com/" not in repo.html_url.lower():
        raise RuntimeError(
            "agentic-fix: only github-hosted repos supported in this build"
        )

    github_token = await _resolve_github_token(session, repo)
    default_branch = repo.default_branch or "main"

    workdir = tempfile.mkdtemp(prefix="pencheff-agentic-fix-")
    cleanup = workdir
    target = Path(workdir) / "src"

    clone_url = repo.html_url
    if github_token:
        clone_url = f"https://x-access-token:{github_token}@github.com/{repo.full_name}.git"

    await _git_clone(clone_url, target, branch=default_branch)

    return _RepoContext(
        findings=findings,
        repo_full_name=repo.full_name,
        default_branch=default_branch,
        github_token=github_token,
        workspace_root=target,
        cleanup_path=cleanup,
    )


async def _resolve_github_token(
    session: AsyncSession, repo: Repository,
) -> str | None:
    """Mint a GitHub installation token if the repo has an integration;
    fall back to a stored PAT; return None for public-URL-only repos.

    Mirrors the pattern in ``services.fix_applier._resolve_github_token`` —
    kept inline here to avoid the layering breakage that would happen
    if we imported from fix_applier (it pulls in scan/finding-specific
    helpers we don't need).
    """
    if repo.integration_id:
        integ = (await session.execute(
            select(RepoIntegration).where(
                RepoIntegration.id == repo.integration_id,
            )
        )).scalar_one_or_none()
        if integ is None:
            log.warning("agentic-fix: integration %s missing for repo %s",
                        repo.integration_id, repo.id)
        else:
            try:
                return await github_app.get_installation_token(integ.installation_id)
            except Exception:  # noqa: BLE001
                log.exception(
                    "agentic-fix: failed to mint installation token for %s",
                    repo.full_name,
                )
                return None

    if getattr(repo, "token_encrypted", None):
        from ..services.credentials import decrypt_credentials
        tok_blob = decrypt_credentials(repo.token_encrypted) or {}
        token = tok_blob.get("token") or ""
        if token:
            return token

    # Public-URL repo without a GitHub App install + no PAT — we can
    # clone but not push. The PR-creation step will surface
    # ``push_failed`` cleanly.
    return None


async def _git_clone(
    clone_url: str,
    into: Path,
    *,
    branch: str | None = None,
) -> None:
    """Shallow-clone ``clone_url`` (may already embed an
    x-access-token) into ``into``. Errors get redacted before being
    surfaced so the token doesn't end up in logs.
    """
    args = ["clone", "--depth=1"]
    if branch:
        args.extend(["--branch", branch])
    args.extend([clone_url, str(into)])
    proc = await asyncio.create_subprocess_exec(
        "git", *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    _out, err = await proc.communicate()
    if proc.returncode != 0:
        raise RuntimeError(
            f"git clone failed: {redact(err.decode('utf-8', errors='replace'))[:400]}"
        )


async def _drive_loop(
    *,
    db_factory,
    run_id: str,
    ctx: _RepoContext,
) -> None:
    """Wire up persistence callbacks then run the agent loop. After
    the agent finishes (and only on success), invoke the PR creator
    against the workspace."""
    settings = get_settings()
    branch_name = f"pencheff/agentic-fix-{run_id[:8]}"
    findings = ctx.findings
    repo_full_name = ctx.repo_full_name
    workspace_root = ctx.workspace_root

    # ── Per-step persistence callback ─────────────────────────────
    async def persist_step(
        iteration: int,
        step_index: int,
        tool_name: str,
        tool_input: dict,
        result: ToolResult,
        duration_ms: int,
    ) -> None:
        # Output may legitimately be very long. Cap to 8 KiB
        # before persisting; full output flows back to the LLM but
        # not into the DB.
        truncated = redact((result.content or "")[:8192])
        async with db_factory() as session:
            row = await session.get(AgenticFixRun, run_id)
            session.add(AgenticFixStep(
                run_id=run_id,
                iteration=iteration,
                step_index=step_index,
                tool_name=tool_name,
                tool_input=tool_input,
                tool_output_truncated=truncated if not result.is_error else None,
                tool_error=truncated if result.is_error else None,
                duration_ms=duration_ms,
            ))
            # Mirror the tool call into AuditLog so the org's
            # compliance trail captures every agentic action.
            # Bash + write/edit are the security-meaningful ones;
            # read/grep/glob are noise but tracking them preserves
            # the full chain for incident review. Tool input is
            # already JSON-safe (it came from the LLM as JSON).
            if row is not None:
                session.add(AuditLog(
                    user_id=row.user_id,
                    org_id=row.org_id,
                    workspace_id=row.workspace_id,
                    action=f"agentic_fix.tool_call.{tool_name}",
                    entity_type="agentic_fix_run",
                    entity_id=run_id,
                    meta={
                        "iteration": iteration,
                        "step_index": step_index,
                        "is_error": result.is_error,
                        "duration_ms": duration_ms,
                        "tool_input": tool_input,
                    },
                ))
            await session.commit()

    # ── Per-iteration persistence callback ────────────────────────
    async def persist_iteration(outcome: IterationOutcome) -> None:
        cents = compute_cost_cents(outcome.usage, settings.agentic_fix_effective_model)
        async with db_factory() as session:
            session.add(AgenticFixUsage(
                run_id=run_id,
                workspace_id=(await session.get(AgenticFixRun, run_id)).workspace_id,
                iteration=outcome.iteration,
                model=settings.agentic_fix_effective_model,
                input_tokens=outcome.usage.input_tokens,
                output_tokens=outcome.usage.output_tokens,
                cache_read_input_tokens=outcome.usage.cache_read_input_tokens,
                cache_creation_input_tokens=outcome.usage.cache_creation_input_tokens,
                cost_usd_cents=cents,
            ))
            row = await session.get(AgenticFixRun, run_id)
            if row is not None:
                row.iterations = outcome.iteration
                row.current_step = (
                    f"iter {outcome.iteration}: "
                    f"{len(outcome.tool_calls)} tool call(s), "
                    f"stop={outcome.stop_reason}"
                )
                # Once we've had at least one iteration, status moves
                # from cloning → running.
                if row.status == "cloning":
                    row.status = "running"
            await session.commit()

    # ── Cancellation check ────────────────────────────────────────
    async def is_canceled() -> bool:
        async with db_factory() as session:
            row = await session.get(AgenticFixRun, run_id)
            if row is None:
                return True
            if row.cancel_requested:
                return True
            return False

    # ── BYO provider override (OpenAI-compatible only) ───────────────
    # If the org has an active LlmProvider and it is OpenAI-tool-calling
    # compatible (openai / openai_compatible / azure_openai), point the
    # agentic-fixer client at it. Anthropic/Gemini providers return False
    # and Pencheff's own key stays in effect (documented limitation: the
    # loop uses OpenAI-shaped tool calling, so native Anthropic/Gemini
    # adapters cannot be honoured here).
    from ..db.models import LlmProvider, Org
    from ..services.agentic_fixer.llm_client import get_client as _get_af_client
    try:
        async with db_factory() as session:
            _run_row = await session.get(AgenticFixRun, run_id)
            _org = await session.get(Org, _run_row.org_id) if _run_row else None
            _prov_id = _org.active_llm_provider_id if _org else None
            _prov = await session.get(LlmProvider, _prov_id) if _prov_id else None
        _overridden = _get_af_client().maybe_override_from_provider(_prov)
        if _prov is not None:
            log.info(
                "agentic-fix run %s: BYO provider '%s/%s' override=%s",
                run_id, _prov.provider, _prov.model, _overridden,
            )
    except Exception:  # noqa: BLE001
        log.warning(
            "agentic-fix run %s: failed to load BYO provider; "
            "falling back to Pencheff default",
            run_id, exc_info=True,
        )

    fixer = AgenticFixer(
        workspace_root=workspace_root,
        branch_name=branch_name,
        repo_full_name=repo_full_name,
        runtime="server",
        findings=findings,
        run_id=run_id,
        on_step=persist_step,
        on_iteration=persist_iteration,
        cancel_cb=is_canceled,
    )

    # Run the loop. Cancellation + hard-stops are NOT fatal — we
    # still attempt PR creation so any edits the agent already made
    # are preserved as a real commit + PR. ``early_stop_reason``
    # captures why the loop ended; the PR body / current_step
    # surfaces it alongside whatever fixes did land.
    early_stop_reason: str | None = None
    try:
        final_text = await fixer.run()
    except AgentCanceled:
        final_text = "[Run canceled by user.]"
        early_stop_reason = "canceled"
    except AgentStuck as e:
        final_text = f"[Run stopped early: {e}]"
        early_stop_reason = f"stopped_early: {e}"

    # ── source="upload": no git remote — zip the edited tree to R2 ──────────
    if ctx.is_upload:
        from starlette.concurrency import run_in_threadpool

        from ..services import upload_storage

        async with db_factory() as session:
            row = await session.get(AgenticFixRun, run_id)
            if row is not None:
                row.status = "committing"
                row.current_step = "packaging fixed files"
                await session.commit()
        try:
            zipped = await run_in_threadpool(
                upload_storage.zip_dir, str(workspace_root)
            )
            await run_in_threadpool(
                upload_storage.put_bytes,
                f"fixes/{run_id}/fixed.zip",
                zipped,
                "application/zip",
            )
        except Exception as e:  # noqa: BLE001
            async with db_factory() as session:
                row = await session.get(AgenticFixRun, run_id)
                if row is not None:
                    row.status = "failed"
                    row.error = f"fixed-zip packaging failed: {e!s}"
                    row.completed_at = datetime.utcnow()
                    await session.commit()
            return
        async with db_factory() as session:
            row = await session.get(AgenticFixRun, run_id)
            if row is not None:
                row.status = "done"
                row.current_step = (
                    "agent finished — fixed .zip ready to download"
                    if early_stop_reason is None
                    else f"{early_stop_reason}; fixed .zip ready to download"
                )
                row.completed_at = datetime.utcnow()
                await session.commit()
        return

    # Agent loop done — drive PR creation.
    async with db_factory() as session:
        row = await session.get(AgenticFixRun, run_id)
        if row is not None:
            row.branch_name = branch_name
            row.status = "committing"
            row.current_step = "staging changes + creating PR"
            await session.commit()

    if not ctx.github_token:
        # The agent made code changes locally but we have no push
        # credentials. Mark done-without-PR so the user can pull the
        # branch from the worker (we leave it in the workspace until
        # the temp dir is cleaned up).
        async with db_factory() as session:
            row = await session.get(AgenticFixRun, run_id)
            if row is not None:
                row.status = "done"
                row.current_step = (
                    "agent finished, but no push token was available "
                    "(public-URL repo without GitHub App / PAT). "
                    "Re-register the repo with a PAT or via the "
                    "Pencheff GitHub App to enable PR creation."
                )
                row.completed_at = datetime.utcnow()
                await session.commit()
        log.warning(
            "agentic-fix run %s ended without push credentials; "
            "agent text length=%d",
            run_id, len(final_text or ""),
        )
        return

    if not repo_full_name or not ctx.default_branch:
        # Shouldn't happen — _materialize_workspace would have
        # raised — but guard for safety.
        raise RuntimeError("agentic-fix: missing repo_full_name or default_branch")

    try:
        scan_id = None
        repo_scan_id = None
        async with db_factory() as session:
            row = await session.get(AgenticFixRun, run_id)
            if row is not None:
                scan_id = row.scan_id
                repo_scan_id = row.repo_scan_id

        pr_title = (
            f"Pencheff Agent: security fixes for "
            f"{repo_scan_id[:8] if repo_scan_id else scan_id[:8] if scan_id else 'scan'}"
        )
        iterations = await _read_iteration_count(db_factory, run_id)
        pr_body = build_pr_body(
            scan_id=scan_id,
            repo_scan_id=repo_scan_id,
            findings_count=len(findings),
            iterations=iterations,
            final_text=final_text,
            workspace_root_label=repo_full_name,
        )

        async with db_factory() as session:
            row = await session.get(AgenticFixRun, run_id)
            if row is not None:
                row.status = "pushing"
                await session.commit()

        result = await create_pr_for_run(
            workspace_root=workspace_root,
            branch_name=branch_name,
            repo_full_name=repo_full_name,
            default_branch=ctx.default_branch,
            github_token=ctx.github_token,
            pr_title=pr_title,
            pr_body=pr_body,
        )
    except PRCreationError as e:
        log.warning("agentic-fix run %s PR creation failed: %s", run_id, e)
        async with db_factory() as session:
            row = await session.get(AgenticFixRun, run_id)
            if row is not None:
                # PRCreationError.code == "no_changes" means the
                # agent didn't actually edit anything. Surface the
                # early-stop reason (canceled / stopped_early /
                # model_stuck) instead of the generic git message
                # when present — that's what the user actually
                # cares about.
                if e.code == "no_changes":
                    if early_stop_reason == "canceled":
                        row.status = "canceled"
                        row.error = "canceled by user (no edits had been made yet)"
                    elif early_stop_reason is not None:
                        row.status = "failed"
                        row.error = early_stop_reason
                    else:
                        row.status = "failed"
                        row.error = "agent made no code changes"
                else:
                    row.status = "failed"
                    row.error = f"pr_creation_failed: {e.code}: {e.message[:400]}"
                row.completed_at = datetime.utcnow()
                await session.commit()
        return

    # PR opened — even if we stopped early. Surface the stop reason
    # in current_step so the UI shows e.g. "stopped early
    # (model_stuck...): opened PR <url>" rather than hiding the
    # caveat.
    summary = result.summary
    if early_stop_reason is not None:
        summary = (
            f"stopped early ({early_stop_reason}) — partial fixes saved. "
            f"{result.summary}"
        )
    async with db_factory() as session:
        row = await session.get(AgenticFixRun, run_id)
        if row is not None:
            row.status = "done"
            row.branch_name = result.branch_name
            row.pr_url = result.pr_url
            row.current_step = summary
            row.completed_at = datetime.utcnow()
            await session.commit()
    log.info(
        "agentic-fix run %s done; PR=%s; final text length=%d; "
        "early_stop=%s",
        run_id, result.pr_url, len(final_text or ""), early_stop_reason,
    )


async def _read_iteration_count(db_factory, run_id: str) -> int:
    """Reach into the row to get the latest persisted iteration count
    (the agent loop already commits it via persist_iteration). Used
    by the PR body builder.
    """
    async with db_factory() as session:
        row = await session.get(AgenticFixRun, run_id)
        return row.iterations if row else 0
