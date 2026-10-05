"""Engine for the async bulk-fix-all flow.

Moved out of ``routers/fix_proposals.py`` so the Celery worker can run
the same logic without dragging the FastAPI router (and its auth deps)
into the worker process.

The router enqueues a ``BulkFixTask`` row and a Celery job; the worker
calls :func:`run_bulk_fix_engine` here. The engine writes proposals,
applies them grouped by repo, and emits per-finding progress through
the optional ``progress_cb`` so the polling endpoint can show "M / N
findings processed" without any Celery-result-backend coupling.

Per-finding skip/fail policy (the kind-aware silent-skip set) lives
here too — it's the engine's call which proposer errors are real
failures vs. "no code anchor in the attached repos" noise.
"""
from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable

from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db.models import FixProposal, User, Workspace
from . import fix_applier, fix_proposer, fix_quota

log = logging.getLogger(__name__)


# Codes that mean "this finding has no source-code home in the
# attached repos" — kind-aware because ``llm_failed`` only correlates
# with no-anchor on DAST.
#
# DAST: ``route_index`` falls back to README.md / LICENSE when no real
#       handler matches the live URL → the LLM bails or hallucinates →
#       ``llm_failed``. Treating it as silent matches user intent
#       ("don't show findings with no code home as failures").
# SAST: scanner already gave us a real source-code file. ``llm_failed``
#       is a genuine LLM error (timeout, bad response, rate-limit) on
#       a patchable file — surface it so the user can act.
_NO_CODE_ANCHOR_KIND_AGNOSTIC = frozenset({
    "no_code_anchor",
    "no_handler_file",
    "no_provenance",
    "empty_repo",
})

_BULK_SILENT_CODES_BY_KIND: dict[str, frozenset[str]] = {
    "dast": _NO_CODE_ANCHOR_KIND_AGNOSTIC | frozenset({"llm_failed"}),
    "sast": _NO_CODE_ANCHOR_KIND_AGNOSTIC,
}


class BulkFixResultOut(BaseModel):
    """One row per repository the bulk request touched."""
    repository_id: str | None = None
    ok: bool = True
    proposal_ids: list[str] = Field(default_factory=list)
    branch_name: str | None = None
    commit_sha: str | None = None
    pr_url: str | None = None
    error: str | None = None


class BulkFixSummary(BaseModel):
    proposals_total: int
    proposals_failed: int
    results: list[BulkFixResultOut]


# (completed_count, total) → coroutine. Runs in the same loop as the
# engine; the typical implementation updates a tracker row in the DB.
ProgressCallback = Callable[[int, int], Awaitable[None]]


class BulkFixCancelled(Exception):
    pass


CancelCallback = Callable[[], Awaitable[bool]]


async def run_bulk_fix_engine(
    *,
    session: AsyncSession,
    workspace: Workspace,
    user: User,
    findings: list[tuple[str, str, str | None, str | None]],
    progress_cb: ProgressCallback | None = None,
    cancel_cb: CancelCallback | None = None,
) -> BulkFixSummary:
    """Generate a draft proposal for each finding, apply them grouped
    by repository, return the summary.

    ``findings`` is a list of ``(finding_kind, finding_id, scan_id,
    repo_scan_id)`` tuples — the router resolves which findings belong
    to a given scan / repo-scan and hands them in bulk.

    Calls ``progress_cb(completed, total)`` after each finding is
    processed (skipped, succeeded, or failed). The callback is allowed
    to commit on its own session; it should NOT use this engine's
    session, which is mid-transaction.
    """
    drafts: list[FixProposal] = []
    failures: list[BulkFixResultOut] = []
    total = len(findings)

    for idx, (kind, fid, scan_id, repo_scan_id) in enumerate(findings, start=1):
        if cancel_cb and await cancel_cb():
            raise BulkFixCancelled()
        # Skip findings that already have an applied (non-superseded)
        # proposal — re-running fix-all shouldn't churn the same finding.
        existing = (await session.execute(
            select(FixProposal).where(
                FixProposal.finding_kind == kind,
                FixProposal.finding_id == fid,
                FixProposal.org_id == workspace.org_id,
                FixProposal.status == "applied",
            )
        )).scalar_one_or_none()
        if existing is not None:
            if progress_cb:
                await progress_cb(idx, total)
            continue

        # Drop any prior drafts so the bulk pass owns this finding.
        prior_drafts = (await session.execute(
            select(FixProposal).where(
                FixProposal.finding_kind == kind,
                FixProposal.finding_id == fid,
                FixProposal.org_id == workspace.org_id,
                FixProposal.status == "draft",
            )
        )).scalars().all()
        for pd in prior_drafts:
            pd.status = "superseded"

        req = fix_proposer.ProposalRequest(
            org_id=workspace.org_id, workspace_id=workspace.id,
            user_id=user.id, finding_kind=kind, finding_id=fid,
            scan_id=scan_id, repo_scan_id=repo_scan_id,
            allow_payg=True,  # bulk implies the user accepts any LLM cost
        )
        try:
            proposal, _notice = await fix_proposer.propose_fix(session, req)
            drafts.append(proposal)
        except (fix_proposer.ProposerError, fix_quota.QuotaExceeded) as exc:
            code = getattr(exc, "code", "error")
            silent_codes = _BULK_SILENT_CODES_BY_KIND.get(kind, frozenset())
            if isinstance(exc, fix_proposer.ProposerError) \
                    and code in silent_codes:
                log.info(
                    "bulk fix: skipping %s finding %s silently (code=%s) — "
                    "no source-code anchor in attached repos.",
                    kind, fid, code,
                )
            else:
                failures.append(BulkFixResultOut(
                    ok=False,
                    proposal_ids=[fid],
                    error=f"{code}: {getattr(exc, 'message', str(exc))}",
                ))
        except Exception as exc:  # noqa: BLE001
            failures.append(BulkFixResultOut(
                ok=False, proposal_ids=[fid],
                error=f"unexpected: {exc!s}",
            ))

        if progress_cb:
            await progress_cb(idx, total)

    # Flush proposals so apply_bulk sees them via the same session.
    await session.flush()

    apply_results: list[BulkFixResultOut] = []
    if drafts:
        if cancel_cb and await cancel_cb():
            raise BulkFixCancelled()
        for r in await fix_applier.apply_bulk(session, drafts):
            apply_results.append(BulkFixResultOut(
                repository_id=r.get("repository_id"),
                ok=r.get("ok", False),
                proposal_ids=list(r.get("proposal_ids") or []),
                branch_name=r.get("branch_name"),
                commit_sha=r.get("commit_sha"),
                pr_url=r.get("pr_url"),
                error=r.get("error"),
            ))
    await session.commit()

    proposals_failed = sum(1 for r in apply_results if not r.ok) + len(failures)
    return BulkFixSummary(
        proposals_total=len(drafts) + len(failures),
        proposals_failed=proposals_failed,
        results=apply_results + failures,
    )
