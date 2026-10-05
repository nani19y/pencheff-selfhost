"""Apply a draft FixProposal to the upstream repository.

Strategy (locked with the user):
  * **Always** create a branch + commit. Never overwrite the main working
    tree silently.
  * GitHub-backed repos (App-installed or PAT) get a real PR opened
    against the default branch.
  * Local-path repos: branch + commit live in the worktree; we do not
    push, since there's no remote we control. The proposal carries the
    branch name so the developer can `git push -u` themselves.

The applier is best-effort: any failure marks the proposal as ``failed``
with an error message and never half-applies state.
"""
from __future__ import annotations

import asyncio
import logging
import os
import re
import secrets
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db.models import FixProposal, Repository
from . import github_app
from .credentials import decrypt_credentials

log = logging.getLogger(__name__)

GITHUB_API = "https://api.github.com"


class ApplyError(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _branch_name(proposal_id: str) -> str:
    return f"pencheff/fix-{proposal_id[:8]}-{secrets.token_hex(2)}"


async def _run(cmd: list[str], cwd: Path | None = None, env: dict | None = None) -> tuple[int, str, str]:
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        cwd=str(cwd) if cwd else None,
        env={**os.environ, **(env or {})},
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    out, err = await proc.communicate()
    return (
        proc.returncode or 0,
        out.decode(errors="replace"),
        err.decode(errors="replace"),
    )


async def _git_apply(repo_root: Path, diff: str) -> None:
    """Apply a unified diff with progressive permissiveness.

    LLMs reliably hallucinate three things in unified diffs:
      * line counts in ``@@ -X,Y +A,B @@`` headers
      * whitespace (tabs vs spaces, trailing spaces)
      * context lines that are *almost* right but off by a character

    Strict ``git apply`` rejects all three. We try four flag sets, each
    forgiving more, and stop on the first that applies cleanly. The
    final attempt is ``--3way`` which falls back to a merge — handles
    "patch was written against a slightly different file" cases.
    """
    diff = _clean_llm_diff(diff)

    # Try in order of strictness. Each entry's flags pass ``--check``
    # first to validate before mutating the tree.
    attempts: list[tuple[str, list[str]]] = [
        ("strict",
            ["--unsafe-paths"]),
        ("recount + whitespace-fix",
            ["--unsafe-paths", "--recount",
             "--whitespace=fix", "--ignore-whitespace"]),
        ("recount + ignore context whitespace",
            ["--unsafe-paths", "--recount", "--ignore-space-change",
             "--whitespace=fix"]),
        ("3-way merge fallback",
            ["--unsafe-paths", "--3way",
             "--whitespace=fix"]),
    ]

    last_err = ""
    for label, flags in attempts:
        # Validate first.
        check_cmd = ["git", "apply", "--check", *flags, "-"]
        rc, _out, err = await _run_with_stdin(check_cmd, diff, cwd=repo_root)
        if rc != 0:
            last_err = err.strip()
            continue
        # Validation passed → actually apply.
        apply_cmd = ["git", "apply", *flags, "-"]
        rc, _out, err = await _run_with_stdin(apply_cmd, diff, cwd=repo_root)
        if rc == 0:
            return  # success
        last_err = err.strip()
        # Apply failed even though check passed — extremely rare, but
        # could happen with --3way when the merge has conflicts. Roll
        # back any partial application before trying the next variant.
        await _run(["git", "checkout", "--", "."], cwd=repo_root)

    # Every attempt failed. Surface the LAST error since the most
    # permissive flag set is the most informative when it fails.
    raise ApplyError(
        "patch_failed",
        f"git apply rejected the diff after 4 progressively-permissive "
        f"attempts. Last error:\n{last_err or '(no stderr)'}",
    )


_LLM_INDEX_LINE = re.compile(r"^index [0-9a-f]{6,}\.\.[0-9a-f]{6,}.*$",
                             re.IGNORECASE | re.MULTILINE)


_HUNK_HEADER_RX_INTERNAL = re.compile(
    r"^@@ -\d+(?:,\d+)? \+\d+(?:,\d+)? @@"
)


def _clean_llm_diff(diff: str) -> str:
    """Repair the three most common LLM diff hallucinations before
    handing the patch to ``git apply``.

    1. ``index abc1234..def5678 100644`` lines with fake SHAs. Git apply
       tolerates these when correctly formatted, but LLMs sometimes emit
       them with extra spaces / wrong field counts that break the
       parser.
    2. Leading prose / markdown / "Here's your diff:" preamble before
       the first ``diff --git`` or ``---`` header.
    3. **Bare empty lines inside hunks.** Per the unified-diff spec,
       blank context lines must start with a single space. LLMs
       routinely emit truly-empty lines, which git interprets as
       end-of-hunk and reports as ``corrupt patch at line N``. We
       prepend a space to any totally-empty line that appears between
       a hunk header and the next file/hunk boundary.
    """
    if not diff:
        return diff
    cleaned = _LLM_INDEX_LINE.sub("", diff)
    lines = cleaned.splitlines()
    # Drop any leading prose before the first ``diff --git`` or ``---``
    # line.
    start = 0
    for i, line in enumerate(lines):
        if line.startswith(("diff --git ", "--- ", "Index: ")):
            start = i
            break
    body = lines[start:]

    # Now walk the body and fix bare-empty lines inside hunks.
    out: list[str] = []
    in_hunk = False
    for raw in body:
        if _HUNK_HEADER_RX_INTERNAL.match(raw):
            in_hunk = True
            out.append(raw)
            continue
        if raw.startswith("diff --git ") or raw.startswith("--- ") \
                or raw.startswith("+++ "):
            in_hunk = False
            out.append(raw)
            continue
        if in_hunk and raw == "":
            # Bare empty line in a hunk context — repair to " "
            # (single-space-prefixed empty context line).
            out.append(" ")
            continue
        out.append(raw)
    return "\n".join(out) + "\n"


async def _run_with_stdin(
    cmd: list[str], stdin_text: str, cwd: Path | None = None,
) -> tuple[int, str, str]:
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        cwd=str(cwd) if cwd else None,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    out, err = await proc.communicate(input=stdin_text.encode())
    return (
        proc.returncode or 0,
        out.decode(errors="replace"),
        err.decode(errors="replace"),
    )


# ── Local-path branch (no remote) ───────────────────────────────────


async def _apply_local(repo: Repository, proposal: FixProposal) -> dict:
    if not repo.local_path:
        raise ApplyError("no_local_path", "Local-provider repo has no local_path.")
    root = Path(repo.local_path).expanduser().resolve()
    if not (root / ".git").exists():
        raise ApplyError(
            "not_a_git_repo",
            f"Local repo at {root} is not a git working tree.",
        )

    # Refuse if the working tree is dirty — we won't stomp on uncommitted work.
    rc, out, err = await _run(["git", "status", "--porcelain"], cwd=root)
    if rc != 0:
        raise ApplyError("git_status_failed", err.strip() or "git status failed")
    if out.strip():
        raise ApplyError(
            "dirty_worktree",
            "Local repo has uncommitted changes. Stash or commit them and retry.",
        )

    # Capture the current HEAD so we can branch off it cleanly.
    rc, head, err = await _run(["git", "rev-parse", "HEAD"], cwd=root)
    if rc != 0:
        raise ApplyError("git_rev_parse_failed", err.strip())
    base_sha = head.strip()
    branch = _branch_name(proposal.id)

    rc, _o, err = await _run(["git", "checkout", "-b", branch], cwd=root)
    if rc != 0:
        raise ApplyError("checkout_failed", err.strip())
    try:
        await _git_apply(root, proposal.diff)
        rc, _o, err = await _run(["git", "add", "-A"], cwd=root)
        if rc != 0:
            raise ApplyError("git_add_failed", err.strip())
        commit_msg = (
            f"pencheff: fix for finding {proposal.finding_id[:8]}\n\n"
            f"Source: {proposal.source} · Kind: {proposal.finding_kind}.\n"
            "Generated by Pencheff fix proposer."
        )
        rc, _o, err = await _run(
            ["git", "-c", "user.name=Pencheff", "-c", "user.email=fix@pencheff.com",
             "commit", "-m", commit_msg],
            cwd=root,
        )
        if rc != 0:
            raise ApplyError("git_commit_failed", err.strip())
        rc, sha, err = await _run(["git", "rev-parse", "HEAD"], cwd=root)
        if rc != 0:
            raise ApplyError("git_rev_parse_failed", err.strip())
        # Switch back so the branch sits there waiting for `git push`.
        await _run(["git", "checkout", "-"], cwd=root)
        return {
            "branch_name": branch,
            "commit_sha": sha.strip(),
            "pr_url": None,  # local — no remote
        }
    except ApplyError:
        # Roll back the branch checkout to leave the repo clean.
        await _run(["git", "checkout", "-"], cwd=root)
        await _run(["git", "branch", "-D", branch], cwd=root)
        raise


# ── GitHub branch + PR ──────────────────────────────────────────────


async def _resolve_github_token(repo: Repository) -> str:
    if repo.integration_id:
        from sqlalchemy import select
        from ..db.models import RepoIntegration
        # Caller passes the session in; pull integration_id eagerly.
        # We re-fetch via the same helper used in scan_runner to avoid
        # an extra round-trip from the caller.
        # Note: this function is async-but-stateless; the DB lookup is
        # done by the caller and the installation_id is the only thing we
        # need here. To keep the applier transactional, the caller resolves
        # the token via _resolve_github_token_for(integration_id) below.
        raise RuntimeError("internal: use _resolve_github_token_for_integration instead")
    if repo.token_encrypted:
        tok_blob = decrypt_credentials(repo.token_encrypted) or {}
        token = tok_blob.get("token") or ""
        if not token:
            raise ApplyError("no_token", "Stored PAT decrypted to empty string.")
        return token
    raise ApplyError("public_repo_no_auth",
                     "Cannot push to a public-clone repo without a token. "
                     "Re-register with a PAT or via the GitHub App.")


async def _resolve_github_token_for_integration(installation_id: str | None) -> str:
    if not installation_id:
        raise ApplyError("no_integration", "GitHub App integration is missing.")
    return await github_app.get_installation_token(installation_id)


async def _apply_github(
    db: AsyncSession,
    repo: Repository,
    proposal: FixProposal,
) -> dict:
    """Clone fresh, apply the diff, push the branch, open a PR via REST."""
    if repo.integration_id:
        from sqlalchemy import select
        from ..db.models import RepoIntegration
        integ = (await db.execute(
            select(RepoIntegration).where(RepoIntegration.id == repo.integration_id)
        )).scalar_one_or_none()
        if integ is None:
            raise ApplyError("no_integration", "Linked GitHub integration is missing.")
        token = await _resolve_github_token_for_integration(integ.installation_id)
    else:
        token = await _resolve_github_token(repo)

    workdir = Path(tempfile.mkdtemp(prefix="pencheff-fix-"))
    try:
        clone_url = f"https://x-access-token:{token}@github.com/{repo.full_name}.git"
        rc, _o, err = await _run(
            ["git", "clone", "--depth", "1", "--branch", repo.default_branch,
             clone_url, str(workdir / "src")],
        )
        if rc != 0:
            raise ApplyError("clone_failed", err.strip())
        root = workdir / "src"

        rc, head, err = await _run(["git", "rev-parse", "HEAD"], cwd=root)
        if rc != 0:
            raise ApplyError("git_rev_parse_failed", err.strip())
        base_sha = head.strip()
        branch = _branch_name(proposal.id)

        rc, _o, err = await _run(["git", "checkout", "-b", branch], cwd=root)
        if rc != 0:
            raise ApplyError("checkout_failed", err.strip())

        await _git_apply(root, proposal.diff)
        rc, _o, err = await _run(["git", "add", "-A"], cwd=root)
        if rc != 0:
            raise ApplyError("git_add_failed", err.strip())
        commit_msg = (
            f"pencheff: fix for finding {proposal.finding_id[:8]}\n\n"
            f"Source: {proposal.source} · Kind: {proposal.finding_kind}."
        )
        rc, _o, err = await _run(
            ["git", "-c", "user.name=Pencheff[bot]",
             "-c", "user.email=fix@pencheff.com",
             "commit", "-m", commit_msg],
            cwd=root,
        )
        if rc != 0:
            raise ApplyError("git_commit_failed", err.strip())
        rc, sha, err = await _run(["git", "rev-parse", "HEAD"], cwd=root)
        if rc != 0:
            raise ApplyError("git_rev_parse_failed", err.strip())
        commit_sha = sha.strip()

        rc, _o, err = await _run(
            ["git", "push", "-u", "origin", branch], cwd=root,
        )
        if rc != 0:
            raise ApplyError("push_failed", err.strip())

        # Open the PR.
        owner, name = repo.full_name.split("/", 1)
        pr_title = f"Pencheff fix: {proposal.finding_kind.upper()} #{proposal.finding_id[:8]}"
        pr_body = _format_pr_body(proposal)
        async with httpx.AsyncClient(timeout=30.0) as c:
            r = await c.post(
                f"{GITHUB_API}/repos/{owner}/{name}/pulls",
                headers={
                    "Authorization": f"Bearer {token}",
                    "Accept": "application/vnd.github+json",
                    "X-GitHub-Api-Version": "2022-11-28",
                },
                json={
                    "title": pr_title,
                    "head": branch,
                    "base": repo.default_branch,
                    "body": pr_body,
                    "maintainer_can_modify": True,
                },
            )
        if r.status_code >= 400:
            raise ApplyError("pr_create_failed",
                             f"GitHub returned {r.status_code}: {r.text[:300]}")
        pr_url = r.json().get("html_url")
        return {"branch_name": branch, "commit_sha": commit_sha, "pr_url": pr_url}
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def _format_pr_body(proposal: FixProposal) -> str:
    bits = [
        "Auto-generated by Pencheff to remediate a security finding.",
        "",
        f"- **Kind:** {proposal.finding_kind.upper()}",
        f"- **Source:** {proposal.source}",
        f"- **Finding ID:** `{proposal.finding_id}`",
    ]
    if proposal.provenance_confidence is not None:
        bits.append(f"- **Provenance confidence:** {proposal.provenance_confidence:.0%}")
        if proposal.provenance_reasoning:
            bits.append(f"- **Reasoning:** {proposal.provenance_reasoning}")
    if proposal.error:
        bits.append(f"\n> ⚠️ {proposal.error}\n")
    bits.append("\n---\nReview the diff carefully before merging.")
    return "\n".join(bits)


# ── Top-level entrypoint ────────────────────────────────────────────


async def apply_proposal(
    db: AsyncSession,
    proposal: FixProposal,
    repo: Repository,
) -> dict:
    """Apply ``proposal`` to ``repo``. Updates the proposal row in place
    (caller commits) with branch / commit / PR pointers. Returns the same
    pointer dict for convenience.
    """
    if proposal.status == "applied":
        raise ApplyError("already_applied",
                         "Proposal was already applied to a branch/PR.")

    try:
        if repo.provider == "local":
            result = await _apply_local(repo, proposal)
        elif repo.provider == "github":
            result = await _apply_github(db, repo, proposal)
        else:
            raise ApplyError("unsupported_provider",
                             f"Unsupported provider: {repo.provider}")
    except ApplyError as exc:
        proposal.status = "failed"
        proposal.error = f"{exc.code}: {exc}"
        await db.flush()
        raise

    proposal.status = "applied"
    proposal.branch_name = result["branch_name"]
    proposal.commit_sha = result["commit_sha"]
    proposal.pr_url = result["pr_url"]
    proposal.applied_at = datetime.now(timezone.utc)
    await db.flush()
    return result


# ── Revert (close PR + delete branch) ──────────────────────────────


async def revert_proposal(
    db: AsyncSession,
    proposal: FixProposal,
    repo: Repository,
) -> None:
    """Undo an applied proposal: close the PR, delete the branch, mark the
    row as superseded so the user can propose a fresh fix.

    Best-effort. PR or branch may already be closed/deleted manually; we
    log and continue. Caller commits.
    """
    if proposal.status != "applied":
        # Nothing to undo — just supersede the draft.
        proposal.status = "superseded"
        await db.flush()
        return

    if repo.provider == "github" and proposal.pr_url and proposal.branch_name:
        try:
            if repo.integration_id:
                from sqlalchemy import select
                from ..db.models import RepoIntegration
                integ = (await db.execute(
                    select(RepoIntegration).where(RepoIntegration.id == repo.integration_id)
                )).scalar_one_or_none()
                if integ is None:
                    raise ApplyError("no_integration",
                                     "Linked GitHub integration is missing.")
                token = await _resolve_github_token_for_integration(integ.installation_id)
            else:
                token = await _resolve_github_token(repo)

            owner, name = repo.full_name.split("/", 1)
            pr_number = _pr_number_from_url(proposal.pr_url)
            async with httpx.AsyncClient(timeout=30.0) as c:
                if pr_number is not None:
                    # PATCH state=closed
                    r = await c.patch(
                        f"{GITHUB_API}/repos/{owner}/{name}/pulls/{pr_number}",
                        headers={
                            "Authorization": f"Bearer {token}",
                            "Accept": "application/vnd.github+json",
                            "X-GitHub-Api-Version": "2022-11-28",
                        },
                        json={"state": "closed"},
                    )
                    if r.status_code >= 400 and r.status_code != 404:
                        log.warning("revert: PR close returned %s: %s",
                                    r.status_code, r.text[:200])
                # DELETE branch ref
                rd = await c.delete(
                    f"{GITHUB_API}/repos/{owner}/{name}/git/refs/heads/{proposal.branch_name}",
                    headers={
                        "Authorization": f"Bearer {token}",
                        "Accept": "application/vnd.github+json",
                        "X-GitHub-Api-Version": "2022-11-28",
                    },
                )
                if rd.status_code >= 400 and rd.status_code != 404:
                    log.warning("revert: branch delete returned %s: %s",
                                rd.status_code, rd.text[:200])
        except Exception as exc:  # noqa: BLE001 — never block the supersede
            log.warning("revert proposal %s on %s: %s",
                        proposal.id, repo.full_name, exc)
    elif repo.provider == "local" and repo.local_path and proposal.branch_name:
        # Local: just delete the branch.
        try:
            await _run(["git", "branch", "-D", proposal.branch_name],
                       cwd=Path(repo.local_path).expanduser().resolve())
        except Exception as exc:  # noqa: BLE001
            log.warning("revert local branch failed: %s", exc)

    proposal.status = "superseded"
    await db.flush()


def _pr_number_from_url(url: str | None) -> int | None:
    if not url:
        return None
    # https://github.com/<owner>/<repo>/pull/<n>
    parts = url.rstrip("/").split("/")
    try:
        idx = parts.index("pull")
    except ValueError:
        return None
    if idx + 1 >= len(parts):
        return None
    try:
        return int(parts[idx + 1])
    except (TypeError, ValueError):
        return None


# ── Bulk apply (one PR per repo, one commit per finding) ───────────


async def apply_bulk(
    db: AsyncSession,
    proposals: list[FixProposal],
) -> list[dict]:
    """Group ``proposals`` by repository_id and open one PR per repo,
    each carrying every proposal's diff as a separate commit. Updates
    each proposal in place with branch / commit / PR pointers; caller
    commits the DB transaction.

    Returns one result dict per repo group.
    """
    by_repo: dict[str, list[FixProposal]] = {}
    for p in proposals:
        if not p.repository_id:
            continue
        by_repo.setdefault(p.repository_id, []).append(p)

    results: list[dict] = []
    for repo_id, group in by_repo.items():
        repo = (await db.execute(
            select(Repository).where(Repository.id == repo_id)
        )).scalar_one_or_none()
        if repo is None:
            for p in group:
                p.status = "failed"
                p.error = "repo_missing: repository deleted before bulk apply"
            results.append({
                "repository_id": repo_id, "ok": False,
                "error": "repository deleted",
                "proposal_ids": [p.id for p in group],
            })
            continue
        try:
            if repo.provider == "github":
                res = await _apply_github_bulk(db, repo, group)
            elif repo.provider == "local":
                res = await _apply_local_bulk(repo, group)
            else:
                raise ApplyError("unsupported_provider",
                                 f"Unsupported provider: {repo.provider}")
            now = datetime.now(timezone.utc)
            for p in group:
                p.status = "applied"
                p.branch_name = res["branch_name"]
                p.commit_sha = res["commit_sha"]
                p.pr_url = res["pr_url"]
                p.applied_at = now
            results.append({
                "repository_id": repo_id, "ok": True,
                "branch_name": res["branch_name"],
                "commit_sha": res["commit_sha"],
                "pr_url": res["pr_url"],
                "proposal_ids": [p.id for p in group],
            })
        except ApplyError as exc:
            for p in group:
                p.status = "failed"
                p.error = f"{exc.code}: {exc}"
            results.append({
                "repository_id": repo_id, "ok": False,
                "error": f"{exc.code}: {exc}",
                "proposal_ids": [p.id for p in group],
            })
    await db.flush()
    return results


async def _regenerate_and_apply(
    db: AsyncSession, repo: Repository, p: FixProposal,
    workdir_root: Path, original_error: ApplyError,
) -> bool:
    """When a proposal's diff doesn't apply against the bulk workdir,
    re-call the fix-LLM using the *current* file content in the workdir
    and try the new diff once.

    The most common cause of bulk-apply drift: ``propose_fix`` cached
    the materialised workspace at proposal time, but the default-branch
    tip in the fresh bulk clone has different content (whitespace, an
    unrelated commit landed since the scan ran, line shifts from
    upstream changes). Regenerating against the workdir sidesteps the
    drift entirely — the new diff is generated against what we'll
    actually apply it to.

    Returns ``True`` when the regenerated diff applied. ``False``
    otherwise (caller marks the proposal failed and continues).
    """
    log.info(
        "bulk apply: regenerating proposal %s (kind=%s) using fresh "
        "workdir content; first-pass error: %s",
        p.id, p.finding_kind, original_error,
    )
    try:
        # Lazy-import to keep ``fix_applier`` standalone-loadable when
        # the worker boots without the proposer's full dep tree.
        from . import fix_proposer
        new_diff = await fix_proposer.regenerate_diff_against_workdir(
            db, p, workdir_root,
        )
    except Exception as exc:  # noqa: BLE001
        log.warning(
            "bulk apply: regenerate failed for proposal %s: %s",
            p.id, exc,
        )
        return False
    if not new_diff:
        log.info(
            "bulk apply: regenerate produced no usable diff for "
            "proposal %s — keeping original failure.", p.id,
        )
        return False
    try:
        await _git_apply(workdir_root, new_diff)
    except ApplyError as exc:
        log.info(
            "bulk apply: regenerated diff for proposal %s also failed: %s",
            p.id, exc,
        )
        return False
    # Success — record the new diff on the proposal so the PR body
    # cites what actually shipped, not the stale draft.
    p.diff = new_diff
    return True


async def _apply_github_bulk(
    db: AsyncSession, repo: Repository, proposals: list[FixProposal],
) -> dict:
    """Clone once, apply each proposal's diff as its own commit, push, open one PR."""
    if repo.integration_id:
        from sqlalchemy import select as _select
        from ..db.models import RepoIntegration
        integ = (await db.execute(
            _select(RepoIntegration).where(RepoIntegration.id == repo.integration_id)
        )).scalar_one_or_none()
        if integ is None:
            raise ApplyError("no_integration", "Linked GitHub integration is missing.")
        token = await _resolve_github_token_for_integration(integ.installation_id)
    else:
        token = await _resolve_github_token(repo)

    workdir = Path(tempfile.mkdtemp(prefix="pencheff-bulk-fix-"))
    try:
        clone_url = f"https://x-access-token:{token}@github.com/{repo.full_name}.git"
        rc, _o, err = await _run(
            ["git", "clone", "--depth", "1", "--branch", repo.default_branch,
             clone_url, str(workdir / "src")],
        )
        if rc != 0:
            raise ApplyError("clone_failed", err.strip())
        root = workdir / "src"

        # One bulk branch with one commit per finding so reviewers can
        # cherry-pick or revert individually if a fix turns out wrong.
        branch = f"pencheff/fix-bulk-{secrets.token_hex(4)}"
        rc, _o, err = await _run(["git", "checkout", "-b", branch], cwd=root)
        if rc != 0:
            raise ApplyError("checkout_failed", err.strip())

        applied_count = 0
        last_sha: str | None = None
        skipped: list[str] = []
        for p in proposals:
            try:
                await _git_apply(root, p.diff)
            except ApplyError as exc:
                # First-pass apply failure usually means the diff was
                # generated against the materialised workspace (cached
                # at proposal time), but the bulk workdir is a fresh
                # clone of the default-branch tip — context lines have
                # drifted. Regenerate the diff using the *current*
                # state of the bulk workdir and try once more.
                regen_ok = await _regenerate_and_apply(
                    db, repo, p, root, exc,
                )
                if not regen_ok:
                    p.status = "failed"
                    p.error = f"{exc.code}: {exc}"
                    skipped.append(p.id)
                    continue
            await _run(["git", "add", "-A"], cwd=root)
            commit_msg = (
                f"pencheff: fix for finding {p.finding_id[:8]} "
                f"({p.finding_kind})"
            )
            rc, _o, err = await _run(
                ["git", "-c", "user.name=Pencheff[bot]",
                 "-c", "user.email=fix@pencheff.com",
                 "commit", "-m", commit_msg],
                cwd=root,
            )
            if rc != 0:
                p.status = "failed"
                p.error = f"git_commit_failed: {err.strip()}"
                skipped.append(p.id)
                continue
            rc, sha, _err = await _run(["git", "rev-parse", "HEAD"], cwd=root)
            if rc == 0:
                last_sha = sha.strip()
            applied_count += 1

        if applied_count == 0:
            attempted = len(proposals)
            raise ApplyError(
                "all_failed",
                f"Could not apply any of the {attempted} draft diff(s) "
                f"in the bulk after regenerate-and-retry. The handler "
                f"source may have drifted significantly from the "
                f"default branch — re-run the scan and retry.",
            )

        rc, _o, err = await _run(["git", "push", "-u", "origin", branch], cwd=root)
        if rc != 0:
            raise ApplyError("push_failed", err.strip())

        owner, name = repo.full_name.split("/", 1)
        pr_title = f"Pencheff bulk fix · {applied_count} finding(s)"
        pr_body = _format_bulk_pr_body(proposals, applied_count, skipped)
        async with httpx.AsyncClient(timeout=30.0) as c:
            r = await c.post(
                f"{GITHUB_API}/repos/{owner}/{name}/pulls",
                headers={
                    "Authorization": f"Bearer {token}",
                    "Accept": "application/vnd.github+json",
                    "X-GitHub-Api-Version": "2022-11-28",
                },
                json={
                    "title": pr_title, "head": branch,
                    "base": repo.default_branch, "body": pr_body,
                    "maintainer_can_modify": True,
                },
            )
        if r.status_code >= 400:
            raise ApplyError("pr_create_failed",
                             f"GitHub returned {r.status_code}: {r.text[:300]}")
        pr_url = r.json().get("html_url")
        return {"branch_name": branch, "commit_sha": last_sha or "",
                "pr_url": pr_url}
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


async def _apply_local_bulk(
    repo: Repository, proposals: list[FixProposal],
) -> dict:
    if not repo.local_path:
        raise ApplyError("no_local_path", "Local-provider repo has no local_path.")
    root = Path(repo.local_path).expanduser().resolve()
    if not (root / ".git").exists():
        raise ApplyError("not_a_git_repo",
                         f"Local repo at {root} is not a git working tree.")

    rc, out, err = await _run(["git", "status", "--porcelain"], cwd=root)
    if rc != 0:
        raise ApplyError("git_status_failed", err.strip() or "git status failed")
    if out.strip():
        raise ApplyError(
            "dirty_worktree",
            "Local repo has uncommitted changes. Stash or commit them and retry.",
        )

    branch = f"pencheff/fix-bulk-{secrets.token_hex(4)}"
    rc, _o, err = await _run(["git", "checkout", "-b", branch], cwd=root)
    if rc != 0:
        raise ApplyError("checkout_failed", err.strip())

    last_sha: str | None = None
    applied_count = 0
    try:
        for p in proposals:
            try:
                await _git_apply(root, p.diff)
            except ApplyError as exc:
                p.status = "failed"
                p.error = f"{exc.code}: {exc}"
                continue
            await _run(["git", "add", "-A"], cwd=root)
            commit_msg = (
                f"pencheff: fix for finding {p.finding_id[:8]} "
                f"({p.finding_kind})"
            )
            rc, _o, err = await _run(
                ["git", "-c", "user.name=Pencheff",
                 "-c", "user.email=fix@pencheff.com",
                 "commit", "-m", commit_msg],
                cwd=root,
            )
            if rc != 0:
                p.status = "failed"
                p.error = f"git_commit_failed: {err.strip()}"
                continue
            rc, sha, _err = await _run(["git", "rev-parse", "HEAD"], cwd=root)
            if rc == 0:
                last_sha = sha.strip()
            applied_count += 1
        if applied_count == 0:
            raise ApplyError("all_failed",
                             "Every diff in the bulk failed to apply cleanly.")
        await _run(["git", "checkout", "-"], cwd=root)
        return {"branch_name": branch, "commit_sha": last_sha or "", "pr_url": None}
    except ApplyError:
        await _run(["git", "checkout", "-"], cwd=root)
        await _run(["git", "branch", "-D", branch], cwd=root)
        raise


def _format_bulk_pr_body(
    proposals: list[FixProposal], applied: int, skipped: list[str],
) -> str:
    lines = [
        f"Auto-generated by Pencheff to remediate **{applied} finding(s)** "
        "across the attached repository.",
        "",
        "Each commit corresponds to a single finding, so reviewers can "
        "cherry-pick / revert individually if needed.",
        "",
        "| Finding | Kind | Source |",
        "| --- | --- | --- |",
    ]
    for p in proposals:
        if p.status == "applied":
            lines.append(
                f"| `{p.finding_id[:8]}` | {p.finding_kind.upper()} | {p.source} |"
            )
    if skipped:
        lines.append("")
        lines.append(f"⚠️ **{len(skipped)} proposal(s) skipped** because their "
                     "diff didn't apply cleanly on the current default branch:")
        for sid in skipped:
            lines.append(f"- `{sid[:8]}`")
    return "\n".join(lines)
