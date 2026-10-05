"""Repo attachment helpers — local-path validation and shallow git clone.

Repos attached to a pentest session can be either an already-checked-out
local directory or a git URL. URLs are shallow-cloned into a per-session
workspace under ``~/.pencheff/workspaces/<session_id>/`` so SAST can run
against them. Pencheff cleans up cloned workspaces; user-supplied local
paths are left alone.
"""

from __future__ import annotations

import re
import shutil
from pathlib import Path

from pencheff.core.tool_runner import run_tool

_WORKSPACES_ROOT = Path.home() / ".pencheff" / "workspaces"

# Heuristic: schemes/prefixes that mean "this is a git URL, not a path"
_GIT_URL_RE = re.compile(
    r"^("
    r"git@[\w.\-]+:"            # git@github.com:org/repo
    r"|(https?|git|ssh)://"     # https://, git://, ssh://
    r")"
)


class RepoWorkspaceError(RuntimeError):
    """Raised when attaching/cloning a repo fails for a user-actionable reason."""


def is_git_url(source: str) -> bool:
    """True if ``source`` looks like a remote git URL rather than a local path."""
    if not source:
        return False
    if _GIT_URL_RE.match(source):
        return True
    # Trailing .git on a non-path is a strong URL signal too
    if source.endswith(".git") and not Path(source).expanduser().exists():
        return True
    return False


def safe_name_for(source: str) -> str:
    """Slugify the last path component for use as a workspace folder / repo name."""
    raw = source.rstrip("/").rstrip(".git")
    last = raw.split("/")[-1].split(":")[-1] or "repo"
    cleaned = re.sub(r"[^A-Za-z0-9._-]", "-", last).strip("-")
    return cleaned or "repo"


def workspace_root(session_id: str) -> Path:
    """Return the per-session workspace dir; creates it on demand."""
    root = _WORKSPACES_ROOT / session_id
    root.mkdir(parents=True, exist_ok=True)
    return root


async def clone_repo(
    url: str,
    dest: Path,
    branch: str | None = None,
    depth: int = 1,
    timeout: float = 300.0,
) -> None:
    """Shallow-clone ``url`` into ``dest``. Raises RepoWorkspaceError on failure."""
    if dest.exists():
        raise RepoWorkspaceError(f"Clone destination already exists: {dest}")
    args = ["git", "clone", "--depth", str(depth)]
    if branch:
        args += ["--branch", branch, "--single-branch"]
    args += [url, str(dest)]
    result = await run_tool(args, timeout=timeout)
    if not result.success:
        # Best-effort: tear down any partial clone the user can't easily inspect.
        if dest.exists():
            shutil.rmtree(dest, ignore_errors=True)
        msg = result.stderr.strip() or result.stdout.strip() or "git clone failed"
        raise RepoWorkspaceError(f"git clone failed: {msg}")


def cleanup_repo(path: Path) -> None:
    """Remove a previously cloned repo workspace."""
    if path.exists():
        shutil.rmtree(path, ignore_errors=True)


def cleanup_session(session_id: str) -> None:
    """Remove the entire workspace tree for a session."""
    root = _WORKSPACES_ROOT / session_id
    if root.exists():
        shutil.rmtree(root, ignore_errors=True)
