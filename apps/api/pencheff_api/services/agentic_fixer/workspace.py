"""Path-safety guards for tool execution.

Every tool that touches the filesystem (read_file, edit_file,
write_file, grep, glob, bash) is constrained to a single "workspace
root" — the per-run repo clone directory. Any path that resolves
(after symlink expansion) outside this root rejects the tool call
with a ``PathOutsideWorkspace`` error.

This is the only barrier between the LLM and the rest of the
filesystem. We rely on it being correct.
"""
from __future__ import annotations

import os
from pathlib import Path


class PathOutsideWorkspace(Exception):
    """Raised when a tool tries to access a path outside the run's workspace."""


def resolve_within(root: Path, candidate: str | os.PathLike) -> Path:
    """Resolve ``candidate`` relative to ``root`` and verify it lives
    under ``root`` after symlink expansion. Returns the resolved
    absolute path. Raises ``PathOutsideWorkspace`` on escape attempts.

    Both ``root`` and the resolved candidate are normalised via
    ``os.path.realpath`` so symlinks pointing outside the workspace
    are caught.
    """
    root_real = Path(os.path.realpath(str(root)))
    cand_path = Path(candidate)
    if not cand_path.is_absolute():
        cand_path = root_real / cand_path
    cand_real = Path(os.path.realpath(str(cand_path)))
    # `is_relative_to` raises on Path < 3.9, but we're on 3.13+.
    try:
        cand_real.relative_to(root_real)
    except ValueError:
        raise PathOutsideWorkspace(
            f"path '{candidate}' resolves outside workspace root"
        )
    return cand_real
