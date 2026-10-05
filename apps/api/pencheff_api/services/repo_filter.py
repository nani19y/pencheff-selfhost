"""Filter a repo directory down to "files the user actually wants scanned".

What gets stripped:
  * ``.git/`` — never useful to scan and can be huge.
  * Common noise dirs that almost always belong in ``.gitignore`` even
    when not declared explicitly: ``node_modules``, ``.venv``, ``venv``,
    ``__pycache__``, ``.next``, ``dist``, ``build``, ``.cache``,
    ``target`` (Rust / Java), ``.gradle``, ``.idea``, ``.vscode``,
    ``.pytest_cache``, ``.mypy_cache``, ``.ruff_cache``,
    ``bower_components``, ``.terraform``, ``Pods``.
  * ``.env`` and ``.env.*`` files — typically dev-only secrets the user
    has intentionally not committed; surfacing them as gitleaks findings
    creates noise on local scans without proving anything new.
  * Anything matched by the repo's ``.gitignore`` (full git semantics
    via ``pathspec``).
  * Negation rules (``!path``) inside ``.gitignore`` are honoured — if
    the user explicitly *un-ignores* something, it gets included.

The helper materialises a clean staging directory using **hardlinks** so
it's effectively free for local-disk repos: no bytes copied, just inode
references. Falls back to ``shutil.copy2`` when hardlinks aren't
possible (cross-filesystem mounts).
"""
from __future__ import annotations

import logging
import os
import shutil
from pathlib import Path

log = logging.getLogger(__name__)

NOISE_DIRS: frozenset[str] = frozenset({
    ".git",
    "node_modules",
    ".venv",
    "venv",
    "env",
    "__pycache__",
    ".next",
    "dist",
    "build",
    ".cache",
    "target",
    ".gradle",
    ".idea",
    ".vscode",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "bower_components",
    ".terraform",
    "Pods",
    ".DS_Store",
    "__MACOSX",
})


def _is_env_file(name: str) -> bool:
    """``.env`` and any ``.env.*`` variant (e.g. ``.env.local``)."""
    return name == ".env" or name.startswith(".env.")


def _load_gitignore(repo_root: str):
    """Return a ``pathspec.PathSpec`` (or ``None`` if no .gitignore exists).

    We deliberately load only the root ``.gitignore`` — nested ones are
    rare in practice and supporting them properly requires a recursive
    walk that defeats the hardlink optimisation. The noise-dir blacklist
    above catches the common cases that nested gitignores typically
    cover (``.next``, ``__pycache__``, etc.).
    """
    gi_path = os.path.join(repo_root, ".gitignore")
    if not os.path.isfile(gi_path):
        return None
    try:
        from pathspec import PathSpec
    except ImportError:  # pragma: no cover — pathspec is a hard dep now
        log.warning("pathspec not installed; .gitignore patterns ignored")
        return None
    try:
        with open(gi_path, encoding="utf-8", errors="replace") as fh:
            return PathSpec.from_lines("gitwildmatch", fh)
    except Exception as exc:  # noqa: BLE001
        log.warning(".gitignore parse failed: %s", exc)
        return None


def clean_repo_dir(src: str, staging: str) -> tuple[str, dict]:
    """Build a clean staging dir from ``src`` using hardlinks.

    Returns ``(staging_path, stats)`` where ``stats`` looks like::

        {"included": 1234, "excluded": 5678, "method": "hardlink"|"copy"}

    The staging path is always created — even if ``src`` is empty or all
    files are excluded, callers get a valid (possibly empty) directory
    they can hand to scanners without branching on edge cases.
    """
    os.makedirs(staging, exist_ok=True)
    spec = _load_gitignore(src)
    src_path = Path(src)
    src_real = os.path.realpath(src)

    included = 0
    excluded = 0
    method = "hardlink"

    for dirpath, dirnames, filenames in os.walk(src, topdown=True, followlinks=False):
        # Mutate dirnames in-place so os.walk doesn't descend into
        # excluded subtrees — saves a *lot* of work on repos with large
        # node_modules / .venv directories.
        rel_dir = os.path.relpath(dirpath, src)
        kept_dirs: list[str] = []
        for d in dirnames:
            if d in NOISE_DIRS:
                excluded += 1
                continue
            sub_rel = d if rel_dir == "." else os.path.join(rel_dir, d)
            # PathSpec wants directory paths with a trailing slash.
            if spec is not None and spec.match_file(sub_rel + "/"):
                excluded += 1
                continue
            kept_dirs.append(d)
        dirnames[:] = kept_dirs

        for f in filenames:
            if f in NOISE_DIRS or _is_env_file(f):
                excluded += 1
                continue
            sub_rel = f if rel_dir == "." else os.path.join(rel_dir, f)
            if spec is not None and spec.match_file(sub_rel):
                excluded += 1
                continue

            src_file = os.path.join(dirpath, f)
            # Defence in depth: never let a symlink escape ``src`` and
            # let a scanner read /etc/passwd or similar.
            try:
                target_real = os.path.realpath(src_file)
                if not target_real.startswith(src_real):
                    excluded += 1
                    continue
            except OSError:
                excluded += 1
                continue

            dst_file = os.path.join(staging, sub_rel)
            os.makedirs(os.path.dirname(dst_file), exist_ok=True)
            try:
                os.link(src_file, dst_file)
            except OSError:
                # Cross-filesystem (common with bind mounts on macOS
                # Docker) or already-exists. Fall back to copy.
                method = "copy"
                try:
                    shutil.copy2(src_file, dst_file)
                except Exception as exc:  # noqa: BLE001
                    log.debug("skip %s during staging: %s", src_file, exc)
                    excluded += 1
                    continue
            included += 1

    return staging, {
        "included": included,
        "excluded": excluded,
        "method": method,
    }
