#!/usr/bin/env python3
"""SPDX-License-Identifier header check + auto-insertion.

Pencheff source files should declare ``SPDX-License-Identifier: MIT``
in their header. This tool walks the repo, identifies source files
that lack the header, and either lists them (default) or inserts the
header in-place (``--fix``).

Run on every PR via ``.github/workflows/license-audit.yml``. Failing
the check forces a contributor to add the header before merge —
makes provenance machine-readable for downstream SBOM tooling.

Excluded paths:
    * ``.venv``, ``node_modules``, ``__pycache__``, ``dist``, ``build``
    * ``apps/web/.next``, ``apps/docs/.next``, ``apps/*/node_modules``
    * Generated ``THIRD_PARTY_NOTICES.md``
    * Anything inside ``plugins/pencheff/.venv``
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

# (extension, comment-prefix) → header style.
_HEADER_STYLES: dict[str, tuple[str, str]] = {
    ".py": ("# ", ""),
    ".sh": ("# ", ""),
    ".js": ("// ", ""),
    ".jsx": ("// ", ""),
    ".ts": ("// ", ""),
    ".tsx": ("// ", ""),
    ".cjs": ("// ", ""),
    ".mjs": ("// ", ""),
    ".go": ("// ", ""),
    ".rs": ("// ", ""),
}

_LICENSE_TAG = "SPDX-License-Identifier: MIT"

_EXCLUDE_DIRS = {
    ".venv", ".git", "__pycache__", "node_modules", "dist", "build",
    ".next", ".turbo", ".tox", ".pytest_cache", ".mypy_cache",
    "graphify-out", "out",
}

_EXCLUDE_PATH_PREFIXES = (
    "apps/api/.venv",
    "plugins/pencheff/.venv",
    "apps/web/.next",
    "apps/docs/.next",
    "apps/extension/dist",
    "apps/vscode/out",
)


def _is_excluded(rel_path: str) -> bool:
    parts = rel_path.split(os.sep)
    if any(p in _EXCLUDE_DIRS for p in parts):
        return True
    return any(rel_path.startswith(p) for p in _EXCLUDE_PATH_PREFIXES)


def _has_header(text: str) -> bool:
    head = text[:2048]
    return _LICENSE_TAG in head


def _insert_header(path: Path, prefix: str) -> None:
    text = path.read_text(encoding="utf-8", errors="replace")
    lines = text.splitlines(keepends=True)
    insert_at = 0
    # Preserve shebang.
    if lines and lines[0].startswith("#!"):
        insert_at = 1
    # Preserve encoding cookie (PEP 263) if present on line 1 of .py files.
    if (
        path.suffix == ".py"
        and len(lines) > insert_at
        and "coding" in lines[insert_at]
        and lines[insert_at].lstrip().startswith("#")
    ):
        insert_at += 1
    header = f"{prefix}{_LICENSE_TAG}\n"
    new_text = "".join(lines[:insert_at]) + header + "".join(lines[insert_at:])
    path.write_text(new_text, encoding="utf-8")


def _changed_files(base: str = "origin/main") -> list[Path]:
    """Return source files changed vs ``base`` (default: origin/main).

    Used by CI to scope the check to the PR's diff. Falls back to an
    empty list when ``git`` isn't available or the base ref doesn't
    exist (typical on a fresh clone).
    """
    import subprocess
    try:
        out = subprocess.check_output(
            ["git", "diff", "--name-only", "--diff-filter=AM", f"{base}...HEAD"],
            cwd=REPO_ROOT, stderr=subprocess.DEVNULL, timeout=30,
        ).decode("utf-8", errors="replace")
    except (subprocess.SubprocessError, FileNotFoundError, OSError):
        return []
    paths: list[Path] = []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        full = (REPO_ROOT / line).resolve()
        if full.is_file():
            paths.append(full)
    return paths


def main() -> int:
    parser = argparse.ArgumentParser(description="SPDX header check.")
    parser.add_argument(
        "--fix", action="store_true",
        help="Insert the SPDX header in files that lack it (default: list only).",
    )
    parser.add_argument(
        "--changed-only", action="store_true",
        help="Only check files added/modified vs origin/main. Used by "
             "the license-audit CI workflow so historical files aren't "
             "blockers — new and modified files are.",
    )
    parser.add_argument(
        "--base", default="HEAD~1",
        help="Base ref for --changed-only (default: HEAD~1). CI passes "
             "the PR base SHA explicitly via "
             "$GITHUB_EVENT.pull_request.base.sha.",
    )
    parser.add_argument(
        "paths", nargs="*",
        help="Optional path filter — only scan inside these subdirs.",
    )
    args = parser.parse_args()

    targets: list[Path] = []
    if args.changed_only:
        targets = _changed_files(args.base)
        if not targets:
            print(
                "SPDX: no source files changed vs "
                f"{args.base} — nothing to check."
            )
            return 0
    elif args.paths:
        for p in args.paths:
            full = (REPO_ROOT / p).resolve()
            if full.is_dir():
                targets.append(full)
            elif full.is_file():
                targets.append(full)
    else:
        targets = [REPO_ROOT]

    missing: list[str] = []
    fixed: list[str] = []
    for target in targets:
        if target.is_file():
            files = [target]
        else:
            files = [p for p in target.rglob("*") if p.is_file()]
        for path in files:
            if path.suffix not in _HEADER_STYLES:
                continue
            try:
                rel = str(path.relative_to(REPO_ROOT))
            except ValueError:
                continue
            if _is_excluded(rel):
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if _has_header(text):
                continue
            if args.fix:
                prefix, _ = _HEADER_STYLES[path.suffix]
                _insert_header(path, prefix)
                fixed.append(rel)
            else:
                missing.append(rel)

    if args.fix:
        if fixed:
            print(f"SPDX: inserted header into {len(fixed)} file(s):")
            for f in fixed:
                print(f"  + {f}")
        else:
            print("SPDX: no files needed updating.")
        return 0

    if missing:
        print(f"SPDX: {len(missing)} file(s) missing the SPDX header:")
        for f in missing:
            print(f"  - {f}")
        print("\nRun `python tools/spdx_check.py --fix` to insert.")
        return 1
    print("SPDX: all eligible files declare the license identifier.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
