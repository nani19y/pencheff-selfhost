# apps/api/tests/test_pr_creator_lockfiles.py
"""Unit tests for the npm-lockfile-dir parser that drives deterministic
dependency remediation (`npm audit fix`) in the agentic-fix PR creator.
Pure parser — no git/npm.

Bug it guards: the remaining ghsa findings are transitive npm CVEs locked in
package-lock.json. The agent can't hand-fix them; the PR creator now runs
`npm audit fix` in every dir that has a tracked package-lock.json. This tests
the detection of those dirs from `git ls-files` output.
"""
from __future__ import annotations

from pencheff_api.services.agentic_fixer.pr_creator import _npm_lockfile_dirs


def test_finds_dirs_with_package_lock():
    ls = "frontend/package-lock.json\nbackend/package-lock.json\nREADME.md\n"
    assert _npm_lockfile_dirs(ls) == ["frontend", "backend"]


def test_root_lockfile_maps_to_empty_dir():
    assert _npm_lockfile_dirs("package-lock.json\n") == [""]


def test_excludes_vendored_node_modules_lockfiles():
    ls = (
        "frontend/package-lock.json\n"
        "frontend/node_modules/x/package-lock.json\n"
    )
    assert _npm_lockfile_dirs(ls) == ["frontend"]


def test_ignores_non_lockfiles():
    ls = "frontend/package.json\nyarn.lock\nbackend/pnpm-lock.yaml\n"
    assert _npm_lockfile_dirs(ls) == []


def test_dedups_dirs():
    # (shouldn't normally happen, but be robust)
    ls = "svc/package-lock.json\nsvc/package-lock.json\n"
    assert _npm_lockfile_dirs(ls) == ["svc"]


def test_empty_input():
    assert _npm_lockfile_dirs("") == []
