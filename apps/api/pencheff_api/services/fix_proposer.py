"""Build a fix proposal for a finding.

Single entrypoint ``propose_fix(finding, ...)``. The branches:

  * **SAST + scanner-native autofix** — pull the autofix payload that the
    pencheff SAST runner stashed inside ``Finding.evidence`` (the
    ``request_method == "SAST_AUTOFIX"`` row), apply it on a working copy
    of the repo, capture the unified diff. No LLM. Always free.
  * **SAST + no autofix + Pro+ + quota OK** — load the offending file +
    build a snippet, ask the fix-LLM for a patch, parse it, validate.
  * **DAST + heuristic provenance** — call ``route_index.find_provenance``
    and pick the top match. Free path produces a placeholder remediation
    diff (a comment block at the handler) that the developer can flesh
    out; LLM path generates a real patch.

Returns a draft ``FixProposal`` row (not yet committed). The caller wraps
the call in a transaction so failure cases don't leak rows.
"""
from __future__ import annotations

import asyncio
import json
import logging
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db.models import (
    Finding as DbFinding,
    FixProposal,
    RepoFinding,
    Repository,
    Target,
    TargetRepository,
)
from ..config import get_settings
from . import fix_quota, fix_recipes, github_app, route_index
from .credentials import decrypt_credentials
from .fix_llm import FixLLMClient

log = logging.getLogger(__name__)

# When True, every proposal goes through the configured fix-LLM — no
# scanner-native autofix, no DAST recipe shortcuts. The heuristic
# implementations below remain in place so we can re-enable them (e.g. as a
# fallback for unreachable LLMs) by flipping this flag back to False. The
# monthly quota gate (fix_quota.preflight) runs independently of this flag.
USE_LLM_ONLY = True

# Plans that get the Expert fix model; everyone else gets the Instant model.
PRO_FIX_PLANS = frozenset({"pro", "team", "self_hosted", "enterprise"})


def _fix_model_for_plan(plan: str) -> str:
    """Route the fix-proposer LLM by plan: free → Instant, paid → Expert."""
    s = get_settings()
    return s.fix_llm_model_pro if plan in PRO_FIX_PLANS else s.fix_llm_model_free


# ── Public types ────────────────────────────────────────────────────


@dataclass
class ProposalRequest:
    """Inputs to the proposer. Built from the route-handler request."""
    org_id: str
    workspace_id: str
    user_id: str | None
    finding_kind: str          # "sast" | "dast"
    finding_id: str
    scan_id: str | None
    repo_scan_id: str | None
    allow_payg: bool = False   # user explicitly accepted PAYG charge


@dataclass
class ProposerError(Exception):
    code: str                  # "no_autofix" | "no_provenance" | "no_repo" | "llm_failed" | …
    message: str

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"


# ── Helpers ─────────────────────────────────────────────────────────


def _autofix_payload(evidence: list[dict] | None) -> dict | None:
    """Pull the SAST_AUTOFIX evidence row planted by the runner."""
    for ev in evidence or []:
        if ev.get("request_method") == "SAST_AUTOFIX" and ev.get("request_body"):
            try:
                return json.loads(ev["request_body"])
            except (TypeError, ValueError):
                continue
    return None


def _sca_autofix_payload(evidence: list[dict] | None) -> dict | None:
    """Pull the SCA autofix payload that ``dependency_scan`` planted in
    ``Evidence.autofix``. Required keys: ``ecosystem``, ``package``,
    ``fix_version``, ``manifest_path``. Anything missing → no deterministic
    patch is possible.
    """
    for ev in evidence or []:
        autofix = ev.get("autofix")
        if not isinstance(autofix, dict):
            continue
        if autofix.get("ecosystem") and autofix.get("package") and autofix.get("fix_version"):
            return autofix
        # pip-audit / npm-audit shape — keys are the same set, just emitted
        # by a different upstream tool.
        if autofix.get("tool") in ("pip-audit", "npm-audit") and autofix.get("package"):
            return autofix
    return None


def _parse_repo_endpoint(endpoint: str | None) -> tuple[str, str] | None:
    """Endpoint shape produced by the SAST runner: ``repo://<name>/<file>``.

    Returns ``(repo_name, relative_path)`` or ``None``.
    """
    if not endpoint or not endpoint.startswith("repo://"):
        return None
    body = endpoint[len("repo://"):]
    name, _, rest = body.partition("/")
    if not name:
        return None
    return name, rest


async def _repo_for_sast(
    db: AsyncSession,
    *,
    workspace_id: str,
    repo_name: str,
) -> Repository | None:
    """SAST findings encode the repo name in the endpoint; map that back to
    a Repository row in the same workspace.
    """
    repo = (await db.execute(
        select(Repository).where(
            Repository.workspace_id == workspace_id,
            Repository.full_name.ilike(repo_name.replace("-", "/")),
        )
    )).scalar_one_or_none()
    if repo:
        return repo
    # Fall back to a fuzzy local-path / tail match.
    return (await db.execute(
        select(Repository).where(
            Repository.workspace_id == workspace_id,
            Repository.name == repo_name,
        )
    )).scalar_one_or_none()


_FIX_WORKSPACE_ROOT = Path.home() / ".pencheff" / "fix_workspaces"
# How long a cached clone is considered fresh before we re-fetch HEAD. Short
# enough that proposals reflect recent commits, long enough that clicking
# "Propose fix" on five findings doesn't open five clones in parallel.
_REFRESH_AFTER_SECONDS = 600.0  # 10 minutes


async def _materialise_workspace(
    db: AsyncSession, repo: Repository,
) -> Path | None:
    """Return an on-disk working tree for ``repo`` — cloning on demand if
    we don't already have one. Caches per repo under
    ``~/.pencheff/fix_workspaces/<repo_id>/src``.

    Strategy:
      * ``provider == "local"`` → just return ``local_path``.
      * ``provider == "github"`` → if the cache dir exists, ``git fetch +
        reset --hard origin/<default_branch>`` to refresh; otherwise
        shallow-clone fresh. Auth comes from the GitHub App installation
        token, the encrypted PAT, or — for public repos — anonymous clone.
      * Anything else → ``None`` (caller decides whether to bail).

    Failures bubble up as ``None``. The proposer falls through to whichever
    branch can still produce a useful patch (heuristic-only DAST, scanner-
    autofix SAST, etc.), so this never raises.
    """
    if repo.provider == "local":
        if repo.local_path:
            p = Path(repo.local_path).expanduser().resolve()
            if p.is_dir():
                return p
        return None

    if repo.provider != "github":
        return None

    cache_dir = _FIX_WORKSPACE_ROOT / str(repo.id)
    src = cache_dir / "src"

    # Existing clone — refresh if stale, then return.
    if src.is_dir() and (src / ".git").is_dir():
        try:
            mtime = src.stat().st_mtime
        except OSError:
            mtime = 0.0
        import time
        is_stale = (time.time() - mtime) > _REFRESH_AFTER_SECONDS
        if not is_stale:
            return src
        token = await _resolve_repo_token(db, repo)
        # Best-effort refresh: rewrite the remote URL with the latest token,
        # fetch, and reset hard. Any failure leaves the cached clone in
        # place — better stale than absent.
        remote = _clone_url_with_token(repo, token)
        try:
            await _run(["git", "remote", "set-url", "origin", remote], cwd=src)
            await _run(["git", "fetch", "--depth", "1", "origin", repo.default_branch], cwd=src)
            await _run(["git", "reset", "--hard", f"origin/{repo.default_branch}"], cwd=src)
            src.touch()  # bump mtime so we don't refetch immediately
        except Exception as exc:  # noqa: BLE001
            log.warning("workspace refresh for %s failed: %s; using stale clone",
                        repo.full_name, exc)
        return src

    # No clone yet — make one.
    cache_dir.mkdir(parents=True, exist_ok=True)
    if src.exists():
        # Half-cloned remnant from a previous failure; nuke it.
        import shutil
        shutil.rmtree(src, ignore_errors=True)
    token = await _resolve_repo_token(db, repo)
    remote = _clone_url_with_token(repo, token)
    try:
        rc, _out, err = await _run([
            "git", "clone", "--depth", "1",
            "--branch", repo.default_branch,
            remote, str(src),
        ])
        if rc != 0:
            log.warning("clone for %s failed: %s", repo.full_name, err.strip())
            return None
    except Exception as exc:  # noqa: BLE001
        log.warning("clone for %s raised: %s", repo.full_name, exc)
        return None
    return src


async def _resolve_repo_token(db: AsyncSession, repo: Repository) -> str:
    """Mint or decrypt a token for ``repo``. Returns the empty string for
    public clones (which git accepts) so callers don't have to special-case
    auth.
    """
    if repo.integration_id:
        from ..db.models import RepoIntegration
        integ = (await db.execute(
            select(RepoIntegration).where(RepoIntegration.id == repo.integration_id)
        )).scalar_one_or_none()
        if integ is not None:
            try:
                return await github_app.get_installation_token(integ.installation_id)
            except Exception as exc:  # noqa: BLE001
                log.warning("installation token fetch failed for %s: %s",
                            repo.full_name, exc)
                return ""
    if repo.token_encrypted:
        tok_blob = decrypt_credentials(repo.token_encrypted) or {}
        token = tok_blob.get("token") or ""
        return token
    return ""


def _clone_url_with_token(repo: Repository, token: str) -> str:
    if not token:
        return f"https://github.com/{repo.full_name}.git"
    return f"https://x-access-token:{token}@github.com/{repo.full_name}.git"


async def _run(cmd: list[str], cwd: Path | None = None) -> tuple[int, str, str]:
    """Async-safe `git` subprocess; never inherits stdin."""
    import os
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        cwd=str(cwd) if cwd else None,
        env=os.environ.copy(),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    out, err = await proc.communicate()
    return (
        proc.returncode or 0,
        out.decode(errors="replace"),
        err.decode(errors="replace"),
    )


# ── SAST: scanner-native autofix → unified diff ─────────────────────


def _apply_text_replace(file_text: str, autofix: dict) -> str | None:
    """Apply a semgrep-style ``text_replace`` autofix to in-memory text.

    Semgrep emits ``start.line/end.line/start.col/end.col`` (1-indexed,
    column offsets in the line). When ``fix`` (literal replacement) is
    set we splice it in directly; ``fix_regex`` (``{regex, replacement}``)
    is regex-substituted within the byte range.
    """
    fix = autofix.get("fix")
    fix_regex = autofix.get("fix_regex")
    s_line = autofix.get("start_line")
    s_col = autofix.get("start_col") or 1
    e_line = autofix.get("end_line")
    e_col = autofix.get("end_col") or 1
    if not s_line or not e_line:
        return None
    lines = file_text.splitlines(keepends=True)
    if s_line > len(lines) or e_line > len(lines):
        return None
    # Build prefix / target / suffix using 1-indexed inclusive lines.
    prefix = "".join(lines[: s_line - 1])
    target = "".join(lines[s_line - 1: e_line])
    suffix = "".join(lines[e_line:])
    # Slice columns within target if both ends are on the same line.
    if s_line == e_line:
        head = target[: s_col - 1]
        tail = target[e_col - 1:]
        replaced = (
            (fix if fix is not None else _regex_apply(target[s_col - 1: e_col - 1], fix_regex))
        )
        if replaced is None:
            return None
        target = head + replaced + tail
    else:
        # Multi-line: replace entire range. Column data only used to keep
        # the leading whitespace of the first line if fix doesn't include it.
        replaced = fix if fix is not None else _regex_apply(target, fix_regex)
        if replaced is None:
            return None
        target = replaced
    return prefix + target + suffix


def _regex_apply(text: str, fix_regex: dict | None) -> str | None:
    if not fix_regex:
        return None
    pattern = fix_regex.get("regex")
    replacement = fix_regex.get("replacement", "")
    if not pattern:
        return None
    try:
        return re.sub(pattern, replacement, text)
    except re.error:
        return None


def _detect_secrets_remediation(rel: str, line: int | None) -> str:
    """For detect-secrets findings the "fix" is rotation, not a code change.

    Generate an inline placeholder so the developer's PR carries the
    rotation checklist alongside the diff context.
    """
    return (
        "# TODO(pencheff): rotate this credential immediately, then load it\n"
        "# from a secrets manager / environment variable instead of the source.\n"
    )


def _diff_for_change(rel: str, original: str, modified: str) -> str:
    """Produce a unified diff with `git diff`-compatible headers."""
    import difflib

    diff = difflib.unified_diff(
        original.splitlines(keepends=True),
        modified.splitlines(keepends=True),
        fromfile=f"a/{rel}",
        tofile=f"b/{rel}",
        n=3,
    )
    return "".join(diff)


def _scanner_autofix_diff(
    *,
    repo_root: Path,
    rel_path: str,
    line: int | None,
    autofix: dict,
) -> tuple[str, str] | None:
    """Apply the scanner's autofix to a working copy of the file and return
    ``(diff, modified_text)`` for caller to attach to the proposal.
    """
    file_path = (repo_root / rel_path).resolve()
    try:
        file_path.relative_to(repo_root.resolve())
    except (ValueError, OSError):
        return None
    if not file_path.is_file():
        return None
    try:
        original = file_path.read_text(errors="replace")
    except OSError:
        return None
    kind = autofix.get("kind") or autofix.get("tool")
    modified: str | None = None
    if kind == "text_replace" or autofix.get("fix") is not None or autofix.get("fix_regex"):
        modified = _apply_text_replace(original, autofix)
    elif autofix.get("tool") == "detect-secrets":
        # Insert a TODO comment above the offending line.
        if line and 1 <= line <= len(original.splitlines()) + 1:
            lines = original.splitlines(keepends=True)
            lines.insert(line - 1, _detect_secrets_remediation(rel_path, line))
            modified = "".join(lines)
    elif autofix.get("tool") in ("pip-audit", "npm-audit"):
        modified = _dependency_upgrade_patch(original, rel_path, autofix)
    if modified is None or modified == original:
        return None
    return _diff_for_change(rel_path, original, modified), modified


def _dependency_upgrade_patch(
    original: str, rel_path: str, autofix: dict,
) -> str | None:
    """Deterministic in-place version bump across 9 manifest formats.

    Lockfiles are intentionally **not** edited — the PR body instructs the
    developer to run the relevant installer (`npm install`, `poetry lock`,
    `go mod tidy`, etc.) which regenerates the lockfile correctly. Editing
    a lockfile in place would break integrity hashes for most ecosystems.

    Returns the modified text on success, ``None`` when the package is
    absent from this manifest or the format isn't recognised.
    """
    pkg = autofix.get("package")
    target = autofix.get("fix_version") or autofix.get("target_version")
    if not pkg or not target:
        return None
    base = Path(rel_path).name.lower()
    rel_l = rel_path.lower()

    # ── Python ─────────────────────────────────────────────────────────
    if base == "requirements.txt" or base.endswith(".txt") and "requirement" in base:
        return _bump_requirements_txt(original, pkg, target)
    if base == "pyproject.toml":
        return _bump_pyproject_toml(original, pkg, target)
    if base == "pipfile":
        return _bump_pipfile(original, pkg, target)
    # ── Node ───────────────────────────────────────────────────────────
    if base == "package.json":
        return _bump_package_json(original, pkg, target)
    # ── Go ─────────────────────────────────────────────────────────────
    if base == "go.mod":
        return _bump_go_mod(original, pkg, target)
    # ── Rust ───────────────────────────────────────────────────────────
    if base == "cargo.toml":
        return _bump_cargo_toml(original, pkg, target)
    # ── Ruby ───────────────────────────────────────────────────────────
    if base == "gemfile":
        return _bump_gemfile(original, pkg, target)
    # ── PHP ────────────────────────────────────────────────────────────
    if base == "composer.json":
        return _bump_composer_json(original, pkg, target)
    # ── Java ───────────────────────────────────────────────────────────
    if base == "pom.xml":
        return _bump_pom_xml(original, pkg, target)
    # Lockfile? Refuse — the installer should regenerate it.
    if base in {
        "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml",
        "poetry.lock", "pipfile.lock", "uv.lock",
        "cargo.lock", "gemfile.lock", "composer.lock", "go.sum",
    }:
        return None
    # Unknown manifest: try a "name == version" line, last-ditch.
    if "==" in original or "= " in original:
        return _bump_requirements_txt(original, pkg, target)
    _ = rel_l  # silence linter when no fallback matched
    return None


# ── Format-specific bumpers ─────────────────────────────────────────


def _bump_requirements_txt(original: str, pkg: str, target: str) -> str | None:
    rx = re.compile(
        rf"(?P<head>^[ \t]*{re.escape(pkg)}(?:\[[^\]]*\])?\s*)"
        rf"(?P<spec>[=<>!~]=?\s*[^\s;#]+)?",
        re.MULTILINE | re.IGNORECASE,
    )
    matched = False

    def _sub(m: re.Match) -> str:
        nonlocal matched
        matched = True
        return f"{m.group('head').rstrip()}=={target}"

    out = rx.sub(_sub, original)
    return out if matched and out != original else None


def _bump_pyproject_toml(original: str, pkg: str, target: str) -> str | None:
    """PEP 621 ``project.dependencies`` + Poetry ``tool.poetry.dependencies``.

    Avoids round-tripping through tomllib (which would discard comments
    and reformat). Edits with anchored regexes that respect TOML strings
    in either single- or double-quoted form.
    """
    out = original
    changed = False
    # PEP 621: dependencies = ["pkg ==1.2.3", "other>=2"]
    rx_pep621 = re.compile(
        rf"""(?P<q>['"])(?P<head>{re.escape(pkg)}(?:\[[^\]]*\])?[ \t]*)"""
        rf"""(?P<spec>[=<>!~]=?[^'",]+)?(?P=q)""",
        re.IGNORECASE,
    )
    def _pep621_sub(m: re.Match) -> str:
        nonlocal changed
        changed = True
        return f"{m.group('q')}{m.group('head').rstrip()}=={target}{m.group('q')}"
    out = rx_pep621.sub(_pep621_sub, out)
    # Poetry: pkg = "1.2.3" or pkg = {version = "1.2.3", ...}
    rx_poetry_str = re.compile(
        rf"""(?m)^(?P<head>[ \t]*{re.escape(pkg)}[ \t]*=[ \t]*)"""
        rf"""(?P<q>['"])(?P<spec>[\^~>=<! ]*[^'"\s]+)(?P=q)""",
        re.IGNORECASE,
    )
    def _poetry_str_sub(m: re.Match) -> str:
        nonlocal changed
        changed = True
        return f"{m.group('head')}{m.group('q')}^{target}{m.group('q')}"
    out = rx_poetry_str.sub(_poetry_str_sub, out)
    rx_poetry_tbl = re.compile(
        rf"""(?ms)^(?P<head>[ \t]*{re.escape(pkg)}[ \t]*=[ \t]*\{{[^}}]*?version[ \t]*=[ \t]*)"""
        rf"""(?P<q>['"])[^'"]+(?P=q)""",
        re.IGNORECASE,
    )
    def _poetry_tbl_sub(m: re.Match) -> str:
        nonlocal changed
        changed = True
        return f"{m.group('head')}{m.group('q')}^{target}{m.group('q')}"
    out = rx_poetry_tbl.sub(_poetry_tbl_sub, out)
    return out if changed and out != original else None


def _bump_pipfile(original: str, pkg: str, target: str) -> str | None:
    rx = re.compile(
        rf"""(?m)^(?P<head>[ \t]*{re.escape(pkg)}[ \t]*=[ \t]*)"""
        rf"""(?P<q>['"])[^'"]+(?P=q)""",
        re.IGNORECASE,
    )
    matched = False
    def _sub(m: re.Match) -> str:
        nonlocal matched
        matched = True
        return f"{m.group('head')}{m.group('q')}=={target}{m.group('q')}"
    out = rx.sub(_sub, original)
    return out if matched and out != original else None


def _bump_package_json(original: str, pkg: str, target: str) -> str | None:
    try:
        data = json.loads(original)
    except json.JSONDecodeError:
        return None
    found = False
    for section in (
        "dependencies", "devDependencies",
        "optionalDependencies", "peerDependencies",
    ):
        if section in data and pkg in data[section]:
            data[section][pkg] = f"^{target}"
            found = True
    if not found:
        return None
    # Match the file's existing indentation when we can detect it.
    indent_match = re.search(r"\n( +)\"", original)
    indent = len(indent_match.group(1)) if indent_match else 2
    trailing_nl = "\n" if original.endswith("\n") else ""
    return json.dumps(data, indent=indent) + trailing_nl


def _bump_go_mod(original: str, pkg: str, target: str) -> str | None:
    # `target` is expected to be a Go module version (e.g. "v1.2.3"). Prepend
    # the leading "v" if the OSV feed gave a bare semver.
    target_v = target if target.startswith("v") else f"v{target}"
    rx = re.compile(
        rf"""(?m)^(?P<head>[ \t]*(?:require[ \t]+)?{re.escape(pkg)}[ \t]+)"""
        rf"""[^\s]+(?P<tail>[ \t]*(?://[^\n]*)?)$"""
    )
    matched = False
    def _sub(m: re.Match) -> str:
        nonlocal matched
        matched = True
        return f"{m.group('head')}{target_v}{m.group('tail')}"
    out = rx.sub(_sub, original)
    return out if matched and out != original else None


def _bump_cargo_toml(original: str, pkg: str, target: str) -> str | None:
    out = original
    changed = False
    # Simple form:  name = "1.2.3"
    rx_str = re.compile(
        rf"""(?m)^(?P<head>[ \t]*{re.escape(pkg)}[ \t]*=[ \t]*)"""
        rf"""(?P<q>['"])[^'"]+(?P=q)"""
    )
    def _str_sub(m: re.Match) -> str:
        nonlocal changed
        changed = True
        return f"{m.group('head')}{m.group('q')}{target}{m.group('q')}"
    out = rx_str.sub(_str_sub, out)
    # Inline-table form: name = { version = "1.2.3", ... }
    rx_tbl = re.compile(
        rf"""(?ms)^(?P<head>[ \t]*{re.escape(pkg)}[ \t]*=[ \t]*\{{[^}}]*?version[ \t]*=[ \t]*)"""
        rf"""(?P<q>['"])[^'"]+(?P=q)"""
    )
    def _tbl_sub(m: re.Match) -> str:
        nonlocal changed
        changed = True
        return f"{m.group('head')}{m.group('q')}{target}{m.group('q')}"
    out = rx_tbl.sub(_tbl_sub, out)
    return out if changed and out != original else None


def _bump_gemfile(original: str, pkg: str, target: str) -> str | None:
    # gem "name", "1.2.3"   |   gem 'name', '~> 1.2'   |   gem "name"
    rx = re.compile(
        rf"""(?m)^(?P<head>[ \t]*gem[ \t]+(?P<q1>['"]){re.escape(pkg)}(?P=q1)[ \t]*,[ \t]*)"""
        rf"""(?P<q2>['"])[^'"]+(?P=q2)"""
    )
    matched = False
    def _sub(m: re.Match) -> str:
        nonlocal matched
        matched = True
        return f"{m.group('head')}{m.group('q2')}~> {target}{m.group('q2')}"
    out = rx.sub(_sub, original)
    if matched and out != original:
        return out
    # Form without an existing version: append one.
    rx_bare = re.compile(
        rf"""(?m)^(?P<line>[ \t]*gem[ \t]+(?P<q>['"]){re.escape(pkg)}(?P=q))[ \t]*$"""
    )
    matched_bare = False
    def _bare_sub(m: re.Match) -> str:
        nonlocal matched_bare
        matched_bare = True
        return f"{m.group('line')}, {m.group('q')}~> {target}{m.group('q')}"
    out = rx_bare.sub(_bare_sub, original)
    return out if matched_bare and out != original else None


def _bump_composer_json(original: str, pkg: str, target: str) -> str | None:
    try:
        data = json.loads(original)
    except json.JSONDecodeError:
        return None
    found = False
    for section in ("require", "require-dev"):
        if section in data and pkg in data[section]:
            data[section][pkg] = f"^{target}"
            found = True
    if not found:
        return None
    indent_match = re.search(r"\n( +)\"", original)
    indent = len(indent_match.group(1)) if indent_match else 4
    trailing_nl = "\n" if original.endswith("\n") else ""
    return json.dumps(data, indent=indent) + trailing_nl


def _bump_pom_xml(original: str, pkg: str, target: str) -> str | None:
    """``pkg`` arrives as ``groupId:artifactId``. Match the dependency block
    that has both, then replace its ``<version>`` (or insert one)."""
    if ":" not in pkg:
        return None
    group, artifact = pkg.split(":", 1)
    pat = re.compile(
        r"<dependency\b[^>]*>(?P<body>.*?)</dependency>",
        re.DOTALL | re.IGNORECASE,
    )
    changed = False
    def _replace(m: re.Match) -> str:
        nonlocal changed
        body = m.group("body")
        gid = re.search(r"<groupId>\s*([^<\s]+)\s*</groupId>", body, re.IGNORECASE)
        aid = re.search(r"<artifactId>\s*([^<\s]+)\s*</artifactId>", body, re.IGNORECASE)
        if not gid or not aid:
            return m.group(0)
        if gid.group(1) != group or aid.group(1) != artifact:
            return m.group(0)
        if "<version>" in body.lower():
            new_body = re.sub(
                r"<version>\s*[^<]+\s*</version>",
                f"<version>{target}</version>",
                body, count=1, flags=re.IGNORECASE,
            )
        else:
            # Insert <version> just after the closing </artifactId>.
            new_body = re.sub(
                r"(</artifactId>\s*)",
                rf"\1<version>{target}</version>\n            ",
                body, count=1, flags=re.IGNORECASE,
            )
        if new_body != body:
            changed = True
        return f"<dependency>{new_body}</dependency>"
    out = pat.sub(_replace, original)
    return out if changed and out != original else None


# ── DAST: snippet around a route handler ────────────────────────────


def _evidence_excerpt(evidence: list[dict] | None) -> str:
    """Compress the first evidence row into a request/response excerpt for
    DAST fix prompts. Mirrors the helper in routers/findings.py so the
    proposer doesn't import from the routers layer."""
    ev = evidence or []
    if not ev or not isinstance(ev[0], dict):
        return ""
    first = ev[0]
    parts: list[str] = []
    if first.get("request_method") and first.get("request_url"):
        parts.append(f"{first['request_method']} {first['request_url']}")
    if first.get("request_headers"):
        h = first["request_headers"]
        if isinstance(h, dict):
            for k in ("Cookie", "cookie", "Authorization", "authorization",
                      "Content-Type", "content-type"):
                if k in h:
                    parts.append(f"{k}: {h[k]}")
                    break
    if first.get("request_body"):
        parts.append(f"\nBody: {str(first['request_body'])[:300]}")
    if first.get("response_status") is not None:
        parts.append(f"\n→ {first['response_status']}")
    body = first.get("response_body_snippet")
    if body:
        parts.append(f"\nResponse: {str(body)[:600]}")
    if not body and first.get("description"):
        parts.append(f"\nNote: {str(first['description'])[:400]}")
    return " ".join(parts).strip()


_COMMENT_PREFIXES = (
    "#",       # Python, Bash, YAML, Ruby, Perl
    "//",      # C/C++, Java, JS, Go, Rust
    "/*", "*", # C-style block comments
    '"""', "'''",  # Python docstring delimiters
    "<!--",    # HTML, XML, Markdown
    ".. ",     # reStructuredText directive
    ">",       # Markdown blockquote — added after we caught the LLM
               # emitting `> **Note:** ...` prose to README.md when no
               # source-code anchor existed for the finding.
)

# Lines that look like an English sentence: start with a capital
# letter, end with .  ! ? (with optional trailing whitespace), and
# contain only letters, digits, spaces, and prose-grade punctuation.
# Code lines almost always include at least one of `()[]{}=<>|&@`,
# which the character class deliberately excludes — so legitimate
# patches like ``return foo.bar()`` or ``if not q:`` don't match.
# Catches the harder LLM fallback shape: a paragraph dropped into a
# .md / .rst / .txt file when the model has no real fix to write.
_PROSE_LINE_RX = re.compile(
    r"^[A-Z][A-Za-z0-9 ,;:'\"`\-]*[.!?]\s*$"
)


def _diff_has_real_changes(diff: str | None) -> bool:
    """A diff is "real" when at least one added line is actual code,
    not a comment, blank, docstring marker, markdown blockquote, or a
    sentence-shaped prose paragraph. Filters out two LLM fallbacks:

      * "Drop a TODO marker" — caught by ``_COMMENT_PREFIXES``.
      * "Drop a Markdown explanation into the README" — caught by the
        blockquote prefix and the prose-line regex; both fire when the
        proposer routed to a non-code file because no real handler
        existed for the finding.
    """
    if not diff:
        return False
    real_added = 0
    for raw in diff.splitlines():
        if not raw.startswith("+") or raw.startswith("+++"):
            continue
        # Strip the leading "+" then strip whitespace.
        body = raw[1:].lstrip()
        if not body:
            continue
        if body.startswith(_COMMENT_PREFIXES):
            continue
        if _PROSE_LINE_RX.match(body):
            continue
        real_added += 1
    return real_added > 0


_HUNK_HEADER_RX = re.compile(
    r"^@@ -\d+(?:,(\d+))? \+\d+(?:,(\d+))? @@"
)


# Files where no real handler can ever live — README.md, LICENSE,
# CHANGELOG, etc. When ``route_index`` resolves a DAST finding to one
# of these (the lowest-confidence fallback when no code candidate
# exists), the LLM is asked to "patch" a documentation file. With
# rule 5 in the system prompt requiring a real diff, the model
# hallucinates plausible-looking code into the wrong file —
# e.g. inserting `from flask import Flask\n@app.route('/jenkins')`
# at the top of README.md, which is syntactically valid Python but
# obviously useless. The proposer rejects these targets up-front so
# the bulk router silently drops the finding via ``no_code_anchor``.
_NON_CODE_SUFFIXES = frozenset({
    ".md", ".markdown", ".rst", ".txt",
    ".adoc", ".asciidoc", ".org",
})

_NON_CODE_BASENAMES = frozenset({
    "README", "LICENSE", "LICENCE", "COPYING", "CHANGELOG", "CHANGES",
    "HISTORY", "NOTICE", "AUTHORS", "CONTRIBUTORS", "CONTRIBUTING",
    "MAINTAINERS", "CODEOWNERS", "TODO", "INSTALL",
})


def _is_non_code_file(rel: str) -> bool:
    """Return True when ``rel`` points to a documentation / metadata
    file rather than source code.

    Matches by lowercase suffix (``.md``, ``.rst`` …) or by uppercase
    stem when there's no suffix (``README``, ``LICENSE`` …). Both are
    case-insensitive against the typical conventions; mixed-case files
    like ``readme.md`` are caught by the suffix branch.
    """
    p = Path(rel)
    if p.suffix.lower() in _NON_CODE_SUFFIXES:
        return True
    if not p.suffix and p.stem.upper() in _NON_CODE_BASENAMES:
        return True
    return False


def _diff_salvage(diff: str | None) -> str | None:
    """Return the largest prefix of ``diff`` consisting of complete hunks.

    LLMs frequently truncate the LAST hunk when they hit a token cap or
    just decide they're done. The earlier hunks are usually fine, so
    rejecting the whole patch wastes a perfectly good partial fix.
    This helper walks the diff, validates each hunk's line count against
    its ``@@`` header, and stops at the first incomplete hunk — returning
    everything up to that point as a still-applyable patch.

    Returns:
        * ``None`` when the diff is empty or has no complete hunks.
        * The original diff when every hunk is well-formed.
        * A truncated-but-clean prefix when a trailing hunk was bad.
    """
    if not diff:
        return None
    lines = diff.splitlines(keepends=True)

    # Walk through the diff; track the byte offset where the last
    # complete hunk ended so we can slice cleanly there.
    in_hunk = False
    expected_old = 0
    expected_new = 0
    seen_old = 0
    seen_new = 0
    last_good_end = 0  # char index in the joined string
    running_offset = 0
    file_header_end = 0  # we want to keep at least the file headers

    def _hunk_complete() -> bool:
        return seen_old == expected_old and seen_new == expected_new

    for line in lines:
        line_len = len(line)
        stripped = line.rstrip("\n")
        m = _HUNK_HEADER_RX.match(stripped)
        if m:
            if in_hunk:
                if _hunk_complete():
                    last_good_end = running_offset
                else:
                    # Previous hunk was incomplete — bail before this
                    # new one. Don't include the new hunk's header.
                    return diff[:last_good_end] if last_good_end > 0 else None
            expected_old = int(m.group(1)) if m.group(1) else 1
            expected_new = int(m.group(2)) if m.group(2) else 1
            seen_old = seen_new = 0
            in_hunk = True
        elif stripped.startswith(("--- ", "+++ ", "diff --git ")):
            if in_hunk:
                if _hunk_complete():
                    last_good_end = running_offset
                else:
                    return diff[:last_good_end] if last_good_end > 0 else None
            in_hunk = False
            file_header_end = running_offset + line_len
        elif in_hunk:
            if stripped.startswith("\\"):
                pass  # "\ No newline at end of file"
            elif stripped.startswith("+"):
                seen_new += 1
            elif stripped.startswith("-"):
                seen_old += 1
            elif stripped.startswith(" ") or stripped == "":
                seen_old += 1
                seen_new += 1
            else:
                # Garbage between hunks — rewind to the last complete
                # boundary.
                if _hunk_complete():
                    last_good_end = running_offset
                return diff[:last_good_end] if last_good_end > 0 else None
        running_offset += line_len

    # End of input: if the trailing hunk completed cleanly, accept the
    # whole diff. Otherwise return the prefix of complete hunks.
    if in_hunk and _hunk_complete():
        last_good_end = running_offset
    if last_good_end == 0:
        return None
    salvaged = diff[:last_good_end]
    # Make sure it ends with a newline so git apply parses cleanly.
    if not salvaged.endswith("\n"):
        salvaged += "\n"
    return salvaged


def _read_handler_snippet(repo_root: Path, rel: str, line: int) -> str:
    """Pull ~25 lines centered on the handler's route declaration."""
    p = (repo_root / rel).resolve()
    try:
        p.relative_to(repo_root.resolve())
    except (ValueError, OSError):
        return ""
    if not p.is_file():
        return ""
    try:
        lines = p.read_text(errors="replace").splitlines()
    except OSError:
        return ""
    start = max(0, line - 5)
    end = min(len(lines), line + 25)
    return "\n".join(f"{i+1:>5} | {lines[i]}" for i in range(start, end))


# ── Top-level entrypoints ───────────────────────────────────────────


async def _load_finding_for_sast(
    db: AsyncSession, finding_id: str,
) -> RepoFinding | DbFinding | None:
    """SAST findings flow through pencheff and land in ``findings`` (DAST
    table) when they're produced via the repo-attach flow we shipped, but
    the standalone repo-scan task writes to ``repo_findings``. Try both.
    """
    df = (await db.execute(
        select(DbFinding).where(DbFinding.id == finding_id)
    )).scalar_one_or_none()
    if df:
        return df
    return (await db.execute(
        select(RepoFinding).where(RepoFinding.id == finding_id)
    )).scalar_one_or_none()


async def _load_dast_finding(
    db: AsyncSession, finding_id: str,
) -> DbFinding | None:
    return (await db.execute(
        select(DbFinding).where(DbFinding.id == finding_id)
    )).scalar_one_or_none()


async def _attached_repos_for_target(
    db: AsyncSession, target_id: str,
) -> list[Repository]:
    rows = (await db.execute(
        select(Repository)
        .join(TargetRepository, TargetRepository.repository_id == Repository.id)
        .where(TargetRepository.target_id == target_id)
    )).scalars().all()
    return list(rows)


async def propose_fix(
    db: AsyncSession,
    req: ProposalRequest,
) -> tuple[FixProposal, str | None]:
    """Build a draft FixProposal. Caller commits.

    Returns ``(proposal, notice)`` where ``notice`` is a user-facing message
    (e.g. the deterministic-fallback notice when the org is over its monthly
    AI allotment), or ``None``.

    SCA findings are detected up-front and routed to a deterministic
    bumper that bypasses the LLM and quota gates entirely — a manifest
    version edit doesn't need an LLM, and we don't want to bill for it.
    """
    sca = await _maybe_propose_sca(db, req)
    if sca is not None:
        return sca, None
    if req.finding_kind == "sast":
        return await _propose_sast(db, req)
    if req.finding_kind == "dast":
        return await _propose_dast(db, req)
    raise ProposerError("bad_kind", f"Unknown finding_kind: {req.finding_kind}")


async def _maybe_propose_sca(
    db: AsyncSession, req: ProposalRequest,
) -> FixProposal | None:
    """Return a SCA proposal if the finding has an SCA autofix payload, else
    ``None`` (in which case the caller falls through to SAST/DAST flow)."""
    if req.finding_kind == "dast":
        f = await _load_dast_finding(db, req.finding_id)
    elif req.finding_kind == "sast":
        f = await _load_finding_for_sast(db, req.finding_id)
    else:
        return None
    if f is None:
        return None
    autofix = _sca_autofix_payload(getattr(f, "evidence", None))
    if not autofix:
        return None
    return await _propose_sca(db, req, finding=f, autofix=autofix)


async def _propose_sast(db: AsyncSession, req: ProposalRequest) -> tuple[FixProposal, str | None]:
    f = await _load_finding_for_sast(db, req.finding_id)
    if f is None:
        raise ProposerError("not_found", "SAST finding not found.")

    # RepoFinding (rows produced by the standalone repo-scan task — what
    # the dashboard's "Fix all findings" on /repos/scans/* hits) have a
    # different shape than DbFinding-routed SAST: they store the path
    # directly in ``file_path`` and the repository on ``repository_id``,
    # so there's no ``repo://name/path`` endpoint to parse.
    rel_path: str | None
    repo: Repository | None = None
    if isinstance(f, RepoFinding):
        rel_path = f.file_path or None
        if not rel_path:
            raise ProposerError(
                "no_file",
                "Repo finding has no file_path — cannot land a patch.",
            )
        if f.repository_id:
            repo = (await db.execute(
                select(Repository).where(Repository.id == f.repository_id)
            )).scalar_one_or_none()
        if repo is None:
            raise ProposerError(
                "no_repo",
                "Repository row for this finding has been deleted.",
            )
        if repo.workspace_id != req.workspace_id:
            raise ProposerError(
                "no_repo",
                "Repository does not belong to the active workspace.",
            )
        # Build a minimal autofix payload from the scanner-native fields
        # so the deterministic / recipe paths can pick it up. Semgrep
        # findings carry their full payload in ``raw``; use it when present.
        autofix = (f.raw or {}).get("autofix") if isinstance(f.raw, dict) else None
        if autofix is None:
            autofix = {
                "kind": "text_replace",
                "start_line": f.line_start,
                "end_line": f.line_end or f.line_start,
                "tool": f.scanner,
            }
        parameter = str(f.line_start) if f.line_start else None
    else:
        evidence = list(getattr(f, "evidence", None) or [])
        autofix = _autofix_payload(evidence)
        endpoint = getattr(f, "endpoint", None)
        parameter = getattr(f, "parameter", None)
        parsed = _parse_repo_endpoint(endpoint)
        if not parsed:
            raise ProposerError(
                "no_repo", "Finding endpoint does not point at a repo.",
            )
        repo_name, rel_path = parsed
        repo = await _repo_for_sast(
            db, workspace_id=req.workspace_id, repo_name=repo_name,
        )
        if repo is None:
            raise ProposerError(
                "no_repo",
                f"No matching repository for `{repo_name}` in workspace.",
            )
    # Materialise a working tree on demand. For local-path repos this just
    # returns ``local_path``; for GitHub repos it shallow-clones (with the
    # right token) into a per-repo cache and refreshes if it's been a while.
    # Either way, the proposer never has to bail on "no on-disk working tree".
    repo_root = await _materialise_workspace(db, repo)

    # Resolve org BYO provider early — when active it bypasses the monthly
    # AI-fix quota entirely (the org is paying their own provider directly).
    from .llm_providers.resolver import resolve_chat_client as _resolve_chat_client
    _byo_client = await _resolve_chat_client(req.org_id, db)

    # Monthly AI-fix quota gate. Never blocks: when the org is over its
    # monthly allotment (and not in beta) preflight returns allow_llm=False and
    # we degrade to the deterministic scanner-native path instead of the LLM.
    charge = await fix_quota.preflight(
        db, req.org_id, kind="sast", scan_id=req.scan_id,
    )
    # BYO active → quota is irrelevant; the org pays their own provider.
    degraded = not charge.allow_llm if _byo_client is None else False

    # Deterministic branch — used when over quota (degraded) or when the
    # global LLM-only switch is off. Tries the scanner autofix; a successful
    # diff is returned with the degradation notice so the UI can explain it.
    if (degraded or not USE_LLM_ONLY) and autofix and repo_root:
        line_value = parameter or autofix.get("start_line")
        try:
            line = int(line_value) if line_value is not None else None
        except (TypeError, ValueError):
            line = None
        result = _scanner_autofix_diff(
            repo_root=repo_root, rel_path=rel_path, line=line, autofix=autofix,
        )
        if result is not None:
            diff, _modified = result
            return FixProposal(
                org_id=req.org_id, workspace_id=req.workspace_id,
                scan_id=req.scan_id, repo_scan_id=req.repo_scan_id,
                finding_kind="sast", finding_id=req.finding_id,
                repository_id=repo.id, status="draft", source="scanner",
                diff=diff, target_files=[rel_path], created_by=req.user_id,
            ), (fix_quota.DETERMINISTIC_FALLBACK_NOTICE if degraded else None)
        # Autofix existed but couldn't be applied (file changed since the
        # scan, weird encoding, etc.) — fall through.

    if degraded:
        # Over the monthly AI allotment and no scanner-native fix is available
        # for this finding. Surface the notice as the outcome rather than
        # spending an LLM call the org no longer has budget for.
        raise ProposerError(
            "ai_limit_no_deterministic",
            f"{fix_quota.DETERMINISTIC_FALLBACK_NOTICE} No scanner-native fix "
            f"is available for this finding — open it manually to draft a patch.",
        )

    if not repo_root:
        # _materialise_workspace exhausted every clone path (no token,
        # default branch missing, etc.). This should be rare in practice
        # since every github repo we accept either has an installation,
        # a stored PAT, or is publicly cloneable.
        raise ProposerError(
            "clone_failed",
            "Could not access the source code for this repository. "
            "Confirm the repo is reachable from this server and try again.",
        )
    if line_value := (parameter or 1):
        try:
            line = int(line_value)
        except (TypeError, ValueError):
            line = 1
    else:
        line = 1
    file_full_path = (repo_root / rel_path).resolve()
    try:
        full_text = file_full_path.read_text(errors="replace")
    except OSError as exc:
        raise ProposerError("file_read_failed", str(exc))
    snippet = _read_handler_snippet(repo_root, rel_path, line)
    plan = await fix_quota.plan_for(db, req.org_id)
    client = FixLLMClient(model=_fix_model_for_plan(plan))
    org_client = _byo_client
    if org_client is not None:
        client.set_org_client(org_client)
    if org_client is None and not client.enabled:
        raise ProposerError(
            "llm_unavailable",
            "Fix-LLM is not configured (FIX_LLM_API_KEY missing).",
        )
    res = await client.propose_sast_patch(
        title=f.title, description=f.description or "",
        file_path=rel_path, snippet=snippet, full_file=full_text,
    )
    if not res.text:
        raise ProposerError("llm_failed", "Fix-LLM returned no patch.")
    diff = _strip_code_fence(res.text)
    cost = (
        fix_quota.cost_for_call(res.input_tokens, res.output_tokens)
        if org_client is None and charge is not None and not charge.free else 0.0
    )
    proposal = FixProposal(
        org_id=req.org_id, workspace_id=req.workspace_id,
        scan_id=req.scan_id, repo_scan_id=req.repo_scan_id,
        finding_kind="sast", finding_id=req.finding_id,
        repository_id=repo.id, status="draft", source="llm",
        diff=diff, target_files=[rel_path], created_by=req.user_id,
        llm_input_tokens=res.input_tokens, llm_output_tokens=res.output_tokens,
        cost_usd=cost,
    )
    db.add(proposal)
    await db.flush()
    if org_client is None and charge is not None:
        await fix_quota.record_usage(
            db, org_id=req.org_id, scan_id=req.scan_id, proposal_id=proposal.id,
            kind="sast", model=client.model,
            input_tokens=res.input_tokens, output_tokens=res.output_tokens,
            free=charge.free,
        )
    return proposal, None


async def _propose_dast(db: AsyncSession, req: ProposalRequest) -> tuple[FixProposal, str | None]:
    f = await _load_dast_finding(db, req.finding_id)
    if f is None:
        raise ProposerError("not_found", "DAST finding not found.")
    if not f.scan_id:
        raise ProposerError("no_scan", "DAST finding has no scan link.")
    # Resolve the target by walking back through the scan record.
    from ..db.models import Scan as _Scan
    scan_row = (await db.execute(
        select(_Scan).where(_Scan.id == f.scan_id)
    )).scalar_one_or_none()
    if scan_row is None:
        raise ProposerError("no_scan", "Scan row for this finding has been deleted.")
    target = (await db.execute(
        select(Target).where(Target.id == scan_row.target_id)
    )).scalar_one_or_none()
    if target is None:
        raise ProposerError("no_target", "Target for this scan no longer exists.")
    repos = await _attached_repos_for_target(db, target.id)
    if not repos:
        raise ProposerError(
            "no_attached_repos",
            "DAST fixes require at least one source repo attached to the target.",
        )

    # Materialise (or refresh) every attached repo concurrently. Whichever
    # succeed are the ones we hand to route_index; if a single repo fails to
    # clone, the others still take part in the lookup. We only bail when
    # every repo failed.
    materialise_tasks = [_materialise_workspace(db, r) for r in repos]
    materialised = await asyncio.gather(*materialise_tasks, return_exceptions=True)
    repo_paths: list[tuple[Repository, Path]] = []
    for r, mat in zip(repos, materialised):
        if isinstance(mat, Path):
            repo_paths.append((r, mat))
        elif isinstance(mat, Exception):
            log.warning("materialise %s for DAST fix raised: %s", r.full_name, mat)
    if not repo_paths:
        raise ProposerError(
            "clone_failed",
            "Could not access source code for any attached repo. "
            "Confirm the repos are reachable from this server and try again.",
        )

    url_path = _path_from_endpoint(f.endpoint or "")
    method = _method_from_evidence(getattr(f, "evidence", None))
    parameter = f.parameter

    candidates = route_index.find_provenance(
        [p for _, p in repo_paths],
        method=method, url_path=url_path, parameter=parameter, top_k=8,
    )
    if not candidates:
        # find_provenance always returns at least a README/repo-root
        # fallback, so the only way we get here is a repo with literally
        # no readable files. Surface a one-line apology rather than an
        # error so the user still understands why the button stopped.
        raise ProposerError(
            "empty_repo",
            "Attached repo has no readable files to land a patch on.",
        )

    confidence_threshold = 0.65
    top_root, top_match = candidates[0]
    repo_for_top = next(r for r, p in repo_paths if p == top_root)

    # Resolve org BYO provider early — when active it bypasses the monthly
    # AI-fix quota entirely (the org is paying their own provider directly).
    from .llm_providers.resolver import resolve_chat_client as _resolve_chat_client_dast
    _byo_client_dast = await _resolve_chat_client_dast(req.org_id, db)

    # Monthly AI-fix quota gate. Never blocks: when over the monthly allotment
    # preflight returns allow_llm=False and we degrade to deterministic
    # provenance + recipe / comment-only patches instead of the LLM.
    charge = await fix_quota.preflight(
        db, req.org_id, kind="dast", scan_id=req.scan_id,
    )
    # BYO active → quota is irrelevant; the org pays their own provider.
    degraded = not charge.allow_llm if _byo_client_dast is None else False
    used_llm = False
    llm_in = llm_out = 0
    reasoning = top_match.reason

    plan = await fix_quota.plan_for(db, req.org_id)
    client = FixLLMClient(model=_fix_model_for_plan(plan))
    if _byo_client_dast is not None:
        client.set_org_client(_byo_client_dast)
    # Provenance ranking runs through the LLM unless the org is over quota
    # (degraded), in which case we keep the heuristic top candidate.
    if client.enabled and not degraded and (
        USE_LLM_ONLY or (charge is not None and (charge.free or req.allow_payg))
    ):
        ranked = await client.rank_dast_candidates(
            title=f.title, description=f.description or "",
            url_path=url_path, method=method, parameter=parameter,
            candidates=[
                {**m.route.to_dict(), "heuristic_confidence": m.confidence,
                 "heuristic_reason": m.reason}
                for _, m in candidates
            ],
        )
        used_llm = True
        llm_in, llm_out = ranked.input_tokens, ranked.output_tokens
        if ranked.text:
            picked = _pick_from_ranking(ranked.text, candidates)
            if picked is not None:
                top_root, top_match = picked
                repo_for_top = next(r for r, p in repo_paths if p == top_root)
                reasoning = (
                    f"LLM ranked: {top_match.reason}; "
                    f"heuristic backup: {top_match.confidence:.2f}"
                )
    elif client and not client.enabled:
        log.info("Fix-LLM not configured; using heuristic provenance only.")

    rel = top_match.route.file
    line = top_match.route.line

    # Reject documentation / metadata files up-front. ``route_index``
    # falls back to README.md (or similar) when it can't find a code
    # candidate for the live route, but the patch LLM can't produce a
    # meaningful fix on a Markdown / RST / LICENSE file — when forced
    # to "MUST produce a real diff" by the system prompt, the model
    # hallucinates plausible-looking code into the wrong file (e.g.
    # synthesising a Flask app inside README.md). Better to surface
    # this as "no source-code anchor" so the bulk router drops the
    # finding silently and the user only sees fixes that landed on
    # actual handlers.
    if _is_non_code_file(rel):
        log.info(
            "DAST fix: top route candidate %s is a non-code file — "
            "no source-code handler exists in the attached repos for "
            "this finding; raising no_code_anchor.",
            rel,
        )
        raise ProposerError(
            "no_code_anchor",
            f"The proposer routed this finding to `{rel}`, which is a "
            f"documentation / metadata file rather than source code. "
            f"There's no handler in the attached repos to patch — "
            f"re-attach the application's source repo or re-scan.",
        )

    snippet = _read_handler_snippet(top_root, rel, line)

    target_files: list[str] = [rel]
    diff: str | None = None

    # Primary path: ask the LLM for a real patch on the candidate file using
    # the dedicated DAST prompt — anchored on the actual live evidence.
    # Skipped when over quota (degraded) so no LLM budget is spent.
    if USE_LLM_ONLY and client.enabled and not degraded:
        target_path = (top_root / rel).resolve()
        file_text = ""
        try:
            target_path.relative_to(top_root.resolve())
            if target_path.is_file():
                file_text = target_path.read_text(errors="replace")
        except (OSError, ValueError):
            file_text = ""
        if not file_text:
            log.warning(
                "DAST fix: candidate file %s missing in %s — cannot patch",
                rel, top_root,
            )
            raise ProposerError(
                "no_handler_file",
                f"Pencheff routed the fix to `{rel}` but the file isn't "
                f"present in the materialised repo. Re-run the scan against "
                f"the latest commit.",
            )
        evidence_excerpt = _evidence_excerpt(getattr(f, "evidence", None))
        patch_res = await client.propose_dast_patch(
            title=f.title, description=f.description or "",
            file_path=rel, snippet=snippet, full_file=file_text,
            method=method, url_path=url_path, parameter=parameter,
            evidence_excerpt=evidence_excerpt,
        )
        llm_in += patch_res.input_tokens
        llm_out += patch_res.output_tokens

        # Validate the LLM output. ``_accept_llm_diff`` takes the raw
        # stripped diff when it has at least one real (non-comment)
        # ``+`` line — the applier already runs ``git apply --recount``
        # / ``--ignore-whitespace`` / ``--3way`` to repair line-count
        # and whitespace drift, so rejecting here for those would just
        # be duplicating work we know succeeds downstream. Salvage is
        # the fallback for *truncated* diffs (model hit token cap
        # mid-hunk) — we slice back to the last complete hunk so a
        # half-finished response is still usable.
        diff = _accept_llm_diff(patch_res.text)
        if diff:
            used_llm = True

        # Retry once with negative feedback — showing the model its own
        # bad output reliably converts most second attempts into real
        # patches. ``deepseek-v4-flash`` in particular needs the kick.
        retry_text: str | None = None
        if not _diff_has_real_changes(diff):
            log.warning(
                "DAST fix: first attempt produced no real code changes "
                "for finding %s (text_len=%d, snippet=%r) — retrying "
                "with negative feedback.",
                req.finding_id, len(patch_res.text or ""),
                (patch_res.text or "")[:200],
            )
            retry_res = await client.propose_dast_patch(
                title=f.title, description=f.description or "",
                file_path=rel, snippet=snippet, full_file=file_text,
                method=method, url_path=url_path, parameter=parameter,
                evidence_excerpt=evidence_excerpt,
                previous_attempt=patch_res.text or "",
            )
            llm_in += retry_res.input_tokens
            llm_out += retry_res.output_tokens
            retry_text = retry_res.text or ""
            retry_diff = _accept_llm_diff(retry_text)
            if retry_diff:
                diff = retry_diff
                used_llm = True

        if not _diff_has_real_changes(diff):
            log.warning(
                "DAST fix: both attempts produced no real code changes "
                "for finding %s (retry_text_len=%d, retry_snippet=%r) — "
                "aborting with llm_failed.",
                req.finding_id,
                len(retry_text or ""),
                (retry_text or "")[:200],
            )
            raise ProposerError(
                "llm_failed",
                "Fix-LLM did not return a usable code patch for this "
                "finding even after a corrective retry. The handler "
                "source may be too thin to auto-patch — open the "
                "finding manually to draft a fix, or attach the full "
                "repo and retry.",
            )

    # Deterministic fallback — recipe registry. Runs when over quota
    # (degraded) or when the global LLM-only switch is off.
    if diff is None and (degraded or not USE_LLM_ONLY):
        recipe = fix_recipes.find_recipe(f) if not used_llm else None
        if recipe is not None:
            recipe_changes = fix_recipes.apply_recipe(
                recipe, top_root, primary_file=rel,
            )
            if recipe_changes:
                diff_chunks = [
                    _diff_for_change(rel_p, orig, mod)
                    for (rel_p, orig, mod) in recipe_changes
                ]
                diff = "".join(diff_chunks)
                target_files = [rel_p for (rel_p, _, _) in recipe_changes]
                reasoning = (
                    f"{reasoning}; applied recipe `{recipe.name}` to "
                    f"{len(recipe_changes)} file(s)"
                )

    # Comment-only fallback. Acceptable when the LLM is genuinely off (no API
    # key) OR when the org is over quota (degraded) — in both cases we drop a
    # TODO marker on the handler so the developer still gets a starting point.
    # When the LLM was available and not degraded, no diff means a real failure.
    if diff is None:
        if client.enabled and not degraded:
            raise ProposerError(
                "llm_failed",
                "Fix-LLM is configured but produced no usable patch. "
                "See worker logs for details.",
            )
        diff = _comment_only_patch(rel, line, top_match.route, f, snippet)

    proposal = FixProposal(
        org_id=req.org_id, workspace_id=req.workspace_id,
        scan_id=req.scan_id, repo_scan_id=req.repo_scan_id,
        finding_kind="dast", finding_id=req.finding_id,
        repository_id=repo_for_top.id, status="draft",
        source="llm" if used_llm else "scanner",
        diff=diff, target_files=target_files,
        provenance_confidence=top_match.confidence,
        provenance_reasoning=reasoning,
        llm_input_tokens=llm_in or None,
        llm_output_tokens=llm_out or None,
        cost_usd=(
            fix_quota.cost_for_call(llm_in, llm_out)
            if _byo_client_dast is None and used_llm and charge and not charge.free else 0.0
        ),
        created_by=req.user_id,
    )
    if top_match.confidence < confidence_threshold:
        # Still emit the proposal but mark a softer error so the UI can warn.
        proposal.error = (
            f"Low-confidence provenance ({top_match.confidence:.0%}). "
            "Verify the file and line before opening the PR."
        )
    db.add(proposal)
    await db.flush()
    if _byo_client_dast is None and used_llm and charge is not None:
        await fix_quota.record_usage(
            db, org_id=req.org_id, scan_id=req.scan_id, proposal_id=proposal.id,
            kind="dast", model=(client.model if client else "n/a"),
            input_tokens=llm_in, output_tokens=llm_out,
            free=charge.free,
        )
    return proposal, (fix_quota.DETERMINISTIC_FALLBACK_NOTICE if degraded else None)


# ── Misc helpers ────────────────────────────────────────────────────


def _strip_code_fence(text: str) -> str:
    text = text.strip()
    if text.startswith("```"):
        # Strip the opening fence + any language tag
        first = text.find("\n")
        if first != -1:
            text = text[first + 1:]
        if text.endswith("```"):
            text = text[: -3]
    return text.strip() + "\n"


def _path_from_endpoint(endpoint: str) -> str:
    try:
        u = urlparse(endpoint)
        return u.path or "/"
    except ValueError:
        return endpoint


def _method_from_evidence(evidence: list[dict] | None) -> str | None:
    for ev in evidence or []:
        m = ev.get("request_method")
        if m and m not in ("SAST", "SAST_AUTOFIX"):
            return m
    return None


def _pick_from_ranking(
    text: str,
    candidates: list[tuple[Path, route_index.RouteMatch]],
) -> tuple[Path, route_index.RouteMatch] | None:
    try:
        data = json.loads(text)
    except (TypeError, ValueError):
        return None
    items = data.get("ranked") if isinstance(data, dict) else None
    if not isinstance(items, list) or not items:
        return None
    first = items[0]
    if not isinstance(first, dict):
        return None
    idx = first.get("index")
    try:
        idx = int(idx)
    except (TypeError, ValueError):
        return None
    if 0 <= idx < len(candidates):
        # Override confidence and reason from the LLM payload.
        path, match = candidates[idx]
        new_conf = first.get("confidence")
        new_reason = first.get("reason") or match.reason
        if isinstance(new_conf, (int, float)):
            match.confidence = max(0.0, min(1.0, float(new_conf)))
        match.reason = str(new_reason)
        return path, match
    return None


_COMMENT_STYLE: dict[str, tuple[str, str]] = {
    # suffix → (line_prefix, block_close_for_multiline)
    ".py": ("# ", ""),
    ".rb": ("# ", ""),
    ".sh": ("# ", ""),
    ".yml": ("# ", ""),
    ".yaml": ("# ", ""),
    ".js": ("// ", ""),
    ".jsx": ("// ", ""),
    ".ts": ("// ", ""),
    ".tsx": ("// ", ""),
    ".go": ("// ", ""),
    ".java": ("// ", ""),
    ".kt": ("// ", ""),
    ".rs": ("// ", ""),
    ".css": ("/* ", " */"),
    ".html": ("<!-- ", " -->"),
    ".md": ("<!-- ", " -->"),
    ".rst": (".. ", ""),
}


def _comment_lines_for(rel: str, lines: list[str]) -> list[str]:
    suffix = "." + rel.rsplit(".", 1)[-1].lower() if "." in rel else ""
    prefix, suffix_close = _COMMENT_STYLE.get(suffix, ("# ", ""))
    if suffix_close:
        # Wrap the whole block in one comment for languages that don't
        # support per-line comments cleanly.
        body = "\n".join(lines)
        return [prefix + body + suffix_close]
    return [prefix + ln for ln in lines]


def _comment_only_patch(
    rel: str, line: int, route: route_index.Route,
    finding: DbFinding, snippet: str,
) -> str:
    """When we don't generate a real code patch (heuristic provenance only),
    drop a TODO block above the handler so the developer's PR is still a
    useful starting point. Comment style adapts to the file extension so
    the block is syntactically valid in Python, JS, Markdown, etc.
    """
    method = route.method
    pattern = route.pattern
    handler = route.handler or "(handler)"
    body = [
        f"TODO(pencheff): {finding.title}",
    ]
    if finding.description:
        body.append(finding.description.strip().splitlines()[0][:140])
    body.append(f"Live route: {method} {pattern}  →  handler {handler}")
    body.append(f"Severity: {finding.severity}.  Endpoint: {finding.endpoint}")
    commented = _comment_lines_for(rel, body)
    line = max(1, line)
    new_count = len(commented)
    return (
        f"--- a/{rel}\n"
        f"+++ b/{rel}\n"
        f"@@ -{line},0 +{line},{new_count} @@\n"
        + "".join(f"+{ln}\n" for ln in commented)
    )


# ── SCA: deterministic dependency-version bump → unified diff ──────


_LOCKFILE_INSTALLERS: dict[str, str] = {
    "PyPI":      "pip install -r requirements.txt   # or `poetry lock` / `pipenv lock`",
    "npm":       "npm install   # or `yarn install` / `pnpm install`",
    "Go":        "go mod tidy",
    "crates.io": "cargo update -p <package>",
    "RubyGems":  "bundle update <package>",
    "Packagist": "composer update <package>",
    "Maven":     "mvn -U dependency:resolve",
}


def _resolve_manifest_in_repo(repo_root: Path, manifest_hint: str) -> str | None:
    """Find the manifest file inside the materialised repo.

    ``manifest_hint`` is whatever ``dependency_scan`` recorded — ideally a
    path relative to the scan root, but it can fall back to a basename
    (e.g. when the scan was run from CLI with absolute paths). We prefer
    an exact relative match; otherwise we walk and pick the closest match
    by basename.
    """
    if not manifest_hint:
        return None
    candidate = (repo_root / manifest_hint).resolve()
    try:
        candidate.relative_to(repo_root.resolve())
        if candidate.is_file():
            return str(candidate.relative_to(repo_root.resolve()))
    except (ValueError, OSError):
        pass
    base = Path(manifest_hint).name
    if not base:
        return None
    matches: list[Path] = []
    try:
        for p in repo_root.rglob(base):
            if p.is_file():
                matches.append(p)
    except OSError:
        return None
    if not matches:
        return None
    # Pick the shortest path (closest to the repo root) — canonical builds
    # put the primary manifest at the top level.
    matches.sort(key=lambda p: len(p.parts))
    try:
        return str(matches[0].resolve().relative_to(repo_root.resolve()))
    except (ValueError, OSError):
        return None


async def _resolve_repo_for_sca(
    db: AsyncSession,
    *,
    workspace_id: str,
    finding: Any,
) -> Repository | None:
    """SCA findings can land in either ``findings`` (DAST table — produced
    by the OSV scanner inside a regular scan) or ``repo_findings`` (when
    pip-audit / npm-audit ran during a repo scan). Resolve the repo from
    whichever fields are available.
    """
    repo_id = getattr(finding, "repository_id", None)
    if repo_id:
        repo = (await db.execute(
            select(Repository).where(Repository.id == repo_id)
        )).scalar_one_or_none()
        if repo and repo.workspace_id == workspace_id:
            return repo
    # DAST-table SCA: walk back through the scan's target → attached repos.
    scan_id = getattr(finding, "scan_id", None)
    if scan_id:
        from ..db.models import Scan as _Scan
        scan_row = (await db.execute(
            select(_Scan).where(_Scan.id == scan_id)
        )).scalar_one_or_none()
        if scan_row is not None:
            repos = await _attached_repos_for_target(db, scan_row.target_id)
            # Single attached repo is the unambiguous case. Multi-repo
            # SCA needs schema-level provenance we don't have yet, so
            # for now we only auto-fix when there's exactly one repo.
            if len(repos) == 1:
                return repos[0]
    return None


def _sca_pr_body_addendum(autofix: dict, ecosystem: str) -> str:
    installer = _LOCKFILE_INSTALLERS.get(ecosystem, "your package manager's install command")
    return (
        f"\n\n**Lockfile note:** this PR bumps only the top-level manifest. "
        f"Run `{installer}` locally before merging so the lockfile picks up the new version. "
        f"Pencheff intentionally does not edit lockfiles to avoid integrity-hash drift."
    )


async def _propose_sca(
    db: AsyncSession,
    req: ProposalRequest,
    *,
    finding: Any,
    autofix: dict,
) -> FixProposal:
    """Deterministic SCA fix flow: bump the manifest in the materialised
    repo, build the diff, save a draft proposal. No LLM, no quota."""
    repo = await _resolve_repo_for_sca(
        db, workspace_id=req.workspace_id, finding=finding,
    )
    if repo is None:
        raise ProposerError(
            "no_repo",
            "SCA fix requires a single repository attached to this scan's target. "
            "Attach the repo first or open the fix from the repository view.",
        )
    repo_root = await _materialise_workspace(db, repo)
    if not repo_root:
        raise ProposerError(
            "clone_failed",
            "Could not access the source for this repository. "
            "Confirm Pencheff has install / clone access and try again.",
        )
    manifest_hint = autofix.get("manifest_path") or getattr(finding, "endpoint", "") or ""
    rel_path = _resolve_manifest_in_repo(repo_root, manifest_hint)
    if rel_path is None:
        raise ProposerError(
            "no_manifest",
            f"Could not locate manifest `{manifest_hint or '?'}` inside the repo. "
            f"Re-run the scan or attach a repo whose tree matches the SCA report.",
        )
    file_path = (repo_root / rel_path).resolve()
    try:
        original = file_path.read_text(errors="replace")
    except OSError as exc:
        raise ProposerError("file_read_failed", str(exc)) from exc
    modified = _dependency_upgrade_patch(original, rel_path, autofix)
    if modified is None or modified == original:
        raise ProposerError(
            "no_match",
            f"`{autofix.get('package')}` was not found in `{rel_path}`. "
            f"It may live in a different manifest, in a transitive lockfile, or have already been removed.",
        )
    diff = _diff_for_change(rel_path, original, modified)
    finding_kind = (
        "sast" if isinstance(finding, RepoFinding) else "dast"
    )
    proposal = FixProposal(
        org_id=req.org_id,
        workspace_id=req.workspace_id,
        scan_id=req.scan_id,
        repo_scan_id=req.repo_scan_id,
        finding_kind=finding_kind,
        finding_id=req.finding_id,
        repository_id=repo.id,
        status="draft",
        source="scanner",
        diff=diff,
        target_files=[rel_path],
        created_by=req.user_id,
    )
    # Stash the addendum so the PR body explains the lockfile dance. The
    # _format_pr_body helper appends ``proposal.notes`` when present (added
    # alongside this commit; safe to omit if the column doesn't exist yet).
    notes = _sca_pr_body_addendum(autofix, autofix.get("ecosystem") or "")
    if hasattr(proposal, "notes"):
        proposal.notes = notes
    return proposal


# ── Bulk-apply regeneration ─────────────────────────────────────────


async def regenerate_diff_against_workdir(
    db: AsyncSession,
    proposal: FixProposal,
    workdir_root: Path,
) -> str | None:
    """Re-call the fix-LLM using the file content currently on disk in
    ``workdir_root`` (the bulk-apply clone) and return a fresh diff.

    Bulk apply uses a fresh clone of the default branch, but proposals
    were generated against the materialised workspace cache — these
    can drift apart. Regenerating against the workdir guarantees the
    diff was written for the file we're about to patch.

    Strategy by ``finding_kind``:
      * **sast** — re-run the SAST patch prompt with the workdir's
        current file as ``full_file``.
      * **dast** — re-run the DAST patch prompt the same way. Uses
        the same evidence + route metadata the original proposal had.
      * **sca**  — recompute the deterministic version-bump patch.
        No LLM call needed; cheap.

    Returns the new diff string on success, ``None`` if regeneration
    can't produce a usable patch.
    """
    target_files = list(proposal.target_files or [])
    if not target_files:
        log.info("regenerate: proposal %s has no target_files", proposal.id)
        return None
    rel = target_files[0]
    file_path = (workdir_root / rel).resolve()
    try:
        file_path.relative_to(workdir_root.resolve())
    except (ValueError, OSError):
        log.info("regenerate: rel_path escapes workdir for proposal %s", proposal.id)
        return None
    if not file_path.is_file():
        log.info("regenerate: file %s not present in workdir", rel)
        return None
    try:
        file_text = file_path.read_text(errors="replace")
    except OSError as exc:
        log.info("regenerate: file_read_failed for proposal %s: %s", proposal.id, exc)
        return None

    finding = await _load_workdir_regen_finding(db, proposal)
    if finding is None:
        log.info("regenerate: source finding %s no longer exists", proposal.finding_id)
        return None

    # SCA path — deterministic, no LLM.
    autofix = _sca_autofix_payload(getattr(finding, "evidence", None))
    if autofix:
        modified = _dependency_upgrade_patch(file_text, rel, autofix)
        if modified is None or modified == file_text:
            return None
        return _diff_for_change(rel, file_text, modified)

    client = FixLLMClient()
    from .llm_providers.resolver import resolve_chat_client as _resolve_regen
    _byo_regen = await _resolve_regen(proposal.org_id, db)
    if _byo_regen is not None:
        client.set_org_client(_byo_regen)
    elif not client.enabled:
        log.info("regenerate: fix-LLM disabled — cannot retry proposal %s", proposal.id)
        return None

    if proposal.finding_kind == "sast":
        snippet = _read_handler_snippet(workdir_root, rel, 1)
        res = await client.propose_sast_patch(
            title=finding.title, description=finding.description or "",
            file_path=rel, snippet=snippet, full_file=file_text,
        )
        return _accept_llm_diff(res.text)

    if proposal.finding_kind == "dast":
        url_path = _path_from_endpoint(getattr(finding, "endpoint", "") or "")
        method = _method_from_evidence(getattr(finding, "evidence", None))
        parameter = getattr(finding, "parameter", None)
        evidence_excerpt = _evidence_excerpt(getattr(finding, "evidence", None))
        # Take a fresh snippet from the workdir so the LLM sees the
        # exact lines we're about to patch — matches the apply target.
        snippet = _read_handler_snippet(workdir_root, rel, 1)
        res = await client.propose_dast_patch(
            title=finding.title, description=finding.description or "",
            file_path=rel, snippet=snippet, full_file=file_text,
            method=method, url_path=url_path, parameter=parameter,
            evidence_excerpt=evidence_excerpt,
        )
        return _accept_llm_diff(res.text)

    return None


def _accept_llm_diff(text: str | None) -> str | None:
    """Apply the proposer's "raw first, salvage on truncation" policy.

    Returns the raw diff when it carries at least one real (non-comment)
    ``+`` line — the applier already repairs line-count and whitespace
    drift, so we don't reject for those here. Falls back to
    ``_diff_salvage`` only when the raw output failed the real-changes
    check (i.e. the trailing hunk was truncated mid-stream and salvage
    can recover earlier complete hunks).
    """
    raw = _strip_code_fence(text or "")
    if _diff_has_real_changes(raw):
        return raw
    salvaged = _diff_salvage(raw)
    return salvaged if _diff_has_real_changes(salvaged) else None


async def _load_workdir_regen_finding(
    db: AsyncSession, proposal: FixProposal,
):
    """Look up the finding row that backs ``proposal``. SAST proposals
    can come from either ``findings`` (DAST table — repo-attach flow)
    or ``repo_findings`` (standalone repo-scan). Try both."""
    if proposal.finding_kind == "dast":
        return await _load_dast_finding(db, proposal.finding_id)
    return await _load_finding_for_sast(db, proposal.finding_id)
