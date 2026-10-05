"""Run a RepoScan: clone the repo, fan out to scanners, persist findings.

Flow (Celery sync task — uses the sync SQLAlchemy engine like the other tasks):
    1. Load the RepoScan + Repository + Integration rows
    2. Mint an installation token
    3. Clone the repo at the scan's commit SHA to a temp dir
    4. Run the selected scanners in parallel subprocesses
    5. Pull Dependabot (GHSA) alerts via the GitHub REST API
    6. Normalize every scanner's output into a shared dict shape
    7. Bulk insert RepoFinding rows, update scan status, clean up
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
import subprocess
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from ..config import get_settings
from ..db.models import Repository, RepoFinding, RepoIntegration, RepoScan
from ..services import github_app, repo_findings
from ..services.repo_filter import clean_repo_dir
from .celery_app import celery_app

log = logging.getLogger(__name__)


def _bench_root() -> Path:
    """Locate the bench/ directory. In Docker the project is laid out as
    /app/apps/api + /app/bench; in a local checkout it's
    <repo>/apps/api + <repo>/bench. Walk up from this file until we find
    a sibling ``bench`` directory, or fall back to the env override."""
    override = os.environ.get("PENCHEFF_BENCH_DIR")
    if override:
        return Path(override)
    start = Path(__file__).resolve()
    for parent in start.parents:
        candidate = parent / "bench"
        if candidate.is_dir():
            return candidate
    return start.parents[3] / "bench"


BENCH_RUNNERS = _bench_root() / "runners"
YARA_RULES = _bench_root() / "rules" / "yara"


@celery_app.task(name="pencheff_api.tasks.repo_scan_task.run_repo_scan")
def run_repo_scan(repo_scan_id: str) -> dict[str, Any]:
    settings = get_settings()
    engine = create_engine(settings.sync_database_url, future=True)

    with Session(engine) as db:
        scan = db.get(RepoScan, repo_scan_id)
        if scan is None:
            return {"ok": False, "error": "scan-not-found"}
        repo = db.get(Repository, scan.repository_id)
        if not repo:
            scan.status = "failed"
            scan.error = "repo-missing"
            scan.completed_at = datetime.now(timezone.utc)
            db.commit()
            return {"ok": False, "error": scan.error}

        # Three valid configurations:
        #   * provider="local" → read from local_path, no integration.
        #   * provider="github" + integration_id set → App-installed clone.
        #   * provider="github" + integration_id NULL → public-URL clone.
        integration = (
            db.get(RepoIntegration, repo.integration_id)
            if repo.integration_id else None
        )

        scan.status = "running"
        scan.started_at = datetime.now(timezone.utc)
        db.commit()

        # Default scanner pack after the CodeQL removal (Phase 0.1):
        # Semgrep OSS + Bandit (Python) + gosec (Go) + Brakeman (Ruby) +
        # ESLint-security (JS/TS) replace CodeQL's primary SAST role,
        # all under permissive licenses (Apache 2.0 / MIT / LGPL via
        # subprocess only). Older scan rows that pinned ``codeql`` get
        # mapped to the new pack at the orchestration step below.
        default_scanners = [
            "semgrep", "bandit", "gosec", "brakeman", "eslint",
            "gitleaks", "ghsa", "yara", "trivy_iac", "checkov",
        ]
        scanners = list(scan.scanners or default_scanners)
        # Back-compat: rewrite the legacy ``codeql`` token onto the new pack.
        if "codeql" in scanners:
            scanners = [s for s in scanners if s != "codeql"]
            for new_name in ("semgrep", "bandit", "gosec", "brakeman", "eslint"):
                if new_name not in scanners:
                    scanners.append(new_name)
        stats: dict[str, Any] = {}
        all_findings: list[dict[str, Any]] = []
        workdir: str | None = None
        token: str | None = None

        try:
            if repo.provider == "local":
                if not repo.local_path or not os.path.isdir(repo.local_path):
                    scan.status = "failed"
                    scan.error = (
                        f"local_path missing or not a directory: {repo.local_path!r}. "
                        "If running the worker in Docker, mount the host path "
                        "into the container and re-register the repo."
                    )
                    scan.completed_at = datetime.now(timezone.utc)
                    db.commit()
                    return {"ok": False, "error": scan.error}

                # Use the user's tree in place. Scanners are read-only; no
                # clone, no copy. The workdir below is *only* for scanner
                # output JSON — the cleanup path operates on workdir, never
                # on repo_path, so the user's tree is never touched.
                workdir = tempfile.mkdtemp(prefix="pencheff-local-scan-")
                repo_path = repo.local_path
                try:
                    subprocess.run(
                        ["git", "-C", repo_path, "pull", "--ff-only"],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        check=False,
                    )
                except Exception:
                    pass
                # Best-effort: capture HEAD SHA if the path is a git repo,
                # so the scan log records what commit got scanned.
                try:
                    sha = subprocess.check_output(
                        ["git", "-C", repo_path, "rev-parse", "HEAD"],
                        stderr=subprocess.DEVNULL, timeout=10,
                    ).decode().strip()
                    if sha:
                        scan.commit_sha = sha
                        scan.ref = "HEAD"
                        db.commit()
                except Exception:
                    pass
            elif integration is not None:
                token = asyncio.run(
                    github_app.get_installation_token(integration.installation_id)
                )

                # Resolve commit SHA if the scan didn't pin one (manual trigger).
                commit_sha = scan.commit_sha
                if scan.trigger == "manual":
                    commit_sha = asyncio.run(
                        github_app.get_default_branch_sha(
                            token, repo.full_name, repo.default_branch
                        )
                    )
                    scan.commit_sha = commit_sha
                    scan.ref = f"refs/heads/{repo.default_branch}"
                    db.commit()
                elif not commit_sha:
                    commit_sha = asyncio.run(
                        github_app.get_default_branch_sha(
                            token, repo.full_name, repo.default_branch
                        )
                    )
                    scan.commit_sha = commit_sha
                    scan.ref = f"refs/heads/{repo.default_branch}"
                    db.commit()

                workdir = tempfile.mkdtemp(prefix="pencheff-repo-scan-")
                repo_path = os.path.join(workdir, "src")
                github_app.clone_with_token(token, repo.full_name, repo_path, sha=commit_sha)
            elif repo.token_encrypted:
                # PAT-authenticated private GitHub repo. The Repository
                # row carries an encrypted Personal Access Token; we
                # decrypt it on the worker side, never log it, and use it
                # as the x-access-token password for ``git clone``.
                from ..services.credentials import decrypt_credentials

                tok_blob = decrypt_credentials(repo.token_encrypted) or {}
                token = tok_blob.get("token") or ""
                if not token:
                    scan.status = "failed"
                    scan.error = (
                        "Stored token is empty — decryption returned no value. "
                        "Re-register the repo with a fresh PAT."
                    )
                    scan.completed_at = datetime.now(timezone.utc)
                    db.commit()
                    return {"ok": False, "error": scan.error}

                commit_sha = scan.commit_sha
                if scan.trigger == "manual":
                    try:
                        commit_sha = asyncio.run(
                            github_app.get_default_branch_sha(
                                token, repo.full_name, repo.default_branch
                            )
                        )
                        scan.commit_sha = commit_sha
                        scan.ref = f"refs/heads/{repo.default_branch}"
                        db.commit()
                    except Exception:  # noqa: BLE001
                        commit_sha = None
                elif not commit_sha:
                    try:
                        commit_sha = asyncio.run(
                            github_app.get_default_branch_sha(
                                token, repo.full_name, repo.default_branch
                            )
                        )
                        scan.commit_sha = commit_sha
                        scan.ref = f"refs/heads/{repo.default_branch}"
                        db.commit()
                    except Exception:  # noqa: BLE001 — best-effort SHA capture
                        log.warning("failed to resolve default-branch SHA for %s via PAT",
                                    repo.full_name)

                workdir = tempfile.mkdtemp(prefix="pencheff-repo-scan-")
                repo_path = os.path.join(workdir, "src")
                # ``clone_with_token`` works with both installation tokens
                # AND PATs — both go in the password slot of HTTPS basic
                # auth at github.com.
                github_app.clone_with_token(token, repo.full_name, repo_path, sha=commit_sha)
            else:
                # Public-URL GitHub repo: no installation token, anonymous
                # shallow clone. Default-branch SHA comes from the public
                # REST API.
                commit_sha = scan.commit_sha
                if scan.trigger == "manual":
                    try:
                        commit_sha = asyncio.run(
                            github_app.get_public_default_branch_sha(
                                repo.full_name, repo.default_branch
                            )
                        )
                        scan.commit_sha = commit_sha
                        scan.ref = f"refs/heads/{repo.default_branch}"
                        db.commit()
                    except Exception:  # noqa: BLE001
                        commit_sha = None
                elif not commit_sha:
                    try:
                        commit_sha = asyncio.run(
                            github_app.get_public_default_branch_sha(
                                repo.full_name, repo.default_branch
                            )
                        )
                        scan.commit_sha = commit_sha
                        scan.ref = f"refs/heads/{repo.default_branch}"
                        db.commit()
                    except Exception:  # noqa: BLE001 — best-effort SHA capture
                        log.warning("failed to resolve public default-branch SHA for %s", repo.full_name)

                workdir = tempfile.mkdtemp(prefix="pencheff-repo-scan-")
                repo_path = os.path.join(workdir, "src")
                github_app.clone_public(repo.html_url, repo_path, sha=commit_sha)

            # ── Honour .gitignore + strip noise dirs before scanning ─────
            # Stage the repo into a clean directory using hardlinks (cheap,
            # no byte copy on the same filesystem). All scanners then see
            # only files the user actually wants scanned: no .git/, no
            # node_modules/, no .venv/, no .env files, no anything matched
            # by the project's .gitignore.
            #
            # Gitleaks is the exception — it expects to walk a real git
            # working tree (``.git/`` present) so it can scan commit
            # history. Stripping ``.git`` made it bail with "fatal: not a
            # git repository" and silently report 0 commits scanned. We
            # therefore keep a pointer to the original cloned tree
            # (``cloned_repo_path``) and feed *that* to gitleaks, while
            # all other scanners get the cleaned staging dir.
            cloned_repo_path = repo_path
            staging_root = os.path.join(workdir, "staging")
            scan_path, filter_stats = clean_repo_dir(repo_path, staging_root)
            stats["filter"] = filter_stats
            if filter_stats["included"] <= 0:
                scan.status = "failed"
                scan.error = (
                    "Repository scan staged 0 files after applying .gitignore "
                    "and noise-directory filters; refusing to report an empty "
                    "scan as clean."
                )
                scan.completed_at = datetime.now(timezone.utc)
                scan.stats = stats
                db.commit()
                return {"ok": False, "error": scan.error, "stats": stats}
            log.info(
                "repo filter: included=%d excluded=%d method=%s",
                filter_stats["included"], filter_stats["excluded"],
                filter_stats["method"],
            )
            repo_path = scan_path

            # All SAST scanners are language-agnostic at the orchestration
            # layer — each runner skips itself if no relevant source
            # files are present (Bandit on no-Python, gosec on no-Go,
            # etc.), so we dispatch every selected scanner unconditionally.
            #
            # Visibility (added 2026-05-23): every scanner's submit + finish
            # logs its elapsed wall-clock so `docker logs pencheff-worker-1`
            # turns from a 5-min silent stretch into a steady progress
            # report. RepoScan rows don't have progress_pct/current_stage
            # columns, so logs are the single source of truth for "is the
            # worker stuck?".
            with ThreadPoolExecutor(max_workers=min(6, len(scanners))) as pool:
                futures: dict = {}
                scanner_start: dict[str, float] = {}

                def _submit(name: str, fn, *args):
                    scanner_start[name] = time.monotonic()
                    fut = pool.submit(fn, *args)
                    futures[fut] = name
                    log.info("scanner %s: dispatched", name)

                if "semgrep" in scanners:    _submit("semgrep", _run_semgrep, repo_path, workdir)
                if "bandit" in scanners:     _submit("bandit", _run_bandit, repo_path, workdir)
                if "gosec" in scanners:      _submit("gosec", _run_gosec, repo_path, workdir)
                if "brakeman" in scanners:   _submit("brakeman", _run_brakeman, repo_path, workdir)
                if "eslint" in scanners:     _submit("eslint", _run_eslint, repo_path, workdir)
                if "gitleaks" in scanners:
                    # Gitleaks needs the original cloned tree (``.git/``
                    # present) — the staged ``repo_path`` has had its
                    # ``.git`` stripped by ``clean_repo_dir``.
                    _submit("gitleaks", _run_gitleaks, cloned_repo_path, workdir)
                if "ghsa" in scanners:       _submit("ghsa", _run_ghsa, repo_path, workdir)
                if "yara" in scanners:       _submit("yara", _run_yara, repo_path, workdir)
                if "trivy_iac" in scanners:  _submit("trivy_iac", _run_trivy_iac, repo_path, workdir)
                if "checkov" in scanners:    _submit("checkov", _run_checkov, repo_path, workdir)

                completed = 0
                total = len(futures)
                log.info("repo scan: dispatched %d scanners; waiting for results…", total)
                for fut in as_completed(futures):
                    name = futures[fut]
                    elapsed = time.monotonic() - scanner_start.get(name, time.monotonic())
                    try:
                        normalized, meta = fut.result()
                        all_findings.extend(normalized)
                        stats[name] = {"count": len(normalized), **meta}
                        completed += 1
                        log.info(
                            "scanner %s: finished in %.1fs (count=%d) — %d/%d done",
                            name, elapsed, len(normalized), completed, total,
                        )
                    except Exception as exc:  # noqa: BLE001
                        stats[name] = {"count": 0, "error": f"{type(exc).__name__}: {exc}"}
                        completed += 1
                        log.exception(
                            "scanner %s: FAILED in %.1fs — %d/%d done",
                            name, elapsed, completed, total,
                        )

            scanner_stats = {
                name: value for name, value in stats.items()
                if name in scanners and isinstance(value, dict)
            }
            runnable = [
                name for name, value in scanner_stats.items()
                if not value.get("skipped") and not value.get("error")
            ]
            if not runnable:
                missing = ", ".join(
                    f"{name}: {value.get('skipped') or value.get('error')}"
                    for name, value in scanner_stats.items()
                    if value.get("skipped") or value.get("error")
                )
                scan.status = "failed"
                scan.error = (
                    "No repository scanners ran successfully in this worker image. "
                    "Rebuild the worker with apps/api/Dockerfile.toolchain. "
                    f"{missing}"[:3500]
                )
                scan.completed_at = datetime.now(timezone.utc)
                scan.stats = stats
                db.commit()
                return {"ok": False, "error": scan.error, "stats": stats}

            # Re-check the scan row exists before we attempt to write
            # findings or status. If a user (or another process) deleted
            # the row while the scanners were running, every attribute
            # access on `scan` raises ObjectDeletedError and the exception
            # handler below would crash trying to set scan.error on the
            # same dead row. Detecting it here lets us abort cleanly with
            # a single log line instead of an unhandled exception.
            from sqlalchemy.orm.exc import ObjectDeletedError as _ObjDel
            scan_was_deleted = False
            try:
                db.refresh(scan)
            except _ObjDel:
                scan_was_deleted = True
            if scan_was_deleted:
                log.warning(
                    "repo scan %s was deleted mid-flight; discarding %d "
                    "scanner findings and exiting cleanly",
                    repo_scan_id, len(all_findings),
                )
                return {"ok": False, "error": "scan deleted mid-flight", "stats": stats}

            # Bulk insert findings.
            for f in all_findings:
                db.add(RepoFinding(
                    repo_scan_id=scan.id,
                    repository_id=repo.id,
                    scanner=f["scanner"],
                    rule_id=f.get("rule_id"),
                    severity=f.get("severity") or "medium",
                    title=(f.get("title") or "finding")[:500],
                    description=f.get("description"),
                    file_path=(f.get("file_path") or None),
                    line_start=f.get("line_start"),
                    line_end=f.get("line_end"),
                    code_snippet=(f.get("code_snippet") or None),
                    cve=f.get("cve"),
                    package=f.get("package"),
                    installed_version=f.get("installed_version"),
                    fixed_version=f.get("fixed_version"),
                    raw=f.get("raw"),
                ))

            triage_org_id = scan.org_id  # capture before commit (expire-on-commit)
            scan.status = "succeeded"
            scan.stats = stats
            scan.completed_at = datetime.now(timezone.utc)
            repo.last_scan_id = scan.id
            repo.last_scan_at = scan.completed_at
            try:
                db.commit()
            except _ObjDel:
                # Same race as above, but caught on the actual write side.
                db.rollback()
                log.warning(
                    "repo scan %s deleted between refresh + commit; "
                    "discarding %d findings",
                    repo_scan_id, len(all_findings),
                )
                return {"ok": False, "error": "scan deleted mid-flight", "stats": stats}

            from .security_lake_ingest_task import enqueue_repo_ingest
            enqueue_repo_ingest(repo_scan_id)
            # AI false-positive triage: the LLM judges each finding and verified
            # false positives (e.g. bandit B608 on parameterized SQL) are
            # suppressed in Pencheff's DB so they drop from the count and stop
            # recurring. Code is never modified. Best-effort — never affects
            # scan success.
            try:
                from ..services.repo_fp_triage import triage_repo_findings
                asyncio.run(triage_repo_findings(repo_scan_id, triage_org_id))
            except Exception:  # noqa: BLE001
                log.exception("repo FP-triage dispatch failed for %s", repo_scan_id)
            return {"ok": True, "findings": len(all_findings), "stats": stats}

        except Exception as exc:  # noqa: BLE001
            log.exception("repo scan %s failed", repo_scan_id)
            # Defensive: the row may have been deleted (ObjectDeletedError),
            # the session may be in a bad state, or both. Roll back, refresh,
            # and only attempt to mark `failed` if the row is still there.
            from sqlalchemy.orm.exc import ObjectDeletedError as _ObjDel
            try:
                db.rollback()
            except Exception:  # noqa: BLE001
                pass
            try:
                db.refresh(scan)
                scan.status = "failed"
                scan.error = f"{type(exc).__name__}: {exc}"[:4000]
                scan.completed_at = datetime.now(timezone.utc)
                scan.stats = stats
                db.commit()
            except _ObjDel:
                log.warning(
                    "repo scan %s was deleted before we could mark it "
                    "failed; nothing to update",
                    repo_scan_id,
                )
            except Exception as commit_exc:  # noqa: BLE001
                log.exception(
                    "repo scan %s: failed to record failure state: %s",
                    repo_scan_id, commit_exc,
                )
            return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
        finally:
            if workdir and os.path.isdir(workdir):
                shutil.rmtree(workdir, ignore_errors=True)


def _run_sast_tool(
    *,
    tool_name: str,
    binary: str,
    script: str,
    out_filename: str,
    repo_path: str,
    workdir: str,
    timeout: int,
    normalizer,
    extra_meta: dict[str, Any] | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Shared invocation skeleton for the SAST replacement tools.

    Each tool ships a sibling shell runner under ``bench/runners/`` that
    handles missing-binary / missing-source cases and emits an empty but
    well-formed JSON envelope so the normalizer never sees malformed input.
    """
    if not _which(binary):
        return [], {"skipped": f"no {binary} binary"}
    out_path = os.path.join(workdir, out_filename)
    runner = str(BENCH_RUNNERS / script)
    subprocess.run(
        ["bash", runner, repo_path, out_path],
        timeout=timeout,
        check=False,
    )
    text = _safe_read(out_path)
    meta: dict[str, Any] = {"output_bytes": len(text or "")}
    if extra_meta:
        meta.update(extra_meta)
    return normalizer(text or "{}", repo_path), meta


def _run_semgrep(
    repo_path: str, workdir: str,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    return _run_sast_tool(
        tool_name="semgrep", binary="semgrep", script="semgrep.sh",
        out_filename="semgrep.json",
        repo_path=repo_path, workdir=workdir, timeout=1800,
        normalizer=repo_findings.normalize_semgrep,
    )


def _run_bandit(
    repo_path: str, workdir: str,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    return _run_sast_tool(
        tool_name="bandit", binary="bandit", script="bandit.sh",
        out_filename="bandit.json",
        repo_path=repo_path, workdir=workdir, timeout=600,
        normalizer=repo_findings.normalize_bandit,
    )


def _run_gosec(
    repo_path: str, workdir: str,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    return _run_sast_tool(
        tool_name="gosec", binary="gosec", script="gosec.sh",
        out_filename="gosec.json",
        repo_path=repo_path, workdir=workdir, timeout=600,
        # gosec emits {"Issues": [...]} which normalize_gosec accepts as a dict.
        normalizer=repo_findings.normalize_gosec,
    )


def _run_brakeman(
    repo_path: str, workdir: str,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    return _run_sast_tool(
        tool_name="brakeman", binary="brakeman", script="brakeman.sh",
        out_filename="brakeman.json",
        repo_path=repo_path, workdir=workdir, timeout=600,
        normalizer=repo_findings.normalize_brakeman,
    )


def _run_eslint(
    repo_path: str, workdir: str,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    # ESLint is invoked via ``npx`` from the runner script; the binary
    # check below probes ``npx`` because that's what the script actually
    # executes.
    return _run_sast_tool(
        tool_name="eslint", binary="npx", script="eslint_security.sh",
        out_filename="eslint.json",
        repo_path=repo_path, workdir=workdir, timeout=900,
        normalizer=repo_findings.normalize_eslint,
    )


def _run_gitleaks(repo_path: str, workdir: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if not _which("gitleaks"):
        return [], {"skipped": "no gitleaks binary"}
    out_json = os.path.join(workdir, "gitleaks.json")
    script = str(BENCH_RUNNERS / "gitleaks.sh")
    # Gitleaks's default ``detect`` subcommand requires a git working
    # tree (``.git/`` present); without it the binary logs "fatal: not
    # a git repository" and reports 0 commits scanned. Pass a flag to
    # the wrapper so it switches to ``--no-git`` (working-tree-only)
    # mode for paths without ``.git`` — typically the local-path repo
    # source where the user pointed us at a non-git directory.
    has_git = os.path.isdir(os.path.join(repo_path, ".git"))
    mode = "git" if has_git else "nogit"
    subprocess.run(
        ["bash", script, repo_path, out_json, mode],
        timeout=600, check=False,
    )
    text = _safe_read(out_json)
    return (
        repo_findings.normalize_gitleaks(text or "[]", repo_path),
        {"output_bytes": len(text or ""), "mode": mode, "has_git": has_git},
    )


def _run_ghsa(repo_path: str, workdir: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Dependency vulnerability scan against the GitHub Advisory Database.

    osv-scanner queries OSV.dev which mirrors GHSA (and other sources).
    Findings are tagged ``scanner="ghsa"``; ``rule_id`` prefers the
    GHSA-* alias when present so the UI groups them as Advisory entries.
    """
    out_json = os.path.join(workdir, "ghsa.json")
    if _which("osv-scanner"):
        with open(out_json, "wb") as fh:
            subprocess.run(
                ["osv-scanner", "--format", "json", "-r", repo_path],
                stdout=fh, stderr=subprocess.DEVNULL, timeout=300, check=False,
            )
    elif _which("docker"):
        img = os.environ.get("OSV_IMAGE", "ghcr.io/google/osv-scanner:latest")
        with open(out_json, "wb") as fh:
            subprocess.run(
                ["docker", "run", "--rm", "-v", f"{repo_path}:/src", img,
                 "-r", "/src", "--format", "json"],
                stdout=fh, stderr=subprocess.DEVNULL, timeout=300, check=False,
            )
    else:
        return [], {"skipped": "no osv-scanner binary or docker"}
    text = _safe_read(out_json)
    return repo_findings.normalize_ghsa(text or "{}", repo_path), {"output_bytes": len(text or "")}


def _run_yara(repo_path: str, workdir: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if not _which("yara"):
        return [], {"skipped": "no yara binary"}
    out_ndjson = os.path.join(workdir, "yara.ndjson")
    script = str(BENCH_RUNNERS / "yara.sh")
    subprocess.run(
        ["bash", script, repo_path, out_ndjson, str(YARA_RULES)],
        timeout=600, check=False,
    )
    text = _safe_read(out_ndjson)
    return repo_findings.normalize_yara(text or "", repo_path), {"output_bytes": len(text or "")}


def _run_trivy_iac(repo_path: str, workdir: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Run Trivy in IaC-config mode (Terraform, CloudFormation, Helm, K8s manifests)."""
    out_json = os.path.join(workdir, "trivy_iac.json")
    if _which("trivy"):
        with open(out_json, "wb") as fh:
            subprocess.run(
                ["trivy", "config", "--format", "json", "--quiet", repo_path],
                stdout=fh, stderr=subprocess.DEVNULL, timeout=300, check=False,
            )
    elif _which("docker"):
        img = os.environ.get("TRIVY_IMAGE", "aquasec/trivy:latest")
        with open(out_json, "wb") as fh:
            subprocess.run(
                ["docker", "run", "--rm", "-v", f"{repo_path}:/src", img,
                 "config", "--format", "json", "--quiet", "/src"],
                stdout=fh, stderr=subprocess.DEVNULL, timeout=300, check=False,
            )
    else:
        return [], {"skipped": "no trivy binary or docker"}
    text = _safe_read(out_json)
    return repo_findings.normalize_trivy_iac(text or "{}", repo_path), {"output_bytes": len(text or "")}


def _run_checkov(repo_path: str, workdir: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Run Checkov over Terraform, CloudFormation, K8s, Helm, Dockerfile."""
    out_json = os.path.join(workdir, "checkov.json")
    if _which("checkov"):
        with open(out_json, "wb") as fh:
            subprocess.run(
                ["checkov", "-d", repo_path, "-o", "json", "--quiet"],
                stdout=fh, stderr=subprocess.DEVNULL, timeout=300, check=False,
            )
    elif _which("docker"):
        img = os.environ.get("CHECKOV_IMAGE", "bridgecrew/checkov:latest")
        with open(out_json, "wb") as fh:
            subprocess.run(
                ["docker", "run", "--rm", "-v", f"{repo_path}:/src", img,
                 "-d", "/src", "-o", "json", "--quiet"],
                stdout=fh, stderr=subprocess.DEVNULL, timeout=300, check=False,
            )
    else:
        return [], {"skipped": "no checkov binary or docker"}
    text = _safe_read(out_json)
    return repo_findings.normalize_checkov(text or "{}", repo_path), {"output_bytes": len(text or "")}


def _safe_read(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except FileNotFoundError:
        return ""


def _which(cmd: str) -> str | None:
    return shutil.which(cmd)
