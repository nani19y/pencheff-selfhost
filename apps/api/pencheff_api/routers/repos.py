"""Repository connect + scan orchestration.

Two ways to connect a repo:
  * GitHub — either via the GitHub App install (private repos, webhooks,
    Dependabot) or by pasting a public github.com URL (anonymous clone).
  * Local — register a directory on the worker's filesystem.

Endpoints:
    GET    /repos/install-url            → install URL for the GitHub App
    GET    /repos/callback               → post-install redirect target
    GET    /repos/integrations           → connected GitHub accounts/orgs
    DELETE /repos/integrations/{id}      → soft-remove an integration
    POST   /repos/integrations/{id}/sync → pull the latest repo list

    POST   /repos/github                 → connect a public GitHub URL
    POST   /repos/local                  → register a local folder

    GET    /repos                        → list org-visible repos
    GET    /repos/{id}                   → repo detail
    POST   /repos/{id}/scan              → enqueue a RepoScan
    GET    /repos/{id}/scans             → recent scans for this repo

    GET    /repos/scans/{scan_id}        → scan detail
    GET    /repos/scans/{scan_id}/findings → findings list
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from datetime import datetime
from typing import Any
from urllib.parse import quote, urlparse

import httpx
from fastapi import (
    APIRouter, Depends, HTTPException, Query, Request, status,
)
from fastapi.responses import RedirectResponse
from pydantic import BaseModel
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth.deps import get_active_workspace, require_scope, session_only
from ..config import get_settings
from ..db.base import get_session
from ..db.models import (
    Repository,
    RepoFinding,
    RepoIntegration,
    RepoScan,
    RepoSbom,
    Target,
    TargetRepository,
    Workspace,
)
from ..scan_categories import category_service
from ..services import github_app
from ..services.repo_filter import clean_repo_dir
from ..services.scan_dispatch import enqueue_repo_scan
from ..services.worker_lifecycle import ensure_worker_started_or_503

router = APIRouter(prefix="/repos", tags=["repos"])


def _mirror_as_target(db: AsyncSession, repo: Repository) -> None:
    """Stage a Target row mirroring this Repository so repos appear in
    /targets, the integrations target multi-select, and the dashboard's
    Registered targets card.

    Idempotent — does nothing if a mirror already exists for this repo.
    Only adds to the session; the caller's existing ``await db.commit()``
    persists both the Repository and its mirror in one transaction.
    """
    db.add(Target(
        org_id=repo.org_id,
        workspace_id=repo.workspace_id,
        name=repo.full_name,
        base_url=repo.html_url,
        repository_id=repo.id,
        kind="repo",
    ))


async def _ensure_mirror_target(db: AsyncSession, repo: Repository) -> None:
    """Idempotent variant — used by the GitHub-sync path which can
    reprocess the same repo. Looks up an existing mirror first."""
    existing = (await db.execute(
        select(Target.id).where(Target.repository_id == repo.id)
    )).scalar_one_or_none()
    if existing:
        return
    _mirror_as_target(db, repo)


# ──────────────────────────── Pydantic shapes ────────────────────────────

class IntegrationOut(BaseModel):
    id: str
    provider: str
    installation_id: str
    account_login: str
    account_type: str
    avatar_url: str | None
    installed_at: datetime


class RepositoryOut(BaseModel):
    id: str
    provider: str
    # NULL for public-URL GitHub repos and local folders. Set for
    # App-installed GitHub repos.
    integration_id: str | None
    full_name: str
    owner: str
    name: str
    default_branch: str
    private: bool
    html_url: str
    language: str | None
    auto_scan_on_push: bool
    last_scan_id: str | None
    last_scan_at: datetime | None
    severity_counts: dict[str, int] | None = None
    # Set when ``provider == "local"`` so the UI can show the on-disk
    # path. Null for GitHub-backed repos.
    local_path: str | None = None


class LocalRepoCreate(BaseModel):
    """Register a local directory as a scannable repo.

    The Celery worker will read files at ``local_path`` directly (no clone).
    The path must be readable by whichever process runs the worker — if the
    worker runs in Docker, the path must be inside a bind-mounted volume.
    """
    name: str
    local_path: str
    language: str | None = None


class GithubUrlConnect(BaseModel):
    """Connect a GitHub repo by URL.

    * ``token`` omitted → public repo, anonymous shallow clone.
    * ``token`` provided → private repo via Personal Access Token. The
      token is Fernet-encrypted at rest and used as the
      ``x-access-token`` password for ``git clone`` in the worker. The
      token must have read access to the target repo (``repo`` for a
      classic PAT; ``Contents: Read`` + ``Metadata: Read`` for a
      fine-grained PAT scoped to the repo).
    """
    url: str
    name: str | None = None
    token: str | None = None


class RepoScanOut(BaseModel):
    id: str
    repository_id: str
    commit_sha: str | None
    ref: str | None
    trigger: str
    status: str
    scanners: list[str] | None
    stats: dict[str, Any] | None
    started_at: datetime | None
    completed_at: datetime | None
    error: str | None
    created_at: datetime
    summary: dict[str, int] | None = None


class RepoFindingOut(BaseModel):
    id: str
    scanner: str
    rule_id: str | None
    severity: str
    title: str
    description: str | None
    file_path: str | None
    line_start: int | None
    line_end: int | None
    code_snippet: str | None
    cve: str | None
    package: str | None
    installed_version: str | None
    fixed_version: str | None
    ai_explanation: str | None
    fix_status: str
    fix_pr_url: str | None
    suppressed: bool


class ScanRequest(BaseModel):
    scanners: list[str] | None = None
    ref: str | None = None
    commit_sha: str | None = None


class RepoSbomRequest(BaseModel):
    format: str = "cyclonedx"
    ref: str | None = None
    commit_sha: str | None = None
    # When the desktop generates the SBOM locally (provider="local"
    # repos the API container can't see), the request carries the
    # finished CycloneDX/SPDX blob and we persist it directly instead
    # of dispatching the worker. None for cloud-side generation.
    content: dict | None = None
    component_count: int | None = None


class RepoSbomOut(BaseModel):
    id: str
    repository_id: str
    commit_sha: str | None
    format: str
    component_count: int | None
    content: dict | None
    created_at: datetime


class InstallUrlOut(BaseModel):
    url: str
    configured: bool


class LocalScanStartRequest(BaseModel):
    """Body for ``POST /repos/{id}/scan/local`` — the desktop sends the
    scanner pack it intends to run + an optional commit SHA. The endpoint
    only opens the scan row; the desktop then runs the scanners and
    posts results back through ``/repos/scans/{id}/ingest``.
    """
    scanners: list[str] | None = None
    commit_sha: str | None = None


class LocalFindingIn(BaseModel):
    """One finding posted by the desktop ingest endpoint. Matches the
    columns of ``RepoFinding`` minus the IDs and timestamps the server
    fills in. ``severity`` is normalised on read (critical/high/medium/
    low/info); unknown values fall back to ``"info"``.
    """
    scanner: str
    rule_id: str | None = None
    severity: str = "info"
    title: str
    description: str | None = None
    file_path: str | None = None
    line_start: int | None = None
    line_end: int | None = None
    code_snippet: str | None = None
    cve: str | None = None
    package: str | None = None
    installed_version: str | None = None
    fixed_version: str | None = None
    ai_explanation: str | None = None


class LocalSbomIn(BaseModel):
    """Optional SBOM payload — desktop usually generates one via
    ``trivy fs --format=cyclonedx``. Stored under the scan's repo as the
    latest SBOM and surfaces through ``GET /repos/{id}/sbom``.
    """
    format: str = "cyclonedx"
    component_count: int | None = None
    content: dict


class LocalScanIngestRequest(BaseModel):
    """Body for ``POST /repos/scans/{scan_id}/ingest`` — the desktop's
    completed-scan payload. Setting ``error`` transitions the scan to
    ``failed`` instead of ``done``. ``stats`` mirrors the cloud worker's
    per-scanner roll-up shape (``{scanner: {count: N, duration_ms: M}}``)
    so the existing scan-history table can render it without branching.
    """
    findings: list[LocalFindingIn] = []
    stats: dict | None = None
    sbom: LocalSbomIn | None = None
    error: str | None = None


# ────────────────────────── Install / callback ──────────────────────────

@router.get(
    "/install-url",
    response_model=InstallUrlOut,
    # GitHub App install handshake is interactive — only sessions trigger it.
    dependencies=[Depends(session_only)],
)
async def get_install_url(
    workspace: Workspace = Depends(get_active_workspace),
) -> InstallUrlOut:
    # The install state carries "org_id:workspace_id" so the callback binds
    # the fresh integration to the exact workspace the user was in when
    # they clicked Install.
    state = quote(f"{workspace.org_id}:{workspace.id}", safe="")
    return InstallUrlOut(
        url=github_app.install_url(state=state),
        configured=github_app.is_configured(),
    )


@router.get("/callback")
async def github_callback(
    request: Request,
    installation_id: int | None = None,
    setup_action: str | None = None,
    state: str | None = None,
    session: AsyncSession = Depends(get_session),
) -> RedirectResponse:
    """GitHub redirects here after the user installs the app."""
    settings = get_settings()
    web_base = settings.web_base_url.rstrip("/")

    if not installation_id:
        return RedirectResponse(f"{web_base}/repos?error=missing-installation", 302)
    if not state:
        return RedirectResponse(f"{web_base}/repos?error=missing-state", 302)

    # state is "org_id:workspace_id" (legacy installs may still carry just
    # an org_id — in that case pick the first workspace in the org).
    if ":" in state:
        state_org_id, state_workspace_id = state.split(":", 1)
    else:
        state_org_id, state_workspace_id = state, None
    if state_workspace_id is None:
        fallback = (await session.execute(
            select(Workspace).where(Workspace.org_id == state_org_id).limit(1)
        )).scalar_one_or_none()
        if fallback is None:
            return RedirectResponse(
                f"{web_base}/repos?error=no-workspace", 302,
            )
        state_workspace_id = fallback.id

    # Fetch installation metadata — validates the installation exists and
    # gives us the account info to store.
    try:
        meta = await github_app.get_installation(installation_id)
    except Exception as exc:  # noqa: BLE001
        return RedirectResponse(
            f"{web_base}/repos?error=install-lookup-failed", 302,
        )

    account = meta.get("account") or {}
    # Upsert by (provider, installation_id).
    existing = (await session.execute(
        select(RepoIntegration).where(
            RepoIntegration.provider == "github",
            RepoIntegration.installation_id == str(installation_id),
        )
    )).scalar_one_or_none()

    if existing is None:
        integ = RepoIntegration(
            org_id=state_org_id,
            workspace_id=state_workspace_id,
            provider="github",
            installation_id=str(installation_id),
            account_login=account.get("login", "unknown"),
            account_type=account.get("type", "User"),
            avatar_url=account.get("avatar_url"),
        )
        session.add(integ)
        await session.commit()
        await session.refresh(integ)
    else:
        integ = existing
        integ.org_id = state_org_id
        integ.workspace_id = state_workspace_id
        integ.account_login = account.get("login", integ.account_login)
        integ.account_type = account.get("type", integ.account_type)
        integ.avatar_url = account.get("avatar_url", integ.avatar_url)
        integ.removed_at = None
        await session.commit()

    # Immediately sync repos so the user sees them on landing.
    try:
        await _sync_integration_repos(session, integ)
    except Exception:  # noqa: BLE001
        # Non-fatal — user can hit Sync from the UI.
        pass

    return RedirectResponse(f"{web_base}/repos?connected={integ.id}", 302)


# ─────────────────────────── Integrations CRUD ───────────────────────────

@router.get(
    "/integrations",
    response_model=list[IntegrationOut],
    dependencies=[Depends(require_scope("repos:read"))],
)
async def list_integrations(
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> list[IntegrationOut]:
    rows = (await session.execute(
        select(RepoIntegration).where(
            RepoIntegration.workspace_id == workspace.id,
            RepoIntegration.removed_at.is_(None),
        ).order_by(RepoIntegration.installed_at.desc())
    )).scalars().all()
    return [
        IntegrationOut(
            id=r.id, provider=r.provider, installation_id=r.installation_id,
            account_login=r.account_login, account_type=r.account_type,
            avatar_url=r.avatar_url, installed_at=r.installed_at,
        ) for r in rows
    ]


@router.delete(
    "/integrations/{integration_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require_scope("repos:write"))],
)
async def remove_integration(
    integration_id: str,
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> None:
    integ = await _load_integration(session, integration_id, workspace.id)
    integ.removed_at = datetime.utcnow()
    # Hard-delete the repos this installation brought in (cascades to mirror
    # targets, scans and findings); the integration row stays as a tombstone.
    await purge_integration_repos(session, integ.id)
    await session.commit()


@router.post(
    "/integrations/{integration_id}/sync",
    response_model=list[RepositoryOut],
    dependencies=[Depends(require_scope("repos:write"))],
)
async def sync_integration(
    integration_id: str,
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> list[RepositoryOut]:
    integ = await _load_integration(session, integration_id, workspace.id)
    await _sync_integration_repos(session, integ)
    return await _list_repos_for_workspace(session, workspace.id)


# ─────────────────────────── Local repos ────────────────────────────────

@router.post(
    "/local",
    response_model=RepositoryOut,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_scope("repos:write"))],
)
async def register_local_repo(
    body: LocalRepoCreate,
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> RepositoryOut:
    """Register a directory on the worker's filesystem as a scannable repo.

    The path is stored verbatim — no clone, no copy. The Celery worker
    reads files in place when ``run_repo_scan`` runs. The worker process
    must be able to ``os.path.isdir(local_path)``; in Docker setups,
    that means the path has to be inside a bind-mounted volume.
    """
    raw = (body.local_path or "").strip()
    if not raw:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "local_path required")
    abs_path = os.path.abspath(os.path.expanduser(raw))
    # Soft validation only: the API process and the worker may be on
    # different machines, so a missing path here doesn't necessarily
    # mean the worker can't see it. We warn but still accept.
    if not os.path.isabs(abs_path):
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "local_path must be an absolute path on the worker filesystem",
        )

    # Stable provider_repo_id so re-registering the same path doesn't
    # explode the unique constraint.
    digest = hashlib.sha256(abs_path.encode()).hexdigest()[:16]

    existing = (await session.execute(
        select(Repository).where(
            Repository.provider == "local",
            Repository.provider_repo_id == digest,
            Repository.workspace_id == workspace.id,
        )
    )).scalar_one_or_none()
    if existing is not None:
        # Idempotent: return the row unchanged. Useful when the user clicks
        # "Connect" twice or the form auto-submits on retry.
        return _repo_to_out(existing)

    nickname = (body.name or os.path.basename(abs_path) or "local-repo")[:200]
    r = Repository(
        org_id=workspace.org_id,
        workspace_id=workspace.id,
        integration_id=None,
        provider="local",
        provider_repo_id=digest,
        owner="local",
        name=nickname,
        full_name=f"local/{nickname}",
        default_branch="HEAD",
        private=True,
        html_url=f"file://{abs_path}",
        language=body.language,
        local_path=abs_path,
        auto_scan_on_push=False,
    )
    session.add(r)
    await session.flush()             # populate r.id for the mirror FK
    _mirror_as_target(session, r)
    await session.commit()
    await session.refresh(r)
    return _repo_to_out(r)


_GITHUB_URL_RE = re.compile(
    r"^https?://(www\.)?github\.com/(?P<owner>[^/\s]+)/(?P<name>[^/\s?#]+?)(\.git)?/?$",
    re.IGNORECASE,
)


def _parse_github_url(url: str) -> tuple[str, str]:
    """Return ``(owner, name)`` for a github.com URL or raise 400."""
    cleaned = (url or "").strip()
    if not cleaned:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "url required")
    parsed = urlparse(cleaned)
    if parsed.scheme not in ("http", "https") or (parsed.netloc or "").lower() not in ("github.com", "www.github.com"):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "url must point to github.com")
    m = _GITHUB_URL_RE.match(cleaned)
    if not m:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "url must look like https://github.com/<owner>/<repo>",
        )
    return m.group("owner"), m.group("name")


# ─────────────────────────── Connect a GitHub URL ───────────────────────────

@router.post(
    "/github",
    response_model=RepositoryOut,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_scope("repos:write"))],
)
async def connect_github_url(
    body: GithubUrlConnect,
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> RepositoryOut:
    """Connect a GitHub repo by URL.

    Two paths:

    * **Public** (``token`` omitted) — public repo, anonymous shallow clone.
    * **Private via PAT** (``token`` provided) — we validate the token
      against the GitHub REST API, confirm it has read access to the
      target, then encrypt + persist the token on the Repository row.
      The scan task uses it as the ``x-access-token`` password for
      ``git clone``.

    For private repos, we authenticate the metadata fetch with the PAT.
    For public repos we use the anonymous endpoint (which 404s on
    private/missing repos).
    """
    owner, name = _parse_github_url(body.url)
    full_name = f"{owner}/{name}"
    token = (body.token or "").strip() or None

    if token:
        # Private path — use the PAT to fetch metadata. github_app.get_repo
        # uses Authorization: token <pat>, which works for both
        # installation tokens and PATs.
        try:
            meta = await github_app.get_repo(token, full_name)
        except httpx.HTTPStatusError as e:
            sc = e.response.status_code
            if sc == 401:
                raise HTTPException(
                    status.HTTP_400_BAD_REQUEST,
                    "GitHub rejected the token (401). The PAT is invalid, "
                    "revoked, or expired.",
                )
            if sc in (403, 404):
                raise HTTPException(
                    status.HTTP_400_BAD_REQUEST,
                    f"Token cannot read {full_name}. Check the PAT has "
                    "'Contents: Read' + 'Metadata: Read' (fine-grained) "
                    "or the 'repo' scope (classic), and that the repo is "
                    "in the PAT's allowed-repos list.",
                )
            raise HTTPException(status.HTTP_502_BAD_GATEWAY,
                                f"GitHub error {sc} while validating token.")
    else:
        # Public path — anonymous probe.
        meta = await github_app.get_public_repo(full_name)
        if meta is None:
            raise HTTPException(
                status.HTTP_404_NOT_FOUND,
                "repo is private or does not exist — supply a Personal "
                "Access Token to connect a private repo, or install the "
                "GitHub App.",
            )
        if meta.get("private"):
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                "repo is private — supply a Personal Access Token in "
                "the 'token' field, or install the GitHub App.",
            )

    provider_repo_id = str(meta["id"])

    existing = (await session.execute(
        select(Repository).where(
            Repository.provider == "github",
            Repository.provider_repo_id == provider_repo_id,
        )
    )).scalar_one_or_none()
    if existing is not None:
        if existing.workspace_id != workspace.id:
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                "repo already connected in another workspace",
            )
        # Already-connected: refresh the token if a new one was supplied
        # so users can rotate without deleting + re-registering.
        if token:
            from ..services.credentials import encrypt_credentials
            existing.token_encrypted = encrypt_credentials({"token": token})
            existing.private = bool(meta.get("private") or existing.private)
            await session.commit()
            await session.refresh(existing)
        return _repo_to_out(existing)

    nickname = (body.name or meta.get("name") or name)[:200]
    repo = Repository(
        org_id=workspace.org_id,
        workspace_id=workspace.id,
        integration_id=None,
        provider="github",
        provider_repo_id=provider_repo_id,
        owner=meta["owner"]["login"],
        name=nickname,
        full_name=meta["full_name"],
        default_branch=meta.get("default_branch") or "main",
        private=bool(meta.get("private", False)),
        html_url=meta["html_url"],
        language=meta.get("language"),
        auto_scan_on_push=False,
    )
    if token:
        from ..services.credentials import encrypt_credentials
        repo.token_encrypted = encrypt_credentials({"token": token})
    session.add(repo)
    await session.flush()             # populate repo.id for the mirror FK
    _mirror_as_target(session, repo)
    await session.commit()
    await session.refresh(repo)
    return _repo_to_out(repo)


@router.delete(
    "/{repo_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require_scope("repos:write"))],
)
async def delete_repo(
    repo_id: str,
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> None:
    r = await _load_repo(session, repo_id, workspace.id)
    # Local folders and public-URL GitHub repos are user-managed and
    # safely deletable. App-installed GitHub repos sync from the
    # installation, so delete blocks them — disconnect the integration
    # instead.
    if r.provider == "github" and r.integration_id is not None:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "App-installed GitHub repos are managed via the integration; "
            "remove the integration to disconnect.",
        )

    # A repo that's currently attached to one or more URL targets stays
    # locked. The FK on target_repositories.repository_id is also ON DELETE
    # RESTRICT — this branch produces a friendlier error before the DB
    # constraint fires. Detach via PATCH /targets/{id} (set
    # attached_repository_ids without this repo) to unblock.
    attached_to = (await session.execute(
        select(Target.id, Target.name)
        .join(TargetRepository, TargetRepository.target_id == Target.id)
        .where(TargetRepository.repository_id == r.id)
        .order_by(Target.name)
    )).all()
    if attached_to:
        names = ", ".join(name for _, name in attached_to[:3])
        more = f" (+{len(attached_to) - 3} more)" if len(attached_to) > 3 else ""
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            f"Repository is attached to {len(attached_to)} URL target(s): {names}{more}. "
            "Detach it from each target before deleting.",
        )

    await session.delete(r)
    await session.commit()


class RepositoryUpdate(BaseModel):
    """Editable subset of a Repository.

    Identity fields (owner, name, full_name, html_url) are derived from
    the upstream provider and never editable here. App-installed repos
    have ``default_branch`` and ``language`` synced from the installation
    on each scan, so user edits to those would be transient — the
    endpoint accepts them anyway since the user explicitly chose to set
    them, and the sync only overwrites at scan time.

    ``token`` is the optional new PAT for token rotation. Only
    meaningful for repos that were registered with a PAT
    (``token_encrypted`` already set). Omit / set to ``None`` to leave
    the token unchanged. Empty string clears it (downgrades the repo to
    public-clone mode if the upstream is public, or breaks scans if not
    — the user is responsible).

    ``local_path`` only meaningful when ``provider == "local"``.
    """
    default_branch: str | None = None
    language: str | None = None
    auto_scan_on_push: bool | None = None
    local_path: str | None = None
    token: str | None = None


@router.patch(
    "/{repo_id}",
    response_model=RepositoryOut,
    dependencies=[Depends(require_scope("repos:write"))],
)
async def update_repo(
    repo_id: str,
    body: RepositoryUpdate,
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> RepositoryOut:
    r = await _load_repo(session, repo_id, workspace.id)
    # App-installed repos are tracked authoritatively by the integration
    # sync, which overwrites full_name/default_branch/private/language on
    # every run. Editing those here creates drift the next sync silently
    # undoes, so we refuse them. auto_scan_on_push is the exception: it is
    # never synced from GitHub, so it stays editable as per-repo scan
    # policy. Validate the drift-prone fields BEFORE mutating anything.
    is_app_managed = r.provider == "github" and r.integration_id is not None
    if is_app_managed and (
        body.default_branch is not None
        or body.language is not None
        or body.local_path is not None
        or body.token is not None
    ):
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "App-installed GitHub repos are managed via the integration; "
            "only auto_scan_on_push is editable here. Disconnect the "
            "integration to re-register as a public/PAT repo.",
        )
    if body.default_branch is not None:
        bn = body.default_branch.strip()
        if not bn:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "default_branch must not be empty")
        r.default_branch = bn[:200]
    if body.language is not None:
        lang = body.language.strip()
        r.language = lang[:64] or None
    if body.auto_scan_on_push is not None:
        r.auto_scan_on_push = bool(body.auto_scan_on_push)
    if body.local_path is not None:
        if r.provider != "local":
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                "local_path is only editable on local-provider repos.",
            )
        path = body.local_path.strip()
        if not path:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "local_path must not be empty")
        r.local_path = path
    if body.token is not None:
        # Public-URL repos store no token; PAT repos do. Ignore for
        # local repos. We treat empty string as "clear the token".
        if r.provider != "github":
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                "token is only editable on GitHub-provider repos.",
            )
        if body.token.strip() == "":
            r.token_encrypted = None
        else:
            from ..services.credentials import encrypt_credentials
            r.token_encrypted = encrypt_credentials({"token": body.token.strip()})
    await session.commit()
    await session.refresh(r)
    return _repo_to_out(r)


# ────────────────────────────── Repos list ──────────────────────────────

@router.get(
    "",
    response_model=list[RepositoryOut],
    dependencies=[Depends(require_scope("repos:read"))],
)
async def list_repos(
    q: str | None = Query(None, description="Substring search on full_name"),
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> list[RepositoryOut]:
    return await _list_repos_for_workspace(session, workspace.id, q=q)


# NOTE: This static-path route must be declared BEFORE the parameterised
# ``GET /{repo_id}`` below — FastAPI matches routes in declaration order, so
# registering ``/{repo_id}`` first would catch ``/repos/scans`` with
# ``repo_id="scans"`` and return 404 from ``_load_repo``.
@router.get(
    "/scans",
    response_model=list[RepoScanOut],
    dependencies=[Depends(require_scope("repos:read"))],
)
async def list_all_workspace_repo_scans(
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> list[RepoScanOut]:
    rows = (await session.execute(
        select(RepoScan).where(RepoScan.workspace_id == workspace.id)
        .order_by(RepoScan.created_at.desc()).limit(200)
    )).scalars().all()

    scan_ids = [s.id for s in rows]
    counts_by_scan: dict[str, dict[str, int]] = {}
    if scan_ids:
        sev_rows = (await session.execute(
            select(
                RepoFinding.repo_scan_id,
                RepoFinding.severity,
                func.count(RepoFinding.id),
            )
            .where(
                RepoFinding.repo_scan_id.in_(scan_ids),
                RepoFinding.suppressed.is_(False),
            )
            .group_by(RepoFinding.repo_scan_id, RepoFinding.severity)
        )).all()
        for scan_id, sev, cnt in sev_rows:
            counts_by_scan.setdefault(scan_id, {})[sev] = int(cnt)

    return [_scan_to_out(s, counts_by_scan.get(s.id)) for s in rows]


@router.get(
    "/{repo_id}",
    response_model=RepositoryOut,
    dependencies=[Depends(require_scope("repos:read"))],
)
async def get_repo(
    repo_id: str,
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> RepositoryOut:
    r = await _load_repo(session, repo_id, workspace.id)
    counts = await _severity_counts(session, r.last_scan_id) if r.last_scan_id else None
    return _repo_to_out(r, counts)


@router.post("/{repo_id}/scan", response_model=RepoScanOut,
             dependencies=[Depends(require_scope("repos:write"))],
             status_code=status.HTTP_202_ACCEPTED)
async def start_scan(
    repo_id: str,
    body: ScanRequest | None = None,
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> RepoScanOut:
    r = await _load_repo(session, repo_id, workspace.id)

    # Default scanner pack after the CodeQL removal (Phase 0.1):
    # Semgrep OSS + Bandit + gosec + Brakeman + ESLint-security replace
    # CodeQL's primary SAST role. Older clients passing ``"codeql"``
    # explicitly are coerced onto the new pack at the worker side
    # (``apps/api/pencheff_api/tasks/repo_scan_task.py``).
    scanners = (
        body.scanners if body and body.scanners
        else [
            "semgrep", "bandit", "gosec", "brakeman", "eslint",
            "gitleaks", "ghsa", "yara", "trivy_iac", "checkov",
        ]
    )
    commit_sha: str | None = None
    ref: str | None = None
    if r.provider == "local":
        if r.local_path and os.path.isdir(r.local_path):
            try:
                await asyncio.to_thread(
                    subprocess.run,
                    ["git", "-C", r.local_path, "pull", "--ff-only"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    check=False,
                )
            except Exception:  # noqa: BLE001
                pass
            try:
                sha = await asyncio.to_thread(
                    subprocess.check_output,
                    ["git", "-C", r.local_path, "rev-parse", "HEAD"],
                )
                commit_sha = sha.decode().strip() or None
                ref = "HEAD"
            except Exception:  # noqa: BLE001
                commit_sha = None
                ref = None
    else:
        integration = (
            await _load_integration(session, r.integration_id, workspace.id)
            if r.integration_id else None
        )
        if integration is not None:
            token = await github_app.get_installation_token(integration.installation_id)
            try:
                commit_sha = await github_app.get_default_branch_sha(
                    token, r.full_name, r.default_branch
                )
                ref = f"refs/heads/{r.default_branch}"
            except Exception:  # noqa: BLE001
                commit_sha = None
        elif getattr(r, "token_encrypted", None):
            from ..services.credentials import decrypt_credentials

            tok_blob = decrypt_credentials(r.token_encrypted) or {}
            token = tok_blob.get("token") or ""
            if token:
                try:
                    commit_sha = await github_app.get_default_branch_sha(
                        token, r.full_name, r.default_branch
                    )
                    ref = f"refs/heads/{r.default_branch}"
                except Exception:  # noqa: BLE001
                    commit_sha = None
        else:
            try:
                commit_sha = await github_app.get_public_default_branch_sha(
                    r.full_name, r.default_branch
                )
                ref = f"refs/heads/{r.default_branch}"
            except Exception:  # noqa: BLE001
                commit_sha = None
    # Repo scans are always source_code → the Code & Supply Chain worker.
    await ensure_worker_started_or_503(service=category_service("source_code"))

    scan = RepoScan(
        org_id=workspace.org_id, workspace_id=workspace.id, repository_id=r.id,
        commit_sha=commit_sha,
        ref=ref,
        trigger="manual", status="queued", scanners=scanners,
    )
    session.add(scan)
    await session.commit()
    await session.refresh(scan)

    # Enqueue lazily onto the Code & Supply Chain queue — the helper keeps the
    # task import off the API startup path.
    enqueue_repo_scan(scan.id)

    return _scan_to_out(scan)


@router.post(
    "/{repo_id}/scan/local",
    response_model=RepoScanOut,
    dependencies=[Depends(require_scope("repos:write"))],
    status_code=status.HTTP_202_ACCEPTED,
)
async def start_local_scan(
    repo_id: str,
    body: LocalScanStartRequest | None = None,
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> RepoScanOut:
    """Open a desktop-driven scan row for a local-provider repo.

    Unlike ``/repos/{id}/scan``, this endpoint does **not** dispatch a
    Celery task — the desktop runs the scanners on its own machine and
    streams findings back via ``/repos/scans/{scan_id}/ingest``. The row
    starts in ``running`` state so it shows up in the scan history and
    blocks duplicate dispatches.
    """
    r = await _load_repo(session, repo_id, workspace.id)
    if r.provider != "local":
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "Desktop-local scans are only valid for local-provider repos.",
        )

    req = body or LocalScanStartRequest()
    scanners = req.scanners or [
        "semgrep", "gitleaks", "trivy_fs", "osv_scanner",
    ]
    scan = RepoScan(
        org_id=workspace.org_id,
        workspace_id=workspace.id,
        repository_id=r.id,
        commit_sha=req.commit_sha,
        ref="HEAD" if req.commit_sha else None,
        trigger="desktop_local",
        status="running",
        scanners=scanners,
        started_at=datetime.utcnow(),
    )
    session.add(scan)
    await session.commit()
    await session.refresh(scan)
    return _scan_to_out(scan)


@router.post(
    "/scans/{scan_id}/ingest",
    response_model=RepoScanOut,
    dependencies=[Depends(require_scope("repos:write"))],
)
async def ingest_local_scan(
    scan_id: str,
    body: LocalScanIngestRequest,
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> RepoScanOut:
    """Accept findings + optional SBOM from a desktop-driven scan and
    close out the scan row. Only valid against scans created via the
    ``/repos/{id}/scan/local`` endpoint (``trigger=='desktop_local'``);
    cloud-worker scans are owned by Celery and must not be hijacked.
    """
    s = await _load_scan(session, scan_id, workspace.id)
    if s.trigger != "desktop_local":
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "Ingest is only valid for desktop-local scans.",
        )
    if s.status in ("done", "failed"):
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"Scan is already {s.status}; results were ingested earlier.",
        )

    valid_sev = {"critical", "high", "medium", "low", "info"}
    for raw in body.findings:
        sev = (raw.severity or "info").lower()
        if sev not in valid_sev:
            sev = "info"
        session.add(RepoFinding(
            repo_scan_id=s.id,
            repository_id=s.repository_id,
            scanner=raw.scanner,
            rule_id=raw.rule_id,
            severity=sev,
            title=(raw.title or "(no title)")[:500],
            description=raw.description,
            file_path=raw.file_path,
            line_start=raw.line_start,
            line_end=raw.line_end,
            code_snippet=raw.code_snippet,
            cve=raw.cve,
            package=raw.package,
            installed_version=raw.installed_version,
            fixed_version=raw.fixed_version,
            ai_explanation=raw.ai_explanation,
            fix_status="none",
            suppressed=False,
        ))

    s.stats = body.stats or {}
    s.completed_at = datetime.utcnow()
    if body.error:
        s.status = "failed"
        s.error = body.error
    else:
        s.status = "done"

    r = await _load_repo(session, s.repository_id, workspace.id)
    r.last_scan_id = s.id
    r.last_scan_at = s.completed_at

    if body.sbom is not None:
        fmt = (body.sbom.format or "cyclonedx").lower()
        if fmt not in {"cyclonedx", "spdx"}:
            fmt = "cyclonedx"
        sbom = RepoSbom(
            repository_id=r.id,
            commit_sha=s.commit_sha,
            format=fmt,
            component_count=body.sbom.component_count,
            content=body.sbom.content,
        )
        session.add(sbom)

    await session.commit()
    await session.refresh(s)
    return _scan_to_out(s)


@router.post(
    "/{repo_id}/sbom",
    response_model=RepoSbomOut,
    dependencies=[Depends(require_scope("repos:write"))],
)
async def generate_repo_sbom(
    repo_id: str,
    body: RepoSbomRequest | None = None,
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> RepoSbomOut:
    r = await _load_repo(session, repo_id, workspace.id)
    req = body or RepoSbomRequest()
    fmt = (req.format or "cyclonedx").strip().lower()
    if fmt not in {"cyclonedx", "spdx"}:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "format must be cyclonedx or spdx")

    # Desktop-supplied SBOM (provider="local" repos): the API container
    # can't see the user's filesystem, so the desktop runs trivy
    # locally and posts the finished blob here. We persist it
    # verbatim and skip the worker entirely.
    if req.content is not None:
        await session.execute(delete(RepoSbom).where(RepoSbom.repository_id == r.id))
        component_count = req.component_count
        if component_count is None:
            if fmt == "cyclonedx":
                component_count = len(req.content.get("components") or [])
            else:
                component_count = len(req.content.get("packages") or [])
        sbom = RepoSbom(
            repository_id=r.id,
            commit_sha=req.commit_sha,
            format=fmt,
            content=req.content,
            component_count=component_count,
        )
        session.add(sbom)
        await session.commit()
        await session.refresh(sbom)
        return RepoSbomOut(
            id=sbom.id,
            repository_id=sbom.repository_id,
            commit_sha=sbom.commit_sha,
            format=sbom.format,
            component_count=sbom.component_count,
            content=sbom.content,
            created_at=sbom.created_at,
        )

    await session.execute(delete(RepoSbom).where(RepoSbom.repository_id == r.id))
    workdir = tempfile.mkdtemp(prefix="pencheff-repo-sbom-")
    try:
        if r.provider == "local":
            if not r.local_path or not os.path.isdir(r.local_path):
                raise HTTPException(status.HTTP_400_BAD_REQUEST, "local_path missing or not a directory")
            repo_path = r.local_path
            try:
                await asyncio.to_thread(
                    subprocess.run,
                    ["git", "-C", repo_path, "pull", "--ff-only"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    check=False,
                )
            except Exception:  # noqa: BLE001
                pass
            commit_sha = None
            try:
                sha = await asyncio.to_thread(
                    subprocess.check_output,
                    ["git", "-C", repo_path, "rev-parse", "HEAD"],
                )
                commit_sha = sha.decode().strip() or None
            except Exception:  # noqa: BLE001
                commit_sha = None
        else:
            integration = (
                await _load_integration(session, r.integration_id, workspace.id)
                if r.integration_id else None
            )
            if integration is not None:
                token = await github_app.get_installation_token(integration.installation_id)
                commit_sha = await github_app.get_default_branch_sha(
                    token, r.full_name, r.default_branch
                )
                repo_path = os.path.join(workdir, "src")
                await asyncio.to_thread(
                    github_app.clone_with_token,
                    token,
                    r.full_name,
                    repo_path,
                    commit_sha,
                )
            elif getattr(r, "token_encrypted", None):
                from ..services.credentials import decrypt_credentials

                tok_blob = decrypt_credentials(r.token_encrypted) or {}
                token = tok_blob.get("token") or ""
                if not token:
                    raise HTTPException(status.HTTP_400_BAD_REQUEST, "stored token is empty")
                try:
                    commit_sha = await github_app.get_default_branch_sha(
                        token, r.full_name, r.default_branch
                    )
                except Exception:  # noqa: BLE001
                    commit_sha = None
                repo_path = os.path.join(workdir, "src")
                await asyncio.to_thread(
                    github_app.clone_with_token,
                    token,
                    r.full_name,
                    repo_path,
                    commit_sha,
                )
            else:
                try:
                    commit_sha = await github_app.get_public_default_branch_sha(
                        r.full_name, r.default_branch
                    )
                except Exception:  # noqa: BLE001
                    commit_sha = None
                repo_path = os.path.join(workdir, "src")
                await asyncio.to_thread(
                    github_app.clone_public,
                    r.html_url,
                    repo_path,
                    commit_sha,
                )

        staging_root = os.path.join(workdir, "staging")
        scan_path, _ = clean_repo_dir(repo_path, staging_root)
        from pencheff.modules.sca.sbom_generator import generate_sbom as _gen

        result = await asyncio.to_thread(_gen, Path(scan_path), fmt=fmt)
        content = (result.get("formats") or {}).get(fmt)
        sbom = RepoSbom(
            repository_id=r.id,
            commit_sha=commit_sha,
            format=fmt,
            content=content,
            component_count=result.get("component_count"),
        )
        session.add(sbom)
        await session.commit()
        await session.refresh(sbom)
        return RepoSbomOut(
            id=sbom.id,
            repository_id=sbom.repository_id,
            commit_sha=sbom.commit_sha,
            format=sbom.format,
            component_count=sbom.component_count,
            content=sbom.content,
            created_at=sbom.created_at,
        )
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


@router.get(
    "/{repo_id}/sbom",
    response_model=RepoSbomOut,
    dependencies=[Depends(require_scope("repos:read"))],
)
async def get_repo_sbom(
    repo_id: str,
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> RepoSbomOut:
    r = await _load_repo(session, repo_id, workspace.id)
    row = (await session.execute(
        select(RepoSbom)
        .where(RepoSbom.repository_id == r.id)
        .order_by(RepoSbom.created_at.desc())
        .limit(1)
    )).scalar_one_or_none()
    if not row:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "sbom not found")
    return RepoSbomOut(
        id=row.id,
        repository_id=row.repository_id,
        commit_sha=row.commit_sha,
        format=row.format,
        component_count=row.component_count,
        content=row.content,
        created_at=row.created_at,
    )


@router.get(
    "/{repo_id}/scans",
    response_model=list[RepoScanOut],
    dependencies=[Depends(require_scope("repos:read"))],
)
async def list_scans(
    repo_id: str,
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> list[RepoScanOut]:
    r = await _load_repo(session, repo_id, workspace.id)
    rows = (await session.execute(
        select(RepoScan).where(RepoScan.repository_id == r.id)
        .order_by(RepoScan.created_at.desc()).limit(50)
    )).scalars().all()

    scan_ids = [s.id for s in rows]
    counts_by_scan: dict[str, dict[str, int]] = {}
    if scan_ids:
        sev_rows = (await session.execute(
            select(
                RepoFinding.repo_scan_id,
                RepoFinding.severity,
                func.count(RepoFinding.id),
            )
            .where(
                RepoFinding.repo_scan_id.in_(scan_ids),
                RepoFinding.suppressed.is_(False),
            )
            .group_by(RepoFinding.repo_scan_id, RepoFinding.severity)
        )).all()
        for scan_id, sev, cnt in sev_rows:
            counts_by_scan.setdefault(scan_id, {})[sev] = int(cnt)

    return [_scan_to_out(s, counts_by_scan.get(s.id)) for s in rows]


class RepoTrendScan(BaseModel):
    id: str
    commit_sha: str | None
    completed_at: str | None
    started_at: str | None
    status: str
    severity_counts: dict[str, int]
    scanner_durations_ms: dict[str, int]


class RepoTrendOut(BaseModel):
    repository: dict[str, str | None]
    scans: list[RepoTrendScan]
    open_total: int
    fixed_total: int
    mttr_days: float | None


@router.get(
    "/{repo_id}/trend",
    response_model=RepoTrendOut,
    dependencies=[Depends(require_scope("repos:read"))],
)
async def repo_trend(
    repo_id: str,
    limit: int = Query(20, ge=2, le=50),
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> RepoTrendOut:
    """Per-repository scan history with severity rollup per scan.

    Powers the trend dashboard at ``/repos/{id}/dashboard`` — TrendLine
    of total findings + SeverityStack of severity counts per scan.

    One query for the scans, one aggregation for severity counts per
    scan_id (joined into Python dicts), one aggregation each for the
    open and fixed totals. MTTR is best-effort: RepoFinding doesn't
    track a "fixed_at" column, so we use ``fix_status='merged'`` rows
    and infer the close timestamp from the most recent scan that no
    longer contains a matching ``rule_id`` — too expensive to compute
    on demand. We return ``None`` when we can't infer it; the frontend
    renders a dash.
    """
    r = await _load_repo(session, repo_id, workspace.id)

    scan_rows = (await session.execute(
        select(RepoScan).where(RepoScan.repository_id == r.id)
        .order_by(RepoScan.created_at.asc()).limit(limit)
    )).scalars().all()

    if not scan_rows:
        return RepoTrendOut(
            repository={
                "id": str(r.id),
                "full_name": r.full_name,
                "default_branch": r.default_branch,
            },
            scans=[], open_total=0, fixed_total=0, mttr_days=None,
        )

    scan_ids = [s.id for s in scan_rows]

    # One SQL roll-up: severity count per (scan_id, severity).
    sev_rows = (await session.execute(
        select(
            RepoFinding.repo_scan_id,
            RepoFinding.severity,
            func.count(RepoFinding.id),
        )
        .where(
            RepoFinding.repo_scan_id.in_(scan_ids),
            RepoFinding.suppressed.is_(False),
        )
        .group_by(RepoFinding.repo_scan_id, RepoFinding.severity)
    )).all()
    sev_map: dict[str, dict[str, int]] = {sid: {} for sid in scan_ids}
    for sid, sev, n in sev_rows:
        sev_map[sid][(sev or "info").lower()] = int(n)

    def _normalise(sev: dict[str, int]) -> dict[str, int]:
        return {
            k: int(sev.get(k, 0))
            for k in ("critical", "high", "medium", "low", "info")
        }

    def _scanner_durations(stats: dict | None) -> dict[str, int]:
        if not isinstance(stats, dict):
            return {}
        out: dict[str, int] = {}
        for scanner, payload in stats.items():
            if isinstance(payload, dict) and isinstance(
                payload.get("duration_ms"), (int, float)
            ):
                out[scanner] = int(payload["duration_ms"])
        return out

    scans = [
        RepoTrendScan(
            id=str(s.id),
            commit_sha=s.commit_sha,
            completed_at=s.completed_at.isoformat() if s.completed_at else None,
            started_at=s.started_at.isoformat() if s.started_at else None,
            status=s.status or "unknown",
            severity_counts=_normalise(sev_map.get(s.id, {})),
            scanner_durations_ms=_scanner_durations(s.stats),
        )
        for s in scan_rows
    ]

    # Repo-wide open + fixed totals across all scans of this repo.
    counts = (await session.execute(
        select(
            func.count(RepoFinding.id).filter(
                RepoFinding.suppressed.is_(False),
                RepoFinding.fix_status != "merged",
            ),
            func.count(RepoFinding.id).filter(
                RepoFinding.fix_status == "merged",
            ),
        )
        .join(RepoScan, RepoScan.id == RepoFinding.repo_scan_id)
        .where(RepoScan.repository_id == r.id)
    )).one()
    open_total, fixed_total = counts

    return RepoTrendOut(
        repository={
            "id": str(r.id),
            "full_name": r.full_name,
            "default_branch": r.default_branch,
        },
        scans=scans,
        open_total=int(open_total or 0),
        fixed_total=int(fixed_total or 0),
        mttr_days=None,
    )


# ─────────────────────────────── Scan detail ───────────────────────────────

@router.get(
    "/scans/{scan_id}",
    response_model=RepoScanOut,
    dependencies=[Depends(require_scope("repos:read"))],
)
async def get_scan(
    scan_id: str,
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> RepoScanOut:
    s = await _load_scan(session, scan_id, workspace.id)
    counts = await _severity_counts(session, s.id)
    return _scan_to_out(s, counts)


@router.get(
    "/scans/{scan_id}/findings",
    response_model=list[RepoFindingOut],
    dependencies=[Depends(require_scope("repos:read"))],
)
async def list_scan_findings(
    scan_id: str,
    severity: str | None = Query(None),
    scanner: str | None = Query(None),
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> list[RepoFindingOut]:
    await _load_scan(session, scan_id, workspace.id)  # authz check
    stmt = select(RepoFinding).where(RepoFinding.repo_scan_id == scan_id,
                                     RepoFinding.suppressed.is_(False))
    if severity:
        stmt = stmt.where(RepoFinding.severity == severity)
    if scanner:
        stmt = stmt.where(RepoFinding.scanner == scanner)
    stmt = stmt.order_by(RepoFinding.severity, RepoFinding.file_path)
    rows = (await session.execute(stmt)).scalars().all()
    return [_finding_to_out(f) for f in rows]


@router.get(
    "/scans/{scan_id}/compliance",
    dependencies=[Depends(require_scope("repos:read"))],
)
async def get_repo_scan_compliance(
    scan_id: str,
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> dict:
    """Return the per-scan compliance rollup for a repository scan.

    Mirrors ``GET /scans/{id}/compliance`` (URL / LLM scans) so the
    same web UI component, JSON exporter, and report appendix can
    consume any scan id without branching by target kind.

    RepoFinding rows do not carry an explicit ``category`` — the
    rollup service infers one from the scanner that produced the row
    plus a few well-known tokens in ``rule_id`` (xss / sql / ssrf /
    crypto / secret / …). Frameworks emitted: OWASP Top 10, PCI-DSS,
    NIST 800-53, SOC 2, ISO 27001:2022, HIPAA.
    """
    from ..services.compliance import build_compliance_rollup

    await _load_scan(session, scan_id, workspace.id)  # authz check

    rows = (await session.execute(
        select(RepoFinding).where(
            RepoFinding.repo_scan_id == scan_id,
            RepoFinding.suppressed.is_(False),
        )
    )).scalars().all()

    return build_compliance_rollup(
        scan_id=scan_id,
        target_kind="repo",
        findings=rows,
    )


@router.delete(
    "/scans/{scan_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require_scope("repos:write"))],
)
async def delete_scan(
    scan_id: str,
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> None:
    """Remove a repository scan and its findings.

    Cascades through ORM relationships configured on ``RepoScan`` —
    ``RepoFinding`` rows tied to the scan come along with it.
    """
    s = await _load_scan(session, scan_id, workspace.id)
    await session.delete(s)
    await session.commit()


# ──────────────────────────────── helpers ────────────────────────────────

async def _load_integration(session: AsyncSession, integration_id: str, workspace_id: str) -> RepoIntegration:
    i = (await session.execute(
        select(RepoIntegration).where(
            RepoIntegration.id == integration_id,
            RepoIntegration.workspace_id == workspace_id,
        )
    )).scalar_one_or_none()
    if not i:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "integration not found")
    return i


async def _load_repo(session: AsyncSession, repo_id: str, workspace_id: str) -> Repository:
    r = (await session.execute(
        select(Repository).where(
            Repository.id == repo_id, Repository.workspace_id == workspace_id,
        )
    )).scalar_one_or_none()
    if not r:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "repository not found")
    return r


async def _load_scan(session: AsyncSession, scan_id: str, workspace_id: str) -> RepoScan:
    s = (await session.execute(
        select(RepoScan).where(RepoScan.id == scan_id, RepoScan.workspace_id == workspace_id)
    )).scalar_one_or_none()
    if not s:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "scan not found")
    return s


async def _list_repos_for_workspace(
    session: AsyncSession, workspace_id: str, q: str | None = None,
) -> list[RepositoryOut]:
    stmt = select(Repository).where(Repository.workspace_id == workspace_id)
    if q:
        stmt = stmt.where(Repository.full_name.ilike(f"%{q}%"))
    stmt = stmt.order_by(Repository.full_name)
    rows = (await session.execute(stmt)).scalars().all()

    # Batch-fetch severity counts per repo's last scan so callers (the
    # Targets dashboard) can render CRIT/HIGH/MED/LOW without an N+1
    # roundtrip.
    scan_ids = [r.last_scan_id for r in rows if r.last_scan_id]
    counts_by_scan: dict[str, dict[str, int]] = {}
    if scan_ids:
        sev_rows = (await session.execute(
            select(
                RepoFinding.repo_scan_id,
                RepoFinding.severity,
                func.count(RepoFinding.id),
            )
            .where(
                RepoFinding.repo_scan_id.in_(scan_ids),
                RepoFinding.suppressed.is_(False),
            )
            .group_by(RepoFinding.repo_scan_id, RepoFinding.severity)
        )).all()
        for scan_id, sev, cnt in sev_rows:
            counts_by_scan.setdefault(scan_id, {})[sev] = int(cnt)

    return [
        _repo_to_out(r, counts_by_scan.get(r.last_scan_id) if r.last_scan_id else None)
        for r in rows
    ]


async def _severity_counts(session: AsyncSession, scan_id: str | None) -> dict[str, int]:
    if not scan_id:
        return {}
    rows = (await session.execute(
        select(RepoFinding.severity, func.count()).where(
            RepoFinding.repo_scan_id == scan_id,
            RepoFinding.suppressed.is_(False),
        ).group_by(RepoFinding.severity)
    )).all()
    return {sev: int(cnt) for sev, cnt in rows}


async def _sync_integration_repos(session: AsyncSession, integ: RepoIntegration) -> None:
    token = await github_app.get_installation_token(integ.installation_id)
    raw = await github_app.list_installation_repos(token)
    summaries = github_app.summarize_repos(raw)
    # Upsert each repo. Track every Repository row touched (new or
    # updated) so we can ensure each has a mirror Target after the flush.
    touched: list[Repository] = []
    for s in summaries:
        existing = (await session.execute(
            select(Repository).where(
                Repository.provider == "github",
                Repository.provider_repo_id == str(s.provider_repo_id),
            )
        )).scalar_one_or_none()
        if existing:
            existing.org_id = integ.org_id
            existing.workspace_id = integ.workspace_id
            existing.integration_id = integ.id
            existing.owner = s.owner
            existing.name = s.name
            existing.full_name = s.full_name
            existing.default_branch = s.default_branch
            existing.private = s.private
            existing.html_url = s.html_url
            existing.language = s.language
            touched.append(existing)
        else:
            new_repo = Repository(
                org_id=integ.org_id, workspace_id=integ.workspace_id,
                integration_id=integ.id,
                provider="github", provider_repo_id=str(s.provider_repo_id),
                owner=s.owner, name=s.name, full_name=s.full_name,
                default_branch=s.default_branch, private=s.private,
                html_url=s.html_url, language=s.language,
            )
            session.add(new_repo)
            touched.append(new_repo)
    # Flush so freshly-added Repositories get their IDs populated.
    await session.flush()
    # Mirror each touched Repository as a Target — idempotent, so
    # re-syncing the same install won't create duplicates.
    for r in touched:
        await _ensure_mirror_target(session, r)
    await session.commit()


async def purge_integration_repos(session: AsyncSession, integration_id: str) -> int:
    """Hard-delete every GitHub-App Repository tied to ``integration_id``.

    Called when an installation is uninstalled (webhook ``installation.deleted``)
    or manually disconnected. Detaches any URL-target attachments first
    (``target_repositories.repository_id`` is ON DELETE RESTRICT, so it would
    otherwise block the delete), then deletes the Repository rows. The DB-level
    ON DELETE CASCADE on the mirror ``Target``, ``RepoScan`` and ``RepoFinding``
    rows removes those automatically.

    Does NOT commit — the caller owns the transaction (so the integration's
    ``removed_at`` update and this purge land atomically). Returns the number
    of repositories deleted.
    """
    repo_ids = (await session.execute(
        select(Repository.id).where(Repository.integration_id == integration_id)
    )).scalars().all()
    if not repo_ids:
        return 0
    # Detach from any URL targets first (RESTRICT FK), else the delete fails.
    await session.execute(
        delete(TargetRepository).where(TargetRepository.repository_id.in_(repo_ids))
    )
    await session.execute(
        delete(Repository).where(Repository.id.in_(repo_ids))
    )
    return len(repo_ids)


def _repo_to_out(r: Repository, counts: dict[str, int] | None = None) -> RepositoryOut:
    return RepositoryOut(
        id=r.id, provider=r.provider, integration_id=r.integration_id,
        full_name=r.full_name,
        owner=r.owner, name=r.name, default_branch=r.default_branch,
        private=r.private, html_url=r.html_url, language=r.language,
        auto_scan_on_push=r.auto_scan_on_push,
        last_scan_id=r.last_scan_id, last_scan_at=r.last_scan_at,
        severity_counts=counts,
        local_path=r.local_path,
    )


def _scan_to_out(s: RepoScan, summary: dict[str, int] | None = None) -> RepoScanOut:
    return RepoScanOut(
        id=s.id, repository_id=s.repository_id,
        commit_sha=s.commit_sha, ref=s.ref, trigger=s.trigger,
        status=s.status, scanners=s.scanners, stats=s.stats,
        started_at=s.started_at, completed_at=s.completed_at,
        error=s.error, created_at=s.created_at,
        summary=summary,
    )


def _finding_to_out(f: RepoFinding) -> RepoFindingOut:
    return RepoFindingOut(
        id=f.id, scanner=f.scanner, rule_id=f.rule_id, severity=f.severity,
        title=f.title, description=f.description,
        file_path=f.file_path, line_start=f.line_start, line_end=f.line_end,
        code_snippet=f.code_snippet, cve=f.cve, package=f.package,
        installed_version=f.installed_version, fixed_version=f.fixed_version,
        ai_explanation=f.ai_explanation, fix_status=f.fix_status,
        fix_pr_url=f.fix_pr_url, suppressed=f.suppressed,
    )
