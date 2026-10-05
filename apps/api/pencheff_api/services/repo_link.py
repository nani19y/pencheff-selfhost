# apps/api/pencheff_api/services/repo_link.py
"""Bridge: a source_code target registered with a GitHub URL + PAT auto-links a
connected Repository (storing the PAT) so it flows into the agentic Fix → PR
machinery, identical to a GitHub-App repo. Best-effort: never raises to callers.

ponytail: the Repository field build mirrors routers/repos.connect_github_url's
inline block. Kept separate (not a shared refactor) to avoid touching that live
endpoint's HTTP-error mapping; the duplication is ~12 lines and stable.
"""
from __future__ import annotations

import logging
import re

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db.models import Repository, TargetRepository
from . import github_app
from .credentials import decrypt_credentials, encrypt_credentials

log = logging.getLogger("pencheff.repo_link")

_GITHUB_URL_RE = re.compile(
    r"^https?://(?:www\.)?github\.com/([^/]+)/([^/#?]+?)(?:\.git)?/?$"
)


def _parse_github_url(url: str | None) -> tuple[str, str] | None:
    m = _GITHUB_URL_RE.match((url or "").strip())
    return (m.group(1), m.group(2)) if m else None


def _github_repo_url(target) -> str | None:
    cfg = getattr(target, "kind_config", None) or {}
    kind = getattr(target, "kind", None)
    if kind == "source_code":
        # source_code distinguishes github_url vs tarball/local sources.
        if cfg.get("source") != "github_url":
            return None
        return cfg.get("repo_url") or None
    if kind in ("cicd_pipeline", "iac"):
        # cicd/iac carry the repo directly on kind_config.repo_url.
        return cfg.get("repo_url") or None
    return None


def _pat_for(target) -> str | None:
    creds = decrypt_credentials(getattr(target, "kind_credentials_encrypted", None)) or {}
    # source_code uses {auth_type: "pat", pat: …}; cicd/iac use {token: …}.
    if creds.get("auth_type") == "pat" and creds.get("pat"):
        return creds["pat"].strip() or None
    if creds.get("token"):
        return str(creds["token"]).strip() or None
    return None


async def ensure_repo_link_for_target(session: AsyncSession, target, workspace) -> Repository | None:
    """Idempotently link a connected Repository (PAT) to a qualifying source_code
    target. Returns the Repository, or None when the target doesn't qualify or
    GitHub validation fails. Never raises; rolls back its own work on error."""
    try:
        # Repo-backed kinds whose findings can be fixed by editing files + PR.
        # (GitLab/Jenkins repos won't match _parse_github_url below — agent-fix
        # is GitHub-PR-based — so they simply don't auto-link.)
        if getattr(target, "kind", None) not in ("source_code", "cicd_pipeline", "iac"):
            return None
        parsed = _parse_github_url(_github_repo_url(target))
        pat = _pat_for(target)
        if not parsed or not pat:
            return None

        # Idempotent: already linked → return the linked repo, no GitHub call.
        linked = (await session.execute(
            select(Repository)
            .join(TargetRepository, TargetRepository.repository_id == Repository.id)
            .where(TargetRepository.target_id == target.id)
        )).scalars().first()
        if linked is not None:
            return linked

        owner, name = parsed
        full_name = f"{owner}/{name}"
        meta = await github_app.get_repo(pat, full_name)
        provider_repo_id = str(meta["id"])

        repo = (await session.execute(
            select(Repository).where(
                Repository.provider == "github",
                Repository.provider_repo_id == provider_repo_id,
            )
        )).scalar_one_or_none()
        if repo is not None:
            if repo.workspace_id != workspace.id:
                log.warning("repo_link: %s connected in another workspace; skipping", full_name)
                return None
            repo.token_encrypted = encrypt_credentials({"token": pat})  # rotate
        else:
            repo = Repository(
                org_id=workspace.org_id,
                workspace_id=workspace.id,
                integration_id=None,
                provider="github",
                provider_repo_id=provider_repo_id,
                owner=meta["owner"]["login"],
                name=(meta.get("name") or name)[:200],
                full_name=meta["full_name"],
                default_branch=meta.get("default_branch") or "main",
                private=bool(meta.get("private", False)),
                html_url=meta["html_url"],
                language=meta.get("language"),
                auto_scan_on_push=False,
                token_encrypted=encrypt_credentials({"token": pat}),
            )
            session.add(repo)
            await session.flush()

        exists = (await session.execute(
            select(TargetRepository).where(
                TargetRepository.target_id == target.id,
                TargetRepository.repository_id == repo.id,
            )
        )).scalar_one_or_none()
        if exists is None:
            session.add(TargetRepository(target_id=target.id, repository_id=repo.id))

        await session.commit()
        await session.refresh(repo)
        return repo
    except Exception as exc:  # noqa: BLE001 — best-effort, never break the caller
        log.warning("repo_link: ensure failed for target %s: %s",
                    getattr(target, "id", "?"), exc)
        try:
            await session.rollback()
        except Exception:  # noqa: BLE001
            pass
        return None
