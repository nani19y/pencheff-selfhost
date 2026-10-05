"""Inbound GitHub App webhooks.

Signature verification is mandatory — anything without a valid HMAC gets a
401. Events we handle today:

    installation, installation_repositories — keep our repo list in sync.
    push                                    — auto-trigger scans on default-branch pushes.
    dependabot_alert                        — upsert as a RepoFinding.
"""

from __future__ import annotations

import json
import logging

from fastapi import APIRouter, Header, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db.base import SessionLocal
from ..db.models import Repository, RepoFinding, RepoIntegration, RepoScan
from ..scan_categories import category_service
from ..services import github_app
from ..services.scan_dispatch import enqueue_repo_scan
from ..services.worker_lifecycle import ensure_worker_started_or_503

log = logging.getLogger(__name__)

router = APIRouter(prefix="/webhooks", tags=["webhooks"])


@router.post("/github", status_code=status.HTTP_202_ACCEPTED)
async def github_webhook(
    request: Request,
    x_hub_signature_256: str | None = Header(default=None),
    x_github_event: str | None = Header(default=None),
) -> dict[str, str]:
    body = await request.body()
    if not github_app.verify_webhook_signature(x_hub_signature_256, body):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "bad signature")

    payload = json.loads(body or b"{}")
    event = (x_github_event or "").lower()
    handled = "ignored"

    async with SessionLocal() as session:
        if event in ("installation", "installation_repositories"):
            handled = await _handle_installation(session, payload)
        elif event == "push":
            handled = await _handle_push(session, payload)
        elif event == "dependabot_alert":
            handled = await _handle_dependabot_alert(session, payload)

    return {"status": handled}


async def _handle_installation(session: AsyncSession, payload: dict) -> str:
    installation = payload.get("installation") or {}
    installation_id = installation.get("id")
    if not installation_id:
        return "missing-installation-id"

    integ = (await session.execute(
        select(RepoIntegration).where(
            RepoIntegration.provider == "github",
            RepoIntegration.installation_id == str(installation_id),
        )
    )).scalar_one_or_none()

    action = payload.get("action", "")
    if action in ("deleted", "suspend"):
        if integ:
            from datetime import datetime
            integ.removed_at = datetime.utcnow()
            # A full uninstall is permanent: hard-delete the repos this
            # installation brought in (cascades to mirror targets, scans and
            # findings) so they stop listing. A suspend is reversible, so we
            # only flag it and keep the repos for when it's unsuspended.
            if action == "deleted":
                from .repos import purge_integration_repos
                await purge_integration_repos(session, integ.id)
            await session.commit()
        return "integration-removed"

    if not integ:
        # Install happened via the GitHub UI before we got a web callback
        # (e.g. installed from the Marketplace). Without an org binding we
        # can't safely persist — bail out and let the /callback flow seed it.
        return "unknown-installation"

    # Refresh the repo list.
    try:
        token = await github_app.get_installation_token(installation_id)
        raw = await github_app.list_installation_repos(token)
        summaries = github_app.summarize_repos(raw)
        for s in summaries:
            existing = (await session.execute(
                select(Repository).where(
                    Repository.provider == "github",
                    Repository.provider_repo_id == str(s.provider_repo_id),
                )
            )).scalar_one_or_none()
            if existing:
                existing.integration_id = integ.id
                existing.org_id = integ.org_id
                existing.workspace_id = integ.workspace_id
                existing.full_name = s.full_name
                existing.default_branch = s.default_branch
                existing.private = s.private
                existing.html_url = s.html_url
                existing.language = s.language
            else:
                session.add(Repository(
                    org_id=integ.org_id, workspace_id=integ.workspace_id,
                    integration_id=integ.id,
                    provider="github", provider_repo_id=str(s.provider_repo_id),
                    owner=s.owner, name=s.name, full_name=s.full_name,
                    default_branch=s.default_branch, private=s.private,
                    html_url=s.html_url, language=s.language,
                ))
        await session.commit()
        return "repos-synced"
    except Exception:  # noqa: BLE001
        log.exception("webhook repo sync failed")
        return "sync-error"


async def _handle_push(session: AsyncSession, payload: dict) -> str:
    ref = payload.get("ref", "")
    repo = payload.get("repository") or {}
    provider_repo_id = repo.get("id")
    if not provider_repo_id:
        return "missing-repo-id"

    our_repo = (await session.execute(
        select(Repository).where(
            Repository.provider == "github",
            Repository.provider_repo_id == str(provider_repo_id),
        )
    )).scalar_one_or_none()
    if not our_repo or not our_repo.auto_scan_on_push:
        return "repo-not-tracked-or-auto-scan-disabled"

    # Only scan default-branch commits to avoid noise.
    if ref != f"refs/heads/{our_repo.default_branch}":
        return "non-default-branch-skipped"

    # Repo scans are always source_code → the Code & Supply Chain worker.
    await ensure_worker_started_or_503(service=category_service("source_code"))

    commit_sha = payload.get("after") or payload.get("head_commit", {}).get("id")
    scan = RepoScan(
        org_id=our_repo.org_id,
        workspace_id=our_repo.workspace_id,
        repository_id=our_repo.id,
        commit_sha=commit_sha, ref=ref,
        trigger="webhook", status="queued",
        scanners=["semgrep", "gitleaks", "osv", "yara", "ghsa"],
    )
    session.add(scan)
    await session.commit()
    await session.refresh(scan)

    enqueue_repo_scan(scan.id)
    return "scan-queued"


async def _handle_dependabot_alert(session: AsyncSession, payload: dict) -> str:
    """Upsert the alert into RepoFinding under a synthetic 'ghsa' scan slot.

    We don't create a full RepoScan for alert events; instead they land on
    the repo's most-recent scan so the UI keeps dependabot + scanner findings
    in the same place.
    """
    action = payload.get("action")
    if action not in ("created", "reopened"):
        return f"alert-action-{action}"

    alert = payload.get("alert") or {}
    repo = payload.get("repository") or {}
    provider_repo_id = repo.get("id")

    our_repo = (await session.execute(
        select(Repository).where(
            Repository.provider == "github",
            Repository.provider_repo_id == str(provider_repo_id),
        )
    )).scalar_one_or_none()
    if not our_repo or not our_repo.last_scan_id:
        return "no-scan-to-attach-to"

    from ..services.repo_findings import normalize_dependabot
    norm = normalize_dependabot([alert])
    for f in norm:
        session.add(RepoFinding(
            repo_scan_id=our_repo.last_scan_id,
            repository_id=our_repo.id,
            scanner=f["scanner"],
            rule_id=f.get("rule_id"),
            severity=f.get("severity") or "medium",
            title=(f.get("title") or "finding")[:500],
            description=f.get("description"),
            file_path=f.get("file_path"),
            cve=f.get("cve"),
            package=f.get("package"),
            installed_version=f.get("installed_version"),
            fixed_version=f.get("fixed_version"),
            raw=f.get("raw"),
        ))
    await session.commit()
    return "alert-recorded"
