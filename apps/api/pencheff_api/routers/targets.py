from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth.deps import get_active_workspace, get_current_user, require_scope
from ..db.base import get_session
from ..db.models import AuditLog, Org, Repository, Target, TargetRepository, User, Workspace
from ..schemas.targets import (
    ATTACHABLE_REPOSITORY_TARGET_KINDS,
    DISCIPLINE_TO_KINDS,
    KindConfig,
    LlmConfig,
    TargetCreate,
    TargetOut,
    TargetUpdate,
)
from ..services import repo_link
from ..services.credentials import encrypt_credentials
from ..services.llm_model_catalog import (
    LlmModelCatalogOut,
    LlmModelCatalogRequest,
    fetch_llm_model_catalog,
)
from ..services.quota import check_target_quota

from pydantic import TypeAdapter

_kind_config_adapter: TypeAdapter[KindConfig] = TypeAdapter(KindConfig)

router = APIRouter(prefix="/targets", tags=["targets"])


# ─── Discipline-driven registration defaults ─────────────────────────────────
#
# Per spec docs/superpowers/specs/2026-05-21-discipline-target-picker-design.md
# §"Scan-time effects". Applied server-side at POST + PATCH so FE bypass can't
# disable the discipline's safety floor (rbac_enum / network_policy_audit /
# aggressive red-team strategies / guardrails).

# Aggressive red-team strategy set seeded when a Target is tagged ai_redteam.
_AI_REDTEAM_DEFAULT_STRATEGIES: tuple[str, ...] = (
    "jailbreak", "crescendo", "base64", "leetspeak",
)
_AI_REDTEAM_DEFAULT_DATASETS: tuple[str, ...] = ("harmbench",)
# Guardrails seeded when a Target is tagged ai_spm.
_AI_SPM_DEFAULT_GUARDRAILS: tuple[str, ...] = (
    "pii", "secrets", "unsafe-code", "tool-authz",
)


def _union(existing: object, additions: tuple[str, ...]) -> list[str]:
    """Merge ``additions`` into ``existing`` (which may be a list or None),
    preserving first-occurrence order and dropping dups."""
    out: list[str] = []
    seen: set[str] = set()
    if isinstance(existing, list):
        for v in existing:
            if isinstance(v, str) and v not in seen:
                seen.add(v)
                out.append(v)
    for v in additions:
        if v not in seen:
            seen.add(v)
            out.append(v)
    return out


def _apply_discipline_defaults(
    disciplines: list[str],
    kind_config: dict | None,
    llm_config: dict | None,
) -> tuple[dict | None, dict | None]:
    """Apply discipline-driven registration defaults to (kind_config, llm_config).

    Returns the (possibly-mutated) dicts. Never raises — unknown disciplines
    are already rejected by the Pydantic validator before this is called.
    """
    if "kspm" in disciplines or "kiem" in disciplines:
        if isinstance(kind_config, dict) and kind_config.get("kind") == "k8s_cluster":
            kind_config["rbac_enum"] = True
            kind_config["network_policy_audit"] = True
    if "ai_redteam" in disciplines:
        if isinstance(llm_config, dict):
            redteam = llm_config.get("redteam")
            if not isinstance(redteam, dict):
                redteam = {}
            redteam["strategies"] = _union(
                redteam.get("strategies"), _AI_REDTEAM_DEFAULT_STRATEGIES,
            )
            redteam["datasets"] = _union(
                redteam.get("datasets"), _AI_REDTEAM_DEFAULT_DATASETS,
            )
            llm_config["redteam"] = redteam
    if "ai_spm" in disciplines:
        if isinstance(llm_config, dict):
            redteam = llm_config.get("redteam")
            if not isinstance(redteam, dict):
                redteam = {}
            redteam["guardrails"] = _union(
                redteam.get("guardrails"), _AI_SPM_DEFAULT_GUARDRAILS,
            )
            llm_config["redteam"] = redteam
    return kind_config, llm_config


async def _attached_repo_ids(session: AsyncSession, target_id: str) -> list[str]:
    rows = (await session.execute(
        select(TargetRepository.repository_id)
        .where(TargetRepository.target_id == target_id)
    )).scalars().all()
    return list(rows)


async def _validate_and_replace_attachments(
    session: AsyncSession,
    target: Target,
    repository_ids: list[str],
    *,
    workspace_id: str,
) -> None:
    """Replace the target's attached-repo set with ``repository_ids``.

    Validates: each ID exists, belongs to the same workspace as the target,
    and the target kind supports source-repo attachment (already enforced
    by the schema's model validator on create; double-checked here on update).
    """
    if target.kind not in ATTACHABLE_REPOSITORY_TARGET_KINDS:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "attached_repository_ids only valid on runtime, cloud, or AI target kinds",
        )
    repository_ids = list(dict.fromkeys(repository_ids))  # preserve order, drop dups
    if repository_ids:
        repos = (await session.execute(
            select(Repository).where(
                Repository.id.in_(repository_ids),
                Repository.workspace_id == workspace_id,
            )
        )).scalars().all()
        found = {r.id for r in repos}
        missing = [rid for rid in repository_ids if rid not in found]
        if missing:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                f"Repositories not found in this workspace: {', '.join(missing)}",
            )
    await session.execute(
        delete(TargetRepository).where(TargetRepository.target_id == target.id)
    )
    for rid in repository_ids:
        session.add(TargetRepository(target_id=target.id, repository_id=rid))


def _to_out(t: Target, attached_ids: list[str] | None = None) -> TargetOut:
    # repository_id is the authoritative signal for repository mirrors.
    # Older rows may have been created without kind='repo'; keep the API
    # stable so callers always route them through /repos.
    kind = "repo" if t.repository_id else t.kind
    llm_cfg = None
    if kind == "llm" and t.llm_config:
        try:
            llm_cfg = LlmConfig.model_validate(t.llm_config)
        except Exception:
            # Bad row — surface it but don't 500 the list endpoint.
            llm_cfg = None
    # Per-feature-001: parse Target.kind_config back into the typed
    # discriminated union for response serialisation. Tolerate bad rows.
    kind_cfg = None
    if kind not in {"url", "repo", "llm"} and t.kind_config:
        try:
            kind_cfg = _kind_config_adapter.validate_python(t.kind_config)
        except Exception:
            kind_cfg = None
    return TargetOut(
        id=t.id, name=t.name, base_url=t.base_url, scope=t.scope,
        exclude_paths=t.exclude_paths, has_credentials=bool(t.credentials_encrypted),
        repository_id=t.repository_id,
        kind=kind,
        llm_config=llm_cfg,
        kind_config=kind_cfg,
        has_kind_credentials=bool(t.kind_credentials_encrypted),
        attached_repository_ids=list(attached_ids or []),
        disciplines=list(getattr(t, "disciplines", None) or []),
        weekly_digest_emails=t.weekly_digest_emails,
        created_at=t.created_at,
    )


def _reject_if_repo_mirror(t: Target, action: str) -> None:
    """Repo-mirror Targets are managed via /repos. Reject mutation."""
    if t.repository_id:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            f"Cannot {action} a repository-backed target. "
            "Repository targets mirror their Repository row — manage them "
            f"via /repos/{t.repository_id} instead.",
        )


async def _maybe_link_repo(session, target, workspace) -> None:
    """Best-effort: link a connected Repository for a source_code+PAT GitHub
    target so it gets the agentic Fix → PR flow. Never raises."""
    try:
        await repo_link.ensure_repo_link_for_target(session, target, workspace)
    except Exception:  # noqa: BLE001
        pass


@router.post(
    "",
    response_model=TargetOut,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_scope("targets:write"))],
)
async def create_target(
    body: TargetCreate,
    request: Request,
    user: User = Depends(get_current_user),
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> TargetOut:
    await check_target_quota(session, workspace.org_id)

    # Sub-project A: host-kind branch. Validates per-host DNS resolution and
    # RFC1918 gate, then server-sets is_private_target. The OSExploitAgent
    # (sub-project B) consumes Target.kind_config.hosts at scan time.
    if body.kind == "host":
        from pencheff_api.services.host_validation import classify_host_list
        from pencheff_api.schemas.targets import HostKindConfig

        # Load the Org to check the allow_private_targets flag.
        org: Org = await session.get(Org, workspace.org_id)
        assert body.kind_config is not None  # enforced by HostKindConfig validator
        cfg = body.kind_config
        classification = classify_host_list(cfg.hosts)
        if classification.has_errors:
            raise HTTPException(
                status_code=422,
                detail={
                    "error": "host_kind_resolution_failed",
                    "message": "One or more hosts could not be resolved.",
                    "errors": classification.error_hosts,
                },
            )
        if classification.any_private and not org.allow_private_targets:
            raise HTTPException(
                status_code=422,
                detail={
                    "error": "host_kind_private_targets_disabled",
                    "message": (
                        "Your org does not permit private-IP host targets. Ask an "
                        "admin to enable allow_private_targets, or remove the "
                        "private hosts."
                    ),
                    "offending_hosts": classification.private_hosts,
                },
            )
        # Server-side rewrite — strip any client-supplied is_private_target.
        cfg_dict = cfg.model_dump()
        cfg_dict["is_private_target"] = classification.any_private
        body = body.model_copy(update={"kind_config": HostKindConfig(**cfg_dict)})

    creds_blob = encrypt_credentials(body.credentials.model_dump() if body.credentials else None)
    # Per-feature-001: per-kind credentials (kubeconfig / registry / CI tokens /
    # GitHub App private key) ride on a sibling Fernet column. Same encryption
    # primitive, same key rotation policy.
    kind_creds_blob = encrypt_credentials(
        body.kind_credentials.model_dump() if body.kind_credentials else None
    )
    # Apply discipline-driven registration defaults server-side so an FE bypass
    # can't disable them. KSPM/KIEM enforce RBAC + network-policy enumeration on
    # the k8s_cluster config; AI Red Teaming / AI-SPM merge aggressive defaults
    # into llm_config.redteam.
    kind_config_dict = body.kind_config.model_dump(mode="json") if body.kind_config else None
    llm_config_dict = body.llm_config.model_dump(mode="json") if body.llm_config else None
    if body.disciplines:
        kind_config_dict, llm_config_dict = _apply_discipline_defaults(
            list(body.disciplines), kind_config_dict, llm_config_dict,
        )
    t = Target(
        org_id=workspace.org_id, workspace_id=workspace.id, user_id=user.id,
        name=body.name, base_url=str(body.base_url),
        scope=body.scope, exclude_paths=body.exclude_paths,
        credentials_encrypted=creds_blob,
        kind_credentials_encrypted=kind_creds_blob,
        kind=body.kind,
        # Pydantic → JSONB-friendly dict. None for legacy url/repo targets.
        llm_config=llm_config_dict,
        kind_config=kind_config_dict,
        disciplines=list(body.disciplines) if body.disciplines else None,
    )
    session.add(t)
    await session.flush()  # need t.id before writing the join rows
    if body.attached_repository_ids:
        await _validate_and_replace_attachments(
            session, t, body.attached_repository_ids, workspace_id=workspace.id,
        )
    await session.commit()
    await session.refresh(t)
    await _maybe_link_repo(session, t, workspace)
    # _maybe_link_repo rolls back its own transaction when GitHub validation
    # fails (e.g. a private repo the PAT can't see → 404), which expires every
    # ORM object in the session — including t. Reload t in async context so the
    # sync _to_out(t) serialization below doesn't trigger a lazy attribute
    # reload → MissingGreenlet (a 500 that escaped CORS as "Failed to fetch",
    # even though the target itself committed fine above).
    await session.refresh(t)

    if body.kind == "host":
        audit = AuditLog(
            org_id=workspace.org_id,
            workspace_id=workspace.id,
            user_id=user.id,
            action="target.host.create",
            entity_type="target",
            entity_id=t.id,
            request_ip=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
            meta={
                "target_id": t.id,
                "hosts": body.kind_config.hosts,
                "is_private_target": body.kind_config.is_private_target,
            },
        )
        session.add(audit)
        await session.commit()

    return _to_out(t, attached_ids=await _attached_repo_ids(session, t.id))


@router.get(
    "",
    response_model=list[TargetOut],
    dependencies=[Depends(require_scope("targets:read"))],
)
async def list_targets(
    q: str | None = Query(None, description="Substring search on name/base_url"),
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> list[TargetOut]:
    stmt = select(Target).where(Target.workspace_id == workspace.id)
    if q:
        stmt = stmt.where(
            (Target.name.ilike(f"%{q}%")) | (Target.base_url.ilike(f"%{q}%"))
        )
    stmt = stmt.order_by(Target.created_at.desc())
    rows = (await session.execute(stmt)).scalars().all()
    # Single round-trip: pull every join row for the workspace at once,
    # then bucket by target_id. Avoids N+1 on busy workspaces.
    target_ids = [t.id for t in rows]
    attachments: dict[str, list[str]] = {}
    if target_ids:
        join_rows = (await session.execute(
            select(TargetRepository.target_id, TargetRepository.repository_id)
            .where(TargetRepository.target_id.in_(target_ids))
        )).all()
        for tid, rid in join_rows:
            attachments.setdefault(tid, []).append(rid)
    return [_to_out(t, attached_ids=attachments.get(t.id, [])) for t in rows]


@router.post(
    "/llm/model-catalog/preview",
    response_model=LlmModelCatalogOut,
    dependencies=[Depends(require_scope("targets:write"))],
)
async def preview_llm_model_catalog(
    body: LlmModelCatalogRequest,
) -> LlmModelCatalogOut:
    return await fetch_llm_model_catalog(body)


@router.get(
    "/{target_id}",
    response_model=TargetOut,
    dependencies=[Depends(require_scope("targets:read"))],
)
async def get_target(
    target_id: str,
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> TargetOut:
    t = (await session.execute(
        select(Target).where(Target.id == target_id, Target.workspace_id == workspace.id)
    )).scalar_one_or_none()
    if not t:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "target not found")
    return _to_out(t, attached_ids=await _attached_repo_ids(session, t.id))


@router.patch(
    "/{target_id}",
    response_model=TargetOut,
    dependencies=[Depends(require_scope("targets:write"))],
)
async def update_target(
    target_id: str,
    body: TargetUpdate,
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> TargetOut:
    t = (await session.execute(
        select(Target).where(Target.id == target_id, Target.workspace_id == workspace.id)
    )).scalar_one_or_none()
    if not t:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "target not found")
    _reject_if_repo_mirror(t, "edit")

    if body.name is not None:
        t.name = body.name
    if body.base_url is not None:
        t.base_url = str(body.base_url)
    if body.scope is not None:
        t.scope = body.scope
    if body.exclude_paths is not None:
        t.exclude_paths = body.exclude_paths

    if body.clear_credentials:
        t.credentials_encrypted = None
    elif body.credentials is not None:
        t.credentials_encrypted = encrypt_credentials(body.credentials.model_dump())

    # LLM-only: caller may patch the non-secret config (model name,
    # system prompt baseline, request template) without re-uploading
    # credentials. Reject for non-LLM targets to keep the column
    # invariant.
    if body.llm_config is not None:
        if t.kind != "llm":
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                "llm_config is only valid on kind='llm' targets",
            )
        t.llm_config = body.llm_config.model_dump(mode="json")

    # Per-feature-001: kind_config / kind_credentials follow the same
    # omit-vs-clear pattern as credentials. ``None`` leaves unchanged;
    # ``clear_kind_config=True`` nullifies. New value must discriminate
    # to the current target.kind.
    if body.clear_kind_config:
        t.kind_config = None
    elif body.kind_config is not None:
        if body.kind_config.kind != t.kind:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                f"kind_config.kind ({body.kind_config.kind!r}) must match "
                f"target kind ({t.kind!r})",
            )
        if t.kind in {"url", "repo", "llm"}:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                f"kind_config not allowed for legacy kind={t.kind!r}",
            )
        # Sub-project A: host-kind PATCH revalidation. Re-resolve + re-classify
        # every host on every PATCH so adding new private hosts under a
        # still-off org flag is rejected. No retro-invalidation: existing
        # private hosts on a Target created when the flag was ON stay legal
        # even after the flag flips OFF.
        if t.kind == "host":
            from pencheff_api.services.host_validation import classify_host_list
            from pencheff_api.schemas.targets import HostKindConfig
            org: Org = await session.get(Org, workspace.org_id)
            classification = classify_host_list(body.kind_config.hosts)
            if classification.has_errors:
                raise HTTPException(
                    status_code=422,
                    detail={
                        "error": "host_kind_resolution_failed",
                        "message": "One or more hosts could not be resolved.",
                        "errors": classification.error_hosts,
                    },
                )
            if classification.any_private and not org.allow_private_targets:
                raise HTTPException(
                    status_code=422,
                    detail={
                        "error": "host_kind_private_targets_disabled",
                        "message": (
                            "Your org does not permit private-IP host targets. Ask an "
                            "admin to enable allow_private_targets, or remove the "
                            "private hosts."
                        ),
                        "offending_hosts": classification.private_hosts,
                    },
                )
            cfg_dict = body.kind_config.model_dump(mode="json")
            cfg_dict["is_private_target"] = classification.any_private
            t.kind_config = cfg_dict
        else:
            t.kind_config = body.kind_config.model_dump(mode="json")

    if body.clear_kind_credentials:
        t.kind_credentials_encrypted = None
    elif body.kind_credentials is not None:
        if body.kind_credentials.kind != t.kind:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                f"kind_credentials.kind ({body.kind_credentials.kind!r}) "
                f"must match target kind ({t.kind!r})",
            )
        t.kind_credentials_encrypted = encrypt_credentials(
            body.kind_credentials.model_dump()
        )

    if body.attached_repository_ids is not None:
        await _validate_and_replace_attachments(
            session, t, body.attached_repository_ids, workspace_id=workspace.id,
        )

    if body.weekly_digest_emails is not None:
        # Sanitise: trim, drop blanks/non-emails, dedupe, cap at 20.
        seen: set[str] = set()
        clean: list[str] = []
        for raw in body.weekly_digest_emails:
            e = (raw or "").strip()
            if not e or "@" not in e or e in seen:
                continue
            seen.add(e)
            clean.append(e)
        t.weekly_digest_emails = clean[:20] or None

    if body.disciplines is not None:
        # None → omitted (unchanged); [] → clear; non-empty → replace +
        # validate against the current Target.kind. Re-apply discipline
        # defaults to kind_config / llm_config so the safety floor survives.
        new_disc = list(body.disciplines)
        if new_disc:
            for d in new_disc:
                allowed = DISCIPLINE_TO_KINDS.get(d)
                if allowed is None:
                    raise HTTPException(
                        status.HTTP_400_BAD_REQUEST,
                        f"unknown discipline: {d!r}",
                    )
                if t.kind not in allowed:
                    raise HTTPException(
                        status.HTTP_400_BAD_REQUEST,
                        f"discipline={d!r} not compatible with kind={t.kind!r}; "
                        f"allowed kinds: {sorted(allowed)}",
                    )
            # Dedup preserving order.
            seen_d: set[str] = set()
            deduped: list[str] = []
            for d in new_disc:
                if d not in seen_d:
                    seen_d.add(d)
                    deduped.append(d)
            t.disciplines = deduped
            new_kind_cfg, new_llm_cfg = _apply_discipline_defaults(
                deduped, t.kind_config, t.llm_config,
            )
            t.kind_config = new_kind_cfg
            t.llm_config = new_llm_cfg
        else:
            t.disciplines = None

    await session.commit()
    await session.refresh(t)
    await _maybe_link_repo(session, t, workspace)
    # See create_target: a repo-link rollback expires t; reload before _to_out.
    await session.refresh(t)
    return _to_out(t, attached_ids=await _attached_repo_ids(session, t.id))


@router.delete(
    "/{target_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require_scope("targets:write"))],
)
async def delete_target(
    target_id: str,
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> None:
    t = (await session.execute(
        select(Target).where(Target.id == target_id, Target.workspace_id == workspace.id)
    )).scalar_one_or_none()
    if not t:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "target not found")
    _reject_if_repo_mirror(t, "delete")
    await session.delete(t)
    await session.commit()
