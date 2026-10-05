from __future__ import annotations

import time
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth.deps import get_active_workspace, require_permission
from ..db.base import get_session
from ..db.models import AuditLog, LlmProvider, Org, User
from ..schemas.llm_providers import LlmProviderCreate, LlmProviderOut, LlmProviderUpdate
from ..services.credentials import encrypt_credentials, decrypt_credentials
from ..services.llm_providers.catalog import MODEL_CATALOG, PROVIDER_KINDS
from ..services.llm_providers.factory import build_client
from ..services.llm_providers.base import ChatMessage

router = APIRouter(prefix="/llm-providers", tags=["llm-providers"])


def _encrypt_creds(body) -> bytes | None:
    if getattr(body, "credentials", None):
        return encrypt_credentials(body.credentials)
    if getattr(body, "api_key", None):
        return encrypt_credentials({"api_key": body.api_key})
    return None


def _key_hint(blob: bytes | None) -> tuple[bool, str | None]:
    creds = decrypt_credentials(blob) if blob else None
    key = (creds or {}).get("api_key") if creds else None
    if not key:
        return False, None
    return True, "…" + key[-4:]


def _to_out(p: LlmProvider, *, active_id: str | None) -> LlmProviderOut:
    key_set, hint = _key_hint(p.api_key_encrypted)
    return LlmProviderOut(
        id=p.id, label=p.label, provider=p.provider, model=p.model,
        base_url=p.base_url, azure_deployment=p.azure_deployment,
        azure_api_version=p.azure_api_version, extra=p.extra,
        key_set=key_set, key_hint=hint, is_active=(p.id == active_id),
        created_at=p.created_at,
    )


def _audit(session: AsyncSession, *, user: User, org_id: str, action: str,
           request: Request, meta: dict) -> None:
    session.add(AuditLog(
        user_id=user.id, org_id=org_id, action=action,
        entity_type="llm_provider", entity_id=meta.get("id"),
        request_ip=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"), meta=meta,
    ))


async def _load(session: AsyncSession, provider_id: str, org_id: str) -> LlmProvider:
    p = await session.get(LlmProvider, provider_id)
    if p is None or p.org_id != org_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "provider not found")
    return p


@router.get("/catalog")
async def get_catalog() -> dict:
    return {"kinds": list(PROVIDER_KINDS), "models": MODEL_CATALOG}


@router.get("", response_model=list[LlmProviderOut])
async def list_providers(
    workspace=Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> list[LlmProviderOut]:
    org = await session.get(Org, workspace.org_id)
    rows = (await session.execute(
        select(LlmProvider).where(LlmProvider.org_id == workspace.org_id)
        .order_by(LlmProvider.created_at)
    )).scalars().all()
    active = org.active_llm_provider_id if org else None
    return [_to_out(p, active_id=active) for p in rows]


@router.post("", response_model=LlmProviderOut, status_code=status.HTTP_201_CREATED)
async def create_provider(
    body: LlmProviderCreate,
    request: Request,
    ctx: tuple[User, ...] = Depends(require_permission("llm_provider:manage")),
    session: AsyncSession = Depends(get_session),
    workspace=Depends(get_active_workspace),
) -> LlmProviderOut:
    user, _ctx_ws = ctx
    p = LlmProvider(
        id=str(uuid.uuid4()), org_id=workspace.org_id, label=body.label,
        provider=body.provider, model=body.model, base_url=body.base_url,
        api_key_encrypted=_encrypt_creds(body),
        azure_deployment=body.azure_deployment, azure_api_version=body.azure_api_version,
        extra=body.extra, created_by=user.id,
        created_at=datetime.now(timezone.utc),
    )
    session.add(p)
    _audit(session, user=user, org_id=workspace.org_id, action="org.llm_provider.created",
           request=request, meta={"id": p.id, "provider": p.provider, "label": p.label})
    await session.commit()
    org = await session.get(Org, workspace.org_id)
    return _to_out(p, active_id=org.active_llm_provider_id if org else None)


@router.patch("/{provider_id}", response_model=LlmProviderOut)
async def update_provider(
    provider_id: str,
    body: LlmProviderUpdate,
    request: Request,
    ctx: tuple[User, ...] = Depends(require_permission("llm_provider:manage")),
    session: AsyncSession = Depends(get_session),
    workspace=Depends(get_active_workspace),
) -> LlmProviderOut:
    user, _ctx_ws = ctx
    p = await _load(session, provider_id, workspace.org_id)
    if body.label is not None: p.label = body.label
    if body.provider is not None: p.provider = body.provider
    if body.model is not None: p.model = body.model
    if body.base_url is not None: p.base_url = body.base_url
    if body.azure_deployment is not None: p.azure_deployment = body.azure_deployment
    if body.azure_api_version is not None: p.azure_api_version = body.azure_api_version
    if body.extra is not None: p.extra = body.extra
    if body.api_key is not None:
        p.api_key_encrypted = (
            encrypt_credentials({"api_key": body.api_key}) if body.api_key else None
        )
    if getattr(body, "credentials", None):
        p.api_key_encrypted = encrypt_credentials(body.credentials)
    _audit(session, user=user, org_id=workspace.org_id, action="org.llm_provider.updated",
           request=request, meta={"id": p.id})
    await session.commit()
    org = await session.get(Org, workspace.org_id)
    return _to_out(p, active_id=org.active_llm_provider_id if org else None)


@router.delete("/{provider_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_provider(
    provider_id: str,
    request: Request,
    ctx: tuple[User, ...] = Depends(require_permission("llm_provider:manage")),
    session: AsyncSession = Depends(get_session),
    workspace=Depends(get_active_workspace),
) -> None:
    user, _ctx_ws = ctx
    p = await _load(session, provider_id, workspace.org_id)
    org = await session.get(Org, workspace.org_id)
    if org and org.active_llm_provider_id == p.id:
        org.active_llm_provider_id = None
    await session.delete(p)
    _audit(session, user=user, org_id=workspace.org_id, action="org.llm_provider.deleted",
           request=request, meta={"id": provider_id})
    await session.commit()


@router.post("/{provider_id}/activate", response_model=LlmProviderOut)
async def activate_provider(
    provider_id: str,
    request: Request,
    ctx: tuple[User, ...] = Depends(require_permission("llm_provider:manage")),
    session: AsyncSession = Depends(get_session),
    workspace=Depends(get_active_workspace),
) -> LlmProviderOut:
    user, _ctx_ws = ctx
    p = await _load(session, provider_id, workspace.org_id)
    org = await session.get(Org, workspace.org_id)
    if org is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "org not found")
    org.active_llm_provider_id = p.id
    _audit(session, user=user, org_id=workspace.org_id, action="org.llm_provider.activated",
           request=request, meta={"id": p.id})
    await session.commit()
    return _to_out(p, active_id=p.id)


@router.post("/deactivate", status_code=status.HTTP_204_NO_CONTENT)
async def deactivate_provider(
    request: Request,
    ctx: tuple[User, ...] = Depends(require_permission("llm_provider:manage")),
    session: AsyncSession = Depends(get_session),
    workspace=Depends(get_active_workspace),
) -> None:
    user, _ctx_ws = ctx
    org = await session.get(Org, workspace.org_id)
    if org is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "org not found")
    org.active_llm_provider_id = None
    _audit(session, user=user, org_id=workspace.org_id, action="org.llm_provider.deactivated",
           request=request, meta={})
    await session.commit()


@router.post("/{provider_id}/test")
async def test_provider(
    provider_id: str,
    ctx: tuple[User, ...] = Depends(require_permission("llm_provider:manage")),
    session: AsyncSession = Depends(get_session),
    workspace=Depends(get_active_workspace),
) -> dict:
    p = await _load(session, provider_id, workspace.org_id)
    client = build_client(p)
    start = time.monotonic()
    try:
        res = await client.chat([ChatMessage("user", "Reply with the word ok.")],
                                max_tokens=8, timeout=20.0)
    except Exception as exc:  # noqa: BLE001 — surfaced to the UI, not raised
        return {"ok": False, "latency_ms": int((time.monotonic() - start) * 1000),
                "error": str(exc)[:300], "model": p.model}
    return {"ok": True, "latency_ms": int((time.monotonic() - start) * 1000),
            "error": None, "model": p.model, "sample": (res.text or "")[:80]}
