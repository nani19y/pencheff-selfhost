"""External integration CRUD — Slack, Teams, Google Chat, Discord, PagerDuty, Splunk, Opsgenie, Jira, generic webhook."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth.deps import get_active_workspace, require_scope
from ..db.base import get_session
from ..db.models import Integration, Workspace
from ..services.credentials import decrypt_credentials, encrypt_credentials

router = APIRouter(prefix="/integrations", tags=["integrations"])

IntegrationKind = Literal[
    "slack", "teams", "google_chat", "discord",
    "pagerduty", "splunk", "opsgenie",
    "jira", "webhook",
]

IntegrationEvent = Literal[
    "scan_started", "scan_done", "scan_failed",
    "finding_new", "finding_changed",
]
ALL_EVENTS: list[str] = [
    "scan_started", "scan_done", "scan_failed",
    "finding_new", "finding_changed",
]


class IntegrationCreate(BaseModel):
    kind: IntegrationKind
    name: str
    config: dict[str, Any]
    severity_filter: str = "high"
    enabled: bool = True
    # Empty list (or omitted) → fires for every target in the workspace.
    target_ids: list[str] | None = None
    # Empty list (or omitted) → fires on every lifecycle event.
    events: list[IntegrationEvent] | None = None


class IntegrationUpdate(BaseModel):
    name: str | None = None
    config: dict[str, Any] | None = None
    severity_filter: str | None = None
    enabled: bool | None = None
    target_ids: list[str] | None = None
    events: list[IntegrationEvent] | None = None


class IntegrationOut(BaseModel):
    id: str
    kind: str
    name: str
    severity_filter: str
    enabled: bool
    target_ids: list[str] | None = None
    events: list[str] | None = None
    created_at: datetime


def _out(i: Integration) -> IntegrationOut:
    return IntegrationOut(
        id=i.id, kind=i.kind, name=i.name,
        severity_filter=i.severity_filter, enabled=i.enabled,
        target_ids=i.target_ids, events=i.events,
        created_at=i.created_at,
    )


@router.post(
    "",
    response_model=IntegrationOut,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_scope("integrations:write"))],
)
async def create_integration(
    body: IntegrationCreate,
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> IntegrationOut:
    # Empty list from the UI means "all" — store NULL so the matcher can
    # use a single ``IS NULL OR <id> = ANY(...)`` predicate.
    target_ids = body.target_ids or None
    events = list(body.events) if body.events else None
    i = Integration(
        org_id=workspace.org_id, workspace_id=workspace.id, kind=body.kind, name=body.name,
        config_encrypted=encrypt_credentials({"config": json.dumps(body.config)}),
        severity_filter=body.severity_filter, enabled=body.enabled,
        target_ids=target_ids, events=events,
    )
    session.add(i)
    await session.commit()
    await session.refresh(i)
    return _out(i)


@router.get(
    "",
    response_model=list[IntegrationOut],
    dependencies=[Depends(require_scope("integrations:read"))],
)
async def list_integrations(
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> list[IntegrationOut]:
    rows = (await session.execute(
        select(Integration).where(Integration.workspace_id == workspace.id)
        .order_by(Integration.created_at.desc())
    )).scalars().all()
    return [_out(i) for i in rows]


@router.patch(
    "/{integration_id}",
    response_model=IntegrationOut,
    dependencies=[Depends(require_scope("integrations:write"))],
)
async def update_integration(
    integration_id: str,
    body: IntegrationUpdate,
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> IntegrationOut:
    i = (await session.execute(
        select(Integration).where(
            Integration.id == integration_id, Integration.workspace_id == workspace.id
        )
    )).scalar_one_or_none()
    if not i:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "integration not found")
    data = body.model_dump(exclude_unset=True)
    if "config" in data and data["config"] is not None:
        i.config_encrypted = encrypt_credentials({"config": json.dumps(data.pop("config"))})
    # Empty list ⇒ NULL ("all"); preserves the matcher's single-predicate form.
    if "target_ids" in data and not data["target_ids"]:
        data["target_ids"] = None
    if "events" in data and not data["events"]:
        data["events"] = None
    for k, v in data.items():
        setattr(i, k, v)
    await session.commit()
    await session.refresh(i)
    return _out(i)


@router.delete(
    "/{integration_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require_scope("integrations:write"))],
)
async def delete_integration(
    integration_id: str,
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> None:
    i = (await session.execute(
        select(Integration).where(
            Integration.id == integration_id, Integration.workspace_id == workspace.id
        )
    )).scalar_one_or_none()
    if not i:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "integration not found")
    await session.delete(i)
    await session.commit()


@router.post(
    "/{integration_id}/test",
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(require_scope("integrations:write"))],
)
async def test_integration(
    integration_id: str,
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    """Send a dummy findings batch through the integration to confirm connectivity."""
    i = (await session.execute(
        select(Integration).where(
            Integration.id == integration_id, Integration.workspace_id == workspace.id
        )
    )).scalar_one_or_none()
    if not i:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "integration not found")
    config = json.loads((decrypt_credentials(i.config_encrypted) or {}).get("config", "{}"))
    from ..services.integration_dispatch import dispatch_test
    return await dispatch_test(i.kind, config)
