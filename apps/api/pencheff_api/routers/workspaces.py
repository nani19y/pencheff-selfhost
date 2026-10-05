"""Workspace read-only endpoints for the community edition.

CE has exactly one fixed workspace (seeded at startup). Mutation routes
(create/update/delete) are removed — the single workspace is immutable.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth.deps import get_current_user, get_membership
from ..auth.single_tenant import seed_ids
from ..db.base import get_session
from ..db.models import OrgMember, User, Workspace
from ..schemas.workspaces import (
    WorkspaceMemberOut,
    WorkspaceOut,
)

router = APIRouter(prefix="/workspaces", tags=["workspaces"])


def _to_out(w: Workspace) -> WorkspaceOut:
    return WorkspaceOut(
        id=w.id, org_id=w.org_id, name=w.name, slug=w.slug,
        created_at=w.created_at,
        weekly_digest_emails=w.weekly_digest_emails,
    )


@router.get("", response_model=list[WorkspaceOut])
async def list_workspaces(
    org_id: str | None = None,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> list[WorkspaceOut]:
    ids = await seed_ids(session)
    ws = await session.get(Workspace, ids["workspace_id"])
    return [_to_out(ws)]


@router.get("/{workspace_id}", response_model=WorkspaceOut)
async def get_workspace(
    workspace_id: str,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> WorkspaceOut:
    ws = await session.get(Workspace, workspace_id)
    if ws is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "workspace not found")
    member = await get_membership(session, user.id, ws.org_id)
    if member is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "workspace not found")
    return _to_out(ws)


@router.get("/{workspace_id}/members", response_model=list[WorkspaceMemberOut])
async def list_workspace_members(
    workspace_id: str,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> list[WorkspaceMemberOut]:
    """List org members visible to the active user. Powers the
    recipient-picker dropdown for commission-email and digest UIs.

    Workspaces inherit membership from their parent Org — we expose
    every OrgMember of the workspace's org as a candidate recipient.
    """
    ws = await session.get(Workspace, workspace_id)
    if ws is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "workspace not found")
    member = await get_membership(session, user.id, ws.org_id)
    if member is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "workspace not found")
    rows = (
        await session.execute(
            select(OrgMember, User)
            .join(User, User.id == OrgMember.user_id)
            .where(OrgMember.org_id == ws.org_id)
            .order_by(User.email.asc())
        )
    ).all()
    return [
        WorkspaceMemberOut(
            user_id=str(u.id), email=u.email,
            name=getattr(u, "name", None),
            role=om.role,
        )
        for (om, u) in rows
    ]


