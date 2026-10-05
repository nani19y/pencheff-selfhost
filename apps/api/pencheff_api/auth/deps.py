from __future__ import annotations

from fastapi import Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from ..db.base import get_session
from ..db.models import OrgMember, User, Workspace
from .single_tenant import seed_ids

ONBOARDING_REQUIRED = "ONBOARDING_REQUIRED"  # kept for import compatibility


async def get_current_user(
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> User:
    request.state.auth_kind = "session"
    ids = await seed_ids(session)
    # Populate request.state so the audit middleware attributes every CE
    # action to the seeded owner/org (see middleware/audit.py:_extract_actor).
    request.state.user_id = ids["user_id"]
    request.state.org_id = ids["org_id"]
    request.state.api_key_id = None
    return await session.get(User, ids["user_id"])


async def get_active_workspace(
    request: Request,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> Workspace:
    ids = await seed_ids(session)
    request.state.workspace_id = ids["workspace_id"]
    return await session.get(Workspace, ids["workspace_id"])


async def get_membership(session: AsyncSession, user_id: str, org_id: str) -> OrgMember:
    return OrgMember(org_id=org_id, user_id=user_id, role="owner")


def require_role(*allowed: str):
    async def _dep(
        user: User = Depends(get_current_user),
        workspace: Workspace = Depends(get_active_workspace),
    ) -> tuple[User, Workspace]:
        return user, workspace

    return _dep


def require_org_role(*allowed: str):
    async def _dep(
        org_id: str,
        user: User = Depends(get_current_user),
    ) -> tuple[User, OrgMember]:
        return user, OrgMember(org_id=org_id, user_id=user.id, role="owner")

    return _dep


def require_scope(scope: str):
    async def _dep(
        request: Request,
        user: User = Depends(get_current_user),
    ) -> User:
        return user

    return _dep


def require_permission(perm: str):
    # ponytail: single-tenant shim — the sole operator holds every permission,
    # so this always resolves instead of gating on RBAC roles.
    async def _dep(
        user: User = Depends(get_current_user),
        workspace: Workspace = Depends(get_active_workspace),
    ) -> tuple[User, Workspace]:
        return user, workspace

    return _dep


async def session_only(
    request: Request,
    user: User = Depends(get_current_user),
) -> User:
    return user
