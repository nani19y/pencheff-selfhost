from __future__ import annotations

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import get_settings
from ..db.base import get_session
from ..db.models import Org, OrgMember, User, Workspace
from .keycloak import authenticate_request
from .permissions import permissions_for_claims
from .single_tenant import seed_ids


ONBOARDING_REQUIRED = "ONBOARDING_REQUIRED"


async def get_current_user(
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> User:
    """Authenticate through OIDC when enabled; retain CE single-tenant mode otherwise."""
    settings = get_settings()
    if not settings.oidc_enabled:
        request.state.auth_kind = "session"
        ids = await seed_ids(session)
        request.state.user_id = ids["user_id"]
        request.state.org_id = ids["org_id"]
        request.state.api_key_id = None
        return await session.get(User, ids["user_id"])

    claims = await authenticate_request(request)
    subject = str(claims["sub"])
    email = str(claims.get("email") or f"{subject}@oidc.local").lower()
    name = claims.get("name") or claims.get("preferred_username") or email

    user = (await session.execute(select(User).where(User.google_sub == subject))).scalar_one_or_none()
    if user is None:
        user = (await session.execute(select(User).where(User.email == email))).scalar_one_or_none()

    # OIDC authentication identifies the person; Pencheff membership determines
    # which tenant they can access. New users are provisioned into the first
    # organization only when explicitly enabled by the deployment policy.
    if user is None:
        org = (await session.execute(select(Org).order_by(Org.created_at.asc()).limit(1))).scalar_one_or_none()
        if org is None:
            raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "No Pencheff organization is configured.")
        user = User(id=subject if len(subject) == 36 else None, email=email, name=str(name), org_id=org.id, is_active=True)
        # UUID PKs cannot safely use arbitrary OIDC subjects; let SQLAlchemy
        # generate a UUID and store the immutable OIDC subject in google_sub.
        user.google_sub = subject
        session.add(user)
        await session.flush()
        session.add(OrgMember(org_id=org.id, user_id=user.id, role="member"))
        await session.commit()
        await session.refresh(user)

    if not user.is_active:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "User account is disabled.")

    request.state.auth_kind = "oidc"
    request.state.user_id = user.id
    request.state.org_id = user.org_id
    request.state.oidc_claims = claims
    request.state.oidc_permissions = permissions_for_claims(claims)
    request.state.api_key_id = None
    return user


async def get_active_workspace(
    request: Request,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> Workspace:
    settings = get_settings()
    requested = request.headers.get("X-Workspace-Id")
    if settings.oidc_enabled:
        stmt = select(Workspace).join(
            OrgMember, OrgMember.org_id == Workspace.org_id
        ).where(
            Workspace.id == requested if requested else Workspace.org_id == user.org_id,
            OrgMember.user_id == user.id,
        ).order_by(Workspace.created_at.asc())
        workspace = (await session.execute(stmt)).scalars().first()
        if workspace is None:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "You are not a member of this workspace.")
        request.state.workspace_id = workspace.id
        return workspace

    ids = await seed_ids(session)
    request.state.workspace_id = ids["workspace_id"]
    return await session.get(Workspace, ids["workspace_id"])


async def get_membership(session: AsyncSession, user_id: str, org_id: str) -> OrgMember | None:
    return (await session.execute(
        select(OrgMember).where(OrgMember.org_id == org_id, OrgMember.user_id == user_id)
    )).scalar_one_or_none()


def require_role(*allowed: str):
    async def _dep(
        user: User = Depends(get_current_user),
        workspace: Workspace = Depends(get_active_workspace),
        session: AsyncSession = Depends(get_session),
    ):
        settings = get_settings()
        if settings.oidc_enabled:
            member = await get_membership(session, user.id, workspace.org_id)
            if member is None or member.role not in allowed:
                raise HTTPException(status.HTTP_403_FORBIDDEN, "Insufficient organization role.")
        return user, workspace
    return _dep


def require_org_role(*allowed: str):
    async def _dep(
        org_id: str,
        user: User = Depends(get_current_user),
        session: AsyncSession = Depends(get_session),
    ):
        member = await get_membership(session, user.id, org_id)
        if member is None or (allowed and member.role not in allowed):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Insufficient organization role.")
        return user, member
    return _dep


def require_scope(scope: str):
    """Map legacy route scopes to the explicit permission vocabulary."""
    return require_permission(scope)


def require_permission(perm: str):
    async def _dep(
        request: Request,
        user: User = Depends(get_current_user),
        workspace: Workspace = Depends(get_active_workspace),
    ):
        settings = get_settings()
        if settings.oidc_enabled:
            permissions = getattr(request.state, "oidc_permissions", set())
            if perm not in permissions:
                raise HTTPException(
                    status.HTTP_403_FORBIDDEN,
                    f"Missing required permission: {perm}",
                )
        return user, workspace
    return _dep


async def session_only(
    request: Request,
    user: User = Depends(get_current_user),
) -> User:
    return user
