"""OIDC authentication and authorization introspection endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth.deps import get_current_user
from ..auth.permissions import catalog_payload, permissions_for_claims
from ..db.base import get_session
from ..db.models import User

router = APIRouter(prefix="/auth", tags=["authentication"])


@router.get("/config")
async def auth_config() -> dict:
    from ..config import get_settings
    s = get_settings()
    return {
        "enabled": s.oidc_enabled,
        "issuer": s.oidc_issuer,
        "client_id": s.oidc_client_id,
        "audience": s.oidc_audience,
    }


@router.get("/me")
async def me(
    request: Request,
    user: User = Depends(get_current_user),
) -> dict:
    claims = getattr(request.state, "oidc_claims", {})
    permissions = sorted(permissions_for_claims(claims))
    return {
        "id": user.id,
        "email": user.email,
        "name": user.name,
        "org_id": user.org_id,
        "authenticated": True,
        "groups": list(claims.get("groups") or []),
        "roles": sorted(_roles_from_claims(claims)),
        "permissions": permissions,
    }


@router.get("/permissions/catalog")
async def permission_catalog(
    request: Request,
    user: User = Depends(get_current_user),
) -> dict:
    """Permission catalog visible to authenticated operators.

    The endpoint itself requires authentication; authorization administrators
    can use it to see exactly what each capability means before assigning
    roles/groups in the IDP.
    """
    claims = getattr(request.state, "oidc_claims", {})
    permissions = permissions_for_claims(claims)
    return {
        "permissions": catalog_payload(),
        "effective_permissions": sorted(permissions),
    }


@router.get("/permissions/check")
async def permission_check(
    permission: str,
    request: Request,
    user: User = Depends(get_current_user),
) -> dict:
    claims = getattr(request.state, "oidc_claims", {})
    permissions = permissions_for_claims(claims)
    return {
        "permission": permission,
        "allowed": permission in permissions,
    }


def _roles_from_claims(claims: dict) -> set[str]:
    roles: set[str] = set()
    realm = claims.get("realm_access") or {}
    if isinstance(realm, dict):
        roles.update(str(x) for x in realm.get("roles") or [])
    resources = claims.get("resource_access") or {}
    if isinstance(resources, dict):
        for value in resources.values():
            if isinstance(value, dict):
                roles.update(str(x) for x in value.get("roles") or [])
    return roles
