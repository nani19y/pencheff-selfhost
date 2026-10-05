# apps/api/pencheff_api/auth/single_tenant.py
"""Seed and resolve the one implicit tenant for the community edition.

The CE has no login. Exactly one Org + Workspace + User exist; every request
resolves to them. This module owns creating those rows (idempotently) and
caching their IDs for the auth dependencies in ``auth/deps.py``.
"""
from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db.models import Org, OrgMember, User, Workspace

DEFAULT_ORG_NAME = "Pencheff"
DEFAULT_WORKSPACE_NAME = "Default"
DEFAULT_WORKSPACE_SLUG = "default"
DEFAULT_USER_EMAIL = "owner@pencheff.local"
DEFAULT_USER_NAME = "Owner"

_seed_ids: dict[str, str] = {}


async def _first(session: AsyncSession, stmt):
    return (await session.execute(stmt)).scalars().first()


async def ensure_single_tenant(session: AsyncSession) -> dict[str, str]:
    """Idempotently ensure the single tenant exists; cache and return its IDs."""
    org = await _first(session, select(Org).limit(1))
    if org is None:
        org = Org(id=str(uuid.uuid4()), name=DEFAULT_ORG_NAME, plan="self_hosted")
        session.add(org)
        await session.commit()
        await session.refresh(org)

    user = await _first(
        session, select(User).where(User.email == DEFAULT_USER_EMAIL).limit(1)
    )
    if user is None:
        user = User(
            id=str(uuid.uuid4()),
            email=DEFAULT_USER_EMAIL, name=DEFAULT_USER_NAME, org_id=org.id, is_active=True
        )
        session.add(user)
        await session.commit()
        await session.refresh(user)
        session.add(OrgMember(org_id=org.id, user_id=user.id, role="owner"))
        await session.commit()

    ws = await _first(
        session, select(Workspace).where(Workspace.org_id == org.id).limit(1)
    )
    if ws is None:
        ws = Workspace(
            id=str(uuid.uuid4()),
            org_id=org.id,
            name=DEFAULT_WORKSPACE_NAME,
            slug=DEFAULT_WORKSPACE_SLUG,
            created_by_user_id=user.id,
        )
        session.add(ws)
        await session.commit()
        await session.refresh(ws)

    _seed_ids.update(org_id=org.id, user_id=user.id, workspace_id=ws.id)
    return _seed_ids


async def seed_ids(session: AsyncSession) -> dict[str, str]:
    """Return cached seed IDs, seeding on first use."""
    if not _seed_ids:
        await ensure_single_tenant(session)
    return _seed_ids
