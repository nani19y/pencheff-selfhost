"""Engagement notes — markdown blobs pinned to findings, requests, assets, or general."""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import desc, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth.deps import get_active_workspace, get_current_user, require_scope
from ..db.base import get_session
from ..db.models import Engagement, EngagementNote, User, Workspace

router = APIRouter(prefix="/engagements/{engagement_id}/notes", tags=["notes"])


class NoteCreate(BaseModel):
    body_md: str
    kind: str = "general"
    target_kind: str | None = None
    target_id: str | None = None
    pinned: bool = False


class NotePatch(BaseModel):
    body_md: str | None = None
    pinned: bool | None = None


class NoteOut(BaseModel):
    id: str
    kind: str
    target_kind: str | None
    target_id: str | None
    body_md: str
    pinned: bool
    created_at: datetime
    updated_at: datetime


def _to_out(n: EngagementNote) -> NoteOut:
    return NoteOut(
        id=n.id, kind=n.kind, target_kind=n.target_kind, target_id=n.target_id,
        body_md=n.body_md, pinned=n.pinned,
        created_at=n.created_at, updated_at=n.updated_at,
    )


async def _engagement(eid: str, ws: Workspace, s: AsyncSession) -> Engagement:
    e = await s.get(Engagement, eid)
    if e is None or e.workspace_id != ws.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "engagement not found")
    return e


@router.post(
    "",
    response_model=NoteOut,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_scope("notes:write"))],
)
async def create_note(
    engagement_id: str,
    body: NoteCreate,
    user: User = Depends(get_current_user),
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> NoteOut:
    e = await _engagement(engagement_id, workspace, session)
    n = EngagementNote(
        engagement_id=e.id, body_md=body.body_md, kind=body.kind,
        target_kind=body.target_kind, target_id=body.target_id,
        pinned=body.pinned, created_by_user_id=user.id,
    )
    session.add(n)
    await session.commit()
    await session.refresh(n)
    return _to_out(n)


@router.get(
    "",
    response_model=list[NoteOut],
    dependencies=[Depends(require_scope("notes:read"))],
)
async def list_notes(
    engagement_id: str,
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
    kind: str | None = None,
    target_id: str | None = None,
    limit: int = 200,
) -> list[NoteOut]:
    e = await _engagement(engagement_id, workspace, session)
    q = select(EngagementNote).where(EngagementNote.engagement_id == e.id)
    if kind:
        q = q.where(EngagementNote.kind == kind)
    if target_id:
        q = q.where(EngagementNote.target_id == target_id)
    q = q.order_by(desc(EngagementNote.pinned), desc(EngagementNote.updated_at)).limit(limit)
    rows = (await session.execute(q)).scalars().all()
    return [_to_out(n) for n in rows]


@router.get(
    "/search",
    response_model=list[NoteOut],
    dependencies=[Depends(require_scope("notes:read"))],
)
async def search_notes(
    engagement_id: str,
    q: str,
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
    limit: int = Query(default=50, le=200),
) -> list[NoteOut]:
    e = await _engagement(engagement_id, workspace, session)
    if not q.strip():
        return []
    stmt = (
        select(EngagementNote)
        .where(EngagementNote.engagement_id == e.id)
        .where(text("fts_doc @@ plainto_tsquery('simple', :qq)"))
        .order_by(desc(text("ts_rank(fts_doc, plainto_tsquery('simple', :qq))")))
        .limit(limit)
    )
    rows = (await session.execute(stmt, {"qq": q})).scalars().all()
    return [_to_out(n) for n in rows]


@router.patch(
    "/{note_id}",
    response_model=NoteOut,
    dependencies=[Depends(require_scope("notes:write"))],
)
async def patch_note(
    engagement_id: str,
    note_id: str,
    body: NotePatch,
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> NoteOut:
    await _engagement(engagement_id, workspace, session)
    n = await session.get(EngagementNote, note_id)
    if n is None or n.engagement_id != engagement_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "note not found")
    if body.body_md is not None:
        n.body_md = body.body_md
    if body.pinned is not None:
        n.pinned = body.pinned
    n.updated_at = datetime.now(timezone.utc)
    await session.commit()
    await session.refresh(n)
    return _to_out(n)


@router.delete(
    "/{note_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require_scope("notes:write"))],
)
async def delete_note(
    engagement_id: str,
    note_id: str,
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> None:
    await _engagement(engagement_id, workspace, session)
    n = await session.get(EngagementNote, note_id)
    if n is None or n.engagement_id != engagement_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "note not found")
    await session.delete(n)
    await session.commit()
