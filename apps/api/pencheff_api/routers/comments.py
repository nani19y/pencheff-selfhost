"""Finding comments + assignment + tags — collaboration endpoints."""

from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth.deps import get_active_workspace, get_current_user, require_scope
from ..db.base import get_session
from ..db.models import Finding, FindingAssignment, FindingComment, FindingTag, Scan, User, Workspace

router = APIRouter(prefix="/findings/{finding_id}", tags=["findings"])


async def _check_access(
    finding_id: str, workspace: Workspace, session: AsyncSession
) -> Finding:
    f = (await session.execute(
        select(Finding).join(Scan, Finding.scan_id == Scan.id)
        .where(Finding.id == finding_id, Scan.workspace_id == workspace.id)
    )).scalar_one_or_none()
    if not f:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "finding not found")
    return f


class CommentCreate(BaseModel):
    body: str


class CommentOut(BaseModel):
    id: str
    user_id: str
    body: str
    created_at: datetime


@router.post(
    "/comments",
    response_model=CommentOut,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_scope("comments:write"))],
)
async def add_comment(
    finding_id: str,
    body: CommentCreate,
    user: User = Depends(get_current_user),
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> CommentOut:
    await _check_access(finding_id, workspace, session)
    c = FindingComment(finding_id=finding_id, user_id=user.id, body=body.body)
    session.add(c)
    await session.commit()
    await session.refresh(c)
    return CommentOut(id=c.id, user_id=c.user_id, body=c.body, created_at=c.created_at)


@router.get(
    "/comments",
    response_model=list[CommentOut],
    dependencies=[Depends(require_scope("comments:read"))],
)
async def list_comments(
    finding_id: str,
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> list[CommentOut]:
    await _check_access(finding_id, workspace, session)
    rows = (await session.execute(
        select(FindingComment).where(FindingComment.finding_id == finding_id)
        .order_by(FindingComment.created_at)
    )).scalars().all()
    return [CommentOut(id=c.id, user_id=c.user_id, body=c.body, created_at=c.created_at)
            for c in rows]


class AssignBody(BaseModel):
    assignee_user_id: str


@router.post(
    "/assign",
    dependencies=[Depends(require_scope("comments:write"))],
)
async def assign_finding(
    finding_id: str,
    body: AssignBody,
    user: User = Depends(get_current_user),
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> dict[str, str]:
    await _check_access(finding_id, workspace, session)
    # Upsert
    existing = (await session.execute(
        select(FindingAssignment).where(FindingAssignment.finding_id == finding_id)
    )).scalar_one_or_none()
    if existing:
        existing.assignee_user_id = body.assignee_user_id
        existing.assigner_user_id = user.id
    else:
        session.add(FindingAssignment(
            finding_id=finding_id, assignee_user_id=body.assignee_user_id,
            assigner_user_id=user.id,
        ))
    await session.commit()
    return {"finding_id": finding_id, "assignee_user_id": body.assignee_user_id}


class TagBody(BaseModel):
    tag: str


@router.post(
    "/tags",
    dependencies=[Depends(require_scope("comments:write"))],
)
async def add_tag(
    finding_id: str, body: TagBody,
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> dict[str, str]:
    await _check_access(finding_id, workspace, session)
    existing = (await session.execute(
        select(FindingTag).where(
            FindingTag.finding_id == finding_id, FindingTag.tag == body.tag
        )
    )).scalar_one_or_none()
    if not existing:
        session.add(FindingTag(finding_id=finding_id, tag=body.tag))
        await session.commit()
    return {"finding_id": finding_id, "tag": body.tag}


@router.delete(
    "/tags/{tag}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require_scope("comments:write"))],
)
async def remove_tag(
    finding_id: str, tag: str,
    workspace: Workspace = Depends(get_active_workspace),
    session: AsyncSession = Depends(get_session),
) -> None:
    await _check_access(finding_id, workspace, session)
    existing = (await session.execute(
        select(FindingTag).where(
            FindingTag.finding_id == finding_id, FindingTag.tag == tag
        )
    )).scalar_one_or_none()
    if existing:
        await session.delete(existing)
        await session.commit()
