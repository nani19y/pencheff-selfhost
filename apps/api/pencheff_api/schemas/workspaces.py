from datetime import datetime

from pydantic import BaseModel, Field


class WorkspaceCreate(BaseModel):
    org_id: str
    name: str = Field(min_length=1, max_length=200)


class WorkspaceUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    # Recipient list for the workspace-rollup weekly digest. Pass an
    # empty list to disable. Omit to leave unchanged.
    weekly_digest_emails: list[str] | None = None


class WorkspaceOut(BaseModel):
    id: str
    org_id: str
    name: str
    slug: str
    created_at: datetime
    weekly_digest_emails: list[str] | None = None

    model_config = {"from_attributes": True}


class WorkspaceMemberOut(BaseModel):
    user_id: str
    email: str
    name: str | None = None
    role: str
