from datetime import datetime

from pydantic import BaseModel, Field, model_validator


class OrgCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    # Optional: if provided, the first workspace is created in the same call.
    first_workspace_name: str | None = Field(default=None, max_length=200)


class OrgUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    # Per-feature-001: org-level AI orchestration kill switch. Restricted
    # to owner / admin via the ``require_org_role`` decorator on the route.
    force_deterministic_only: bool | None = None
    # Sub-project A (host-target-kind): controls whether host-kind targets
    # may use private / RFC1918 IP addresses. Enabling requires an explicit
    # disclosure acknowledgement (private_targets_disclosure_ack=True).
    allow_private_targets: bool | None = None
    private_targets_disclosure_ack: bool | None = None
    security_lake_enabled: bool | None = None

    @model_validator(mode="after")
    def _ack_required_to_enable_private(self) -> "OrgUpdate":
        if self.allow_private_targets is True and self.private_targets_disclosure_ack is not True:
            raise ValueError(
                "private_targets_disclosure_ack=True is required to enable "
                "allow_private_targets"
            )
        return self


class OrgOut(BaseModel):
    id: str
    name: str
    plan: str
    role: str  # caller's role in this org
    created_at: datetime
    # Resolved AI access — the dashboard checks this rather than ``plan``
    # alone so the UI respects the operator-level ``AI_FREE_TIER_ENABLED``
    # override (free orgs see AI features when the flag is on).
    ai_enabled: bool = False
    # Per-feature-001: surfaced in admin UI so org owners/admins can see
    # current state and toggle it (writes flow through PATCH /orgs/{id}).
    force_deterministic_only: bool = False
    # Sub-project A (host-target-kind): exposed so the FE can render the
    # toggle's current state without a separate lookup.
    allow_private_targets: bool = False
    # Security Lake: exposed so the FE can render the toggle's current state.
    security_lake_enabled: bool = False
    # SSO enforcement toggle: exposed so the FE can render the toggle's
    # current state for org-settings ("Require SSO" toggle).
    require_sso: bool = False

    model_config = {"from_attributes": True}


class MemberOut(BaseModel):
    user_id: str
    email: str
    name: str | None
    role: str
    created_at: datetime

    model_config = {"from_attributes": True}


class MemberRoleUpdate(BaseModel):
    # Not regex-restricted to a fixed role list: the router validates
    # against auth.permissions.KNOWN_ROLES (400 on unknown), which is the
    # single source of truth for valid roles (RBAC L1).
    role: str = Field(min_length=1, max_length=32)


class InviteCreate(BaseModel):
    email: str = Field(min_length=3, max_length=320)
    role: str = Field(default="member", min_length=1, max_length=32)


class InviteOut(BaseModel):
    id: str
    email: str
    role: str
    invited_by_user_id: str | None
    expires_at: datetime
    accepted_at: datetime | None
    created_at: datetime
    # Raw token exposed only on the POST response so the caller can build
    # the invite URL; never returned on subsequent lookups.
    token: str | None = None

    model_config = {"from_attributes": True}
