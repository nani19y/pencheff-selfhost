import uuid
from datetime import datetime

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    Column,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import ARRAY, INET, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base


def _uuid() -> str:
    return str(uuid.uuid4())


class Org(Base):
    __tablename__ = "orgs"
    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    plan: Mapped[str] = mapped_column(String(32), nullable=False, default="free")
    stripe_customer_id: Mapped[str | None] = mapped_column(String(64))
    # Counter for combined deterministic+autonomous scans consumed by free
    # plan orgs. Used by services/dispatch_mode.py to decide when a free
    # plan org should be downgraded to the autonomous-only path.
    option_3_scans_used: Mapped[int] = mapped_column(
        Integer, nullable=False, server_default="0", default=0
    )
    # Org-level kill switch for AI orchestration (feature 001). When true,
    # services/dispatch_mode.resolve_dispatch_mode short-circuits to
    # ``deterministic_only`` regardless of plan / quota / beta override. Toggled
    # by admin/owner only via routers/orgs.py with org_settings_changes audit row.
    force_deterministic_only: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default="false", default=False
    )
    # Sub-project A (host-target-kind). When False (default), the targets router
    # rejects host-kind Target creation/PATCH for any host that resolves to a
    # private IP (RFC1918, loopback, link-local, CGNAT, IPv6 ULA). Flipped by
    # org admins via routers/orgs.py with `private_targets_disclosure_ack=True`
    # and a writes-an-audit-row contract. See spec
    # docs/superpowers/specs/2026-05-17-host-target-kind-design.md §4.
    allow_private_targets: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default="false", default=False
    )
    # Security Lake (OCSF Iceberg) per-org toggle. Disabled by default. When
    # disabled, ingestion + query/export are off; security_lake_disabled_at is
    # the purge clock — set on a user enable->disable, cleared on disable->enable,
    # and an org disabled for >7d is purged by the retention task. The migration
    # leaves disabled_at NULL so the clock starts only on a user-initiated disable.
    security_lake_enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default="false", default=False
    )
    security_lake_disabled_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True)
    )
    # Custom LLM Providers (BYO-LLM). Points at the org's active llm_providers
    # row; NULL means "use Pencheff's default env models". ON DELETE SET NULL so
    # deleting the active provider cleanly reverts the org to defaults. The
    # resolver (services/llm_providers/resolver.py, Plan B) reads this.
    active_llm_provider_id: Mapped[str | None] = mapped_column(
        UUID(as_uuid=False),
        ForeignKey("llm_providers.id", ondelete="SET NULL"),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    users = relationship("User", back_populates="org")


class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    email: Mapped[str] = mapped_column(String(320), unique=True, nullable=False, index=True)
    name: Mapped[str | None] = mapped_column(String(200))
    password_hash: Mapped[str | None] = mapped_column(String(255))
    google_sub: Mapped[str | None] = mapped_column(String(128), unique=True)
    # Deprecated single-org FK — kept nullable during the org/workspace rollout
    # so existing callers keep working. Real membership lives in `org_members`.
    org_id: Mapped[str | None] = mapped_column(UUID(as_uuid=False), ForeignKey("orgs.id", ondelete="SET NULL"))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    org = relationship("Org", back_populates="users")


class Workspace(Base):
    """A workspace inside an Org. All user-facing resources hang off a workspace."""
    __tablename__ = "workspaces"
    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("orgs.id", ondelete="CASCADE"), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    slug: Mapped[str] = mapped_column(String(64), nullable=False)
    created_by_user_id: Mapped[str | None] = mapped_column(UUID(as_uuid=False), ForeignKey("users.id", ondelete="SET NULL"))
    # Recipient list for the weekly workspace digest. NULL/empty = no
    # rollup email sent. Populated via the workspace settings UI.
    weekly_digest_emails: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (
        UniqueConstraint("org_id", "slug", name="uq_workspaces_org_slug"),
    )


class OrgMember(Base):
    """n:n link between User and Org with a role (owner|admin|member)."""
    __tablename__ = "org_members"
    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("orgs.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    role: Mapped[str] = mapped_column(String(16), nullable=False, default="member")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (
        UniqueConstraint("org_id", "user_id", name="uq_org_members_org_user"),
    )


class OrgInvite(Base):
    """Pending email invite to join an Org with a specific role."""
    __tablename__ = "org_invites"
    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("orgs.id", ondelete="CASCADE"), nullable=False, index=True)
    email: Mapped[str] = mapped_column(String(320), nullable=False, index=True)
    role: Mapped[str] = mapped_column(String(16), nullable=False, default="member")
    token_hash: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    invited_by_user_id: Mapped[str | None] = mapped_column(UUID(as_uuid=False), ForeignKey("users.id", ondelete="SET NULL"))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    accepted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Subscription(Base):
    __tablename__ = "subscriptions"
    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("orgs.id", ondelete="CASCADE"), nullable=False, index=True)
    stripe_sub_id: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    plan: Mapped[str] = mapped_column(String(32), nullable=False)
    current_period_end: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Target(Base):
    __tablename__ = "targets"
    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("orgs.id", ondelete="CASCADE"), nullable=False, index=True)
    workspace_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False, index=True)
    engagement_id: Mapped[str | None] = mapped_column(UUID(as_uuid=False), ForeignKey("engagements.id", ondelete="SET NULL"))
    user_id: Mapped[str | None] = mapped_column(UUID(as_uuid=False), ForeignKey("users.id", ondelete="SET NULL"))
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    base_url: Mapped[str] = mapped_column(String(2048), nullable=False)
    scope: Mapped[list[str] | None] = mapped_column(ARRAY(String))
    exclude_paths: Mapped[list[str] | None] = mapped_column(ARRAY(String))
    credentials_encrypted: Mapped[bytes | None] = mapped_column(LargeBinary)
    # Set when this Target is a passive mirror of a Repository (registered
    # via /repos/local, /repos/by-url, or a GitHub App install). Repo-scans
    # still flow through RepoScan; this row only exists so repos are listed
    # alongside DAST URLs in /targets and selectable in the integrations
    # target multi-select. ON DELETE CASCADE: removing a Repository
    # automatically removes its mirror.
    repository_id: Mapped[str | None] = mapped_column(
        UUID(as_uuid=False),
        ForeignKey("repositories.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    # Discriminator — "url" (live web/API endpoint, DAST), "repo"
    # (passive mirror of a Repository row, SAST/SCA), or "llm" (chat
    # completions endpoint subject to red-team probing). Backfilled
    # from repository_id by migration 0022; new rows must specify it.
    kind: Mapped[str] = mapped_column(String(32), nullable=False, default="url", index=True)
    # Non-secret LLM target configuration: provider preset, model
    # name, system prompt baseline, optional custom request template
    # + response JSONPath. NULL for url/repo targets. Secrets ride
    # in credentials_encrypted as before.
    llm_config: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    # Per-kind config for the 11 new non-llm kinds (feature 001): web_app,
    # rest_api, graphql, websocket, grpc, source_code, cicd_pipeline, iac,
    # container_image, k8s_cluster, package_registry, sbom. Validated by the
    # KindConfig Pydantic discriminated union in schemas/targets.py.
    # NULL for legacy url/repo/llm rows; llm_config above remains authoritative
    # for kind="llm".
    kind_config: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    # Per-kind credentials for shapes that don't fit the flat Credentials schema:
    # container_image (registry auth), k8s_cluster (kubeconfig YAML),
    # cicd_pipeline (provider tokens / GitHub App private keys), source_code
    # with auth_type=github_app. Same Fernet key as credentials_encrypted.
    kind_credentials_encrypted: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    # Security-program disciplines this Target serves (KSPM, ASPM, AI-SPM, …).
    # Validated server-side against schemas/targets.py::DISCIPLINE_TO_KINDS so
    # the discipline-to-kind compatibility holds. NULL → no discipline tag.
    disciplines: Mapped[list[str] | None] = mapped_column(ARRAY(String), nullable=True)
    # Recipient list for the per-target weekly digest. NULL/empty = no
    # digest sent. Populated via the target edit UI.
    weekly_digest_emails: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (
        # Reverse-chronological listing per workspace is the hot path on
        # /dashboard and /targets. Index includes created_at so Postgres
        # can satisfy ORDER BY without a sort step.
        Index("ix_targets_workspace_created", "workspace_id", "created_at"),
        # Per-kind list endpoint (/targets?kind=llm). Index includes
        # kind so the filter is index-only as workload grows.
        Index("ix_targets_workspace_kind_created", "workspace_id", "kind", "created_at"),
    )


class TargetRepository(Base):
    """Many-to-many: a URL Target may declare multiple attached Repositories
    so the scan worker runs SAST against each repo in parallel with DAST.

    Created via /targets and /targets/{id} when a URL target is saved with
    ``attached_repository_ids``. ON DELETE RESTRICT on repository_id is the
    safety net behind the API-level "repo is attached, refuse delete" rule.
    """
    __tablename__ = "target_repositories"
    target_id: Mapped[str] = mapped_column(
        UUID(as_uuid=False),
        ForeignKey("targets.id", ondelete="CASCADE"),
        primary_key=True,
    )
    repository_id: Mapped[str] = mapped_column(
        UUID(as_uuid=False),
        ForeignKey("repositories.id", ondelete="RESTRICT"),
        primary_key=True,
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (
        Index("ix_target_repositories_repository_id", "repository_id"),
    )


class Scan(Base):
    __tablename__ = "scans"
    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    target_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("targets.id", ondelete="CASCADE"), nullable=False, index=True)
    org_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("orgs.id", ondelete="CASCADE"), nullable=False, index=True)
    workspace_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False, index=True)
    engagement_id: Mapped[str | None] = mapped_column(UUID(as_uuid=False), ForeignKey("engagements.id", ondelete="SET NULL"))
    user_id: Mapped[str | None] = mapped_column(UUID(as_uuid=False), ForeignKey("users.id", ondelete="SET NULL"))
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="queued", index=True)
    profile: Mapped[str] = mapped_column(String(32), nullable=False, default="standard")
    pencheff_session_id: Mapped[str | None] = mapped_column(String(64))
    progress_pct: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    current_stage: Mapped[str | None] = mapped_column(String(64))
    summary: Mapped[dict | None] = mapped_column(JSONB)
    # Operator consent captured at scan-creation time. Required for all new
    # scans; pre-consent scans carry a sentinel backfilled by migration 0037.
    consent_payload: Mapped[dict | None] = mapped_column(JSONB)
    grade: Mapped[str | None] = mapped_column(String(1))
    score: Mapped[int | None] = mapped_column(Integer)
    # Stream of short, human-readable progress lines ("stage_start: …",
    # "stage_done: …", "finished", …). Persisted so a page refresh mid-scan
    # rehydrates the live log that was previously only in browser state.
    log: Mapped[list | None] = mapped_column(JSONB)
    error: Mapped[str | None] = mapped_column(Text)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # One-shot recipient list captured at scan-commission time. The
    # runner dispatches a "scan complete" email here when the scan
    # transitions to ``done`` or ``failed``. NULL/empty = no email.
    notify_emails: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    # Per-scan kind-specific payload (feature 001). Server-derives from
    # Target.kind_config at scan-creation; client may supply operational
    # overrides (e.g., container_image digest pin per scan). Validated by
    # the KindPayload Pydantic discriminated union in schemas/scans.py.
    # NULL for legacy url/repo/llm scans.
    kind_payload: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    # Operator AI toggle chosen at commission time. False → the runner forces
    # deterministic-only mode (no agent/swarm, no AI triage, no AI grading)
    # regardless of plan. Defaults True; existing rows backfill to True.
    use_ai: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, server_default="true")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (
        # /dashboard and /scans hit list_scans with ORDER BY created_at DESC
        # filtered on workspace_id. Composite index turns this into an
        # index-only descending scan rather than a heap scan + sort.
        Index("ix_scans_workspace_created", "workspace_id", "created_at"),
        # /targets/{id} hits list_scans with target_id=... ORDER BY created_at.
        # Without this composite, the planner picks ix_scans_target_id and
        # then sorts in memory.
        Index("ix_scans_target_created", "target_id", "created_at"),
    )


class Finding(Base):
    __tablename__ = "findings"
    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    scan_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    engagement_id: Mapped[str | None] = mapped_column(UUID(as_uuid=False), ForeignKey("engagements.id", ondelete="SET NULL"))
    pencheff_finding_id: Mapped[str | None] = mapped_column(String(64))
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    category: Mapped[str] = mapped_column(String(64), nullable=False)
    owasp_category: Mapped[str | None] = mapped_column(String(32))
    cwe_id: Mapped[str | None] = mapped_column(String(32))
    cvss_score: Mapped[float | None] = mapped_column()
    cvss_vector: Mapped[str | None] = mapped_column(String(200))
    endpoint: Mapped[str | None] = mapped_column(String(2048))
    parameter: Mapped[str | None] = mapped_column(String(200))
    description: Mapped[str | None] = mapped_column(Text)
    remediation: Mapped[str | None] = mapped_column(Text)
    evidence: Mapped[list | None] = mapped_column(JSONB)
    references_: Mapped[list[str] | None] = mapped_column("references", ARRAY(String))
    verification_status: Mapped[str] = mapped_column(String(32), default="unverified", nullable=False)
    suppressed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    suppress_reason: Mapped[str | None] = mapped_column(String(64))
    suppress_notes: Mapped[str | None] = mapped_column(Text)
    last_rechecked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    recheck_status: Mapped[str | None] = mapped_column(String(32))
    # AI Triage 2.0 — DeepSeek-backed exploitability walkthrough. Shape:
    # {walkthrough, blast_radius, exploit_scenario, fix_outline, confidence,
    #  model, input_tokens, output_tokens}. Cached so the same finding
    # doesn't get re-triaged on every dashboard hit.
    ai_triage: Mapped[dict | None] = mapped_column(JSONB)
    # SLA + EPSS + KEV enrichment
    sla_days: Mapped[int | None] = mapped_column(Integer)
    due_date: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    sla_breached: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    epss: Mapped[float | None] = mapped_column()
    kev: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    risk_score: Mapped[float | None] = mapped_column()
    # SSVC (CISA Stakeholder-Specific Vulnerability Categorization) action
    # class — one of: track | track_star | attend | act. Computed at insert.
    ssvc_decision: Mapped[str | None] = mapped_column(String(16))
    # Reachability — exploited | reachable | present | unknown. Pencheff's
    # core differentiator vs Snyk: every finding carries a verifiable
    # exploitability signal, not just a static-analysis match.
    reachability: Mapped[str | None] = mapped_column(String(16))
    hackable: Mapped[bool | None] = mapped_column(Boolean, nullable=True, default=None)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (
        Index("ix_findings_scan_severity", "scan_id", "severity"),
    )


class Report(Base):
    __tablename__ = "reports"
    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    scan_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    engagement_id: Mapped[str | None] = mapped_column(UUID(as_uuid=False), ForeignKey("engagements.id", ondelete="SET NULL"))
    compared_scan_id: Mapped[str | None] = mapped_column(UUID(as_uuid=False), ForeignKey("scans.id", ondelete="SET NULL"))
    kind: Mapped[str] = mapped_column(String(32), nullable=False, default="point_in_time")
    format: Mapped[str] = mapped_column(String(16), nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="pending", nullable=False)
    storage_path: Mapped[str | None] = mapped_column(String(1024))
    bytes: Mapped[int | None] = mapped_column(BigInteger)
    generated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    user_id: Mapped[str | None] = mapped_column(UUID(as_uuid=False), ForeignKey("users.id", ondelete="SET NULL"))
    org_id: Mapped[str | None] = mapped_column(UUID(as_uuid=False), ForeignKey("orgs.id", ondelete="SET NULL"))
    workspace_id: Mapped[str | None] = mapped_column(UUID(as_uuid=False), ForeignKey("workspaces.id", ondelete="SET NULL"))
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    entity_type: Mapped[str | None] = mapped_column(String(64))
    entity_id: Mapped[str | None] = mapped_column(String(64))
    meta: Mapped[dict | None] = mapped_column(JSONB)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    # Hash-chain tamper-evidence + observability correlation. Populated by
    # the audit middleware (apps/api/pencheff_api/middleware/audit.py).
    # ``row_hash = sha256(prev_hash || canonical_json(row_minus_hash))``.
    # Older rows written before this column existed have NULL hashes and
    # are skipped by the ``/audit/verify`` chain walker.
    prev_hash: Mapped[bytes | None] = mapped_column(LargeBinary)
    row_hash: Mapped[bytes | None] = mapped_column(LargeBinary)
    trace_id: Mapped[bytes | None] = mapped_column(LargeBinary)
    # DB column is ``inet`` (per migration 0042). Declaring it as String(64) at
    # the ORM layer makes asyncpg bind the value as VARCHAR, which the server
    # rejects with DatatypeMismatchError. Use the postgresql.INET type so the
    # binding is correct — the middleware audit pipeline (audit.py) sidesteps
    # this via raw text() statements, but any ORM-level ``AuditLog(request_ip=...)``
    # writes (routers/targets.py, routers/orgs.py) need this to match reality.
    request_ip: Mapped[str | None] = mapped_column(INET)
    user_agent: Mapped[str | None] = mapped_column(Text)
    request_body_diff: Mapped[dict | None] = mapped_column(JSONB)


# ─────────────────────────── Extended scanning workflows ───────────────────────────

class ScanSchedule(Base):
    """Cron-based recurring scan schedule."""
    __tablename__ = "scan_schedules"
    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("orgs.id", ondelete="CASCADE"), nullable=False, index=True)
    workspace_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False, index=True)
    target_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("targets.id", ondelete="CASCADE"), nullable=False, index=True)
    owner_user_id: Mapped[str | None] = mapped_column(UUID(as_uuid=False), ForeignKey("users.id", ondelete="SET NULL"))
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    cron_expression: Mapped[str] = mapped_column(String(128), nullable=False)
    # IANA timezone the cron expression is interpreted in. Default UTC for
    # backward compat with pre-2026-05-16 rows (when there was no tz field
    # and the cron was implicitly UTC). FE-created schedules pass the
    # operator's resolved timezone (Intl.DateTimeFormat().resolvedOptions().timeZone).
    timezone: Mapped[str] = mapped_column(String(64), nullable=False, server_default="UTC", default="UTC")
    profile: Mapped[str] = mapped_column(String(64), default="standard", nullable=False)
    policy_yaml: Mapped[str | None] = mapped_column(Text)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    next_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Asset(Base):
    """Attack-surface management inventory entry."""
    __tablename__ = "assets"
    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("orgs.id", ondelete="CASCADE"), nullable=False, index=True)
    workspace_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False, index=True)
    type: Mapped[str] = mapped_column(String(32), nullable=False)  # domain | subdomain | ip | port | cert | url
    value: Mapped[str] = mapped_column(String(2048), nullable=False)
    meta: Mapped[dict | None] = mapped_column(JSONB)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (
        UniqueConstraint("workspace_id", "type", "value", name="uq_assets_workspace_type_value"),
        Index("ix_assets_workspace_type", "workspace_id", "type"),
    )


class Integration(Base):
    """External notification destination — Slack / Teams / PagerDuty / ...

    Scope:
      * ``target_ids`` NULL/empty → integration fires for every target.
      * ``target_ids`` populated  → only scans on those targets fire events.

    Event filter:
      * ``events`` NULL/empty → every lifecycle event fires (scan_started,
        scan_done, scan_failed, finding_new, finding_changed).
      * ``events`` populated  → only the listed event types fire.

    ``severity_filter`` still gates ``finding_new`` / ``finding_changed`` —
    the per-event toggle decides *whether* to evaluate, severity decides
    *which* findings make the cut.
    """
    __tablename__ = "integrations"
    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("orgs.id", ondelete="CASCADE"), nullable=False, index=True)
    workspace_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False, index=True)
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    config_encrypted: Mapped[bytes | None] = mapped_column(LargeBinary)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    severity_filter: Mapped[str] = mapped_column(String(16), default="high", nullable=False)
    target_ids: Mapped[list[str] | None] = mapped_column(ARRAY(UUID(as_uuid=False)))
    events: Mapped[list[str] | None] = mapped_column(ARRAY(String(32)))
    # Per-feature-001 opt-in: which Target.kind values this integration fires
    # for. NULL = legacy (fires for all). Existing integrations backfilled by
    # migration 0045 to ["url","repo","llm"] — their pre-feature scope.
    target_kinds: Mapped[list[str] | None] = mapped_column(JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Sbom(Base):
    """Generated SBOM tied to a scan."""
    __tablename__ = "sboms"
    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    scan_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    format: Mapped[str] = mapped_column(String(32), nullable=False)  # cyclonedx | spdx
    content: Mapped[dict | None] = mapped_column(JSONB)
    component_count: Mapped[int | None] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class RepoSbom(Base):
    __tablename__ = "repo_sboms"
    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    repository_id: Mapped[str] = mapped_column(
        UUID(as_uuid=False),
        ForeignKey("repositories.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    commit_sha: Mapped[str | None] = mapped_column(String(64))
    format: Mapped[str] = mapped_column(String(32), nullable=False)  # cyclonedx | spdx
    content: Mapped[dict | None] = mapped_column(JSONB)
    component_count: Mapped[int | None] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Dependency(Base):
    """Discovered dependency for a scan — used to render dep + license tables."""
    __tablename__ = "dependencies"
    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    scan_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    ecosystem: Mapped[str] = mapped_column(String(32), nullable=False)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    version: Mapped[str] = mapped_column(String(64), nullable=False)
    license: Mapped[str | None] = mapped_column(String(128))
    scope: Mapped[str] = mapped_column(String(16), default="runtime", nullable=False)
    vulnerabilities: Mapped[list | None] = mapped_column(JSONB)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class ProxySession(Base):
    __tablename__ = "proxy_sessions"
    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    scan_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    engagement_id: Mapped[str | None] = mapped_column(UUID(as_uuid=False), ForeignKey("engagements.id", ondelete="SET NULL"))
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    mode: Mapped[str] = mapped_column(String(32), default="mitmproxy", nullable=False)
    request_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    stopped_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class FindingComment(Base):
    __tablename__ = "finding_comments"
    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    finding_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class FindingAssignment(Base):
    __tablename__ = "finding_assignments"
    finding_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("findings.id", ondelete="CASCADE"), primary_key=True)
    assignee_user_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    assigner_user_id: Mapped[str | None] = mapped_column(UUID(as_uuid=False), ForeignKey("users.id", ondelete="SET NULL"))
    assigned_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class FindingTag(Base):
    __tablename__ = "finding_tags"
    finding_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("findings.id", ondelete="CASCADE"), primary_key=True)
    tag: Mapped[str] = mapped_column(String(64), primary_key=True)


# ─────────────────────── Fix proposals (SAST + DAST) ───────────────


class FixProposal(Base):
    """A proposed code change to remediate a Finding (DAST) or RepoFinding (SAST).

    The ``finding_kind``/``finding_id`` pair is polymorphic: it points at
    ``findings.id`` when ``finding_kind == "dast"`` and at ``repo_findings.id``
    when ``"sast"``. We don't put a real FK on ``finding_id`` because it would
    have to span two tables; a soft pointer plus the index is enough since
    the row gets cascaded via ``scan_id`` / ``repo_scan_id`` when scans are
    deleted, which is the only deletion path that matters.
    """
    __tablename__ = "fix_proposals"
    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("orgs.id", ondelete="CASCADE"), nullable=False)
    workspace_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False)
    scan_id: Mapped[str | None] = mapped_column(UUID(as_uuid=False), ForeignKey("scans.id", ondelete="CASCADE"))
    repo_scan_id: Mapped[str | None] = mapped_column(UUID(as_uuid=False), ForeignKey("repo_scans.id", ondelete="CASCADE"))
    finding_kind: Mapped[str] = mapped_column(String(16), nullable=False)  # sast | dast
    finding_id: Mapped[str] = mapped_column(UUID(as_uuid=False), nullable=False)
    repository_id: Mapped[str | None] = mapped_column(UUID(as_uuid=False), ForeignKey("repositories.id", ondelete="SET NULL"))
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="draft")  # draft | applied | failed | superseded
    source: Mapped[str] = mapped_column(String(32), nullable=False)  # scanner | llm
    diff: Mapped[str] = mapped_column(Text, nullable=False)
    target_files: Mapped[list | None] = mapped_column(JSONB)
    provenance_confidence: Mapped[float | None] = mapped_column()
    provenance_reasoning: Mapped[str | None] = mapped_column(Text)
    llm_input_tokens: Mapped[int | None] = mapped_column(Integer)
    llm_output_tokens: Mapped[int | None] = mapped_column(Integer)
    cost_usd: Mapped[float | None] = mapped_column()
    branch_name: Mapped[str | None] = mapped_column(String(200))
    pr_url: Mapped[str | None] = mapped_column(String(1024))
    commit_sha: Mapped[str | None] = mapped_column(String(64))
    error: Mapped[str | None] = mapped_column(Text)
    created_by: Mapped[str | None] = mapped_column(UUID(as_uuid=False), ForeignKey("users.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    applied_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        Index("ix_fix_proposals_finding", "finding_kind", "finding_id"),
        Index("ix_fix_proposals_org_created", "org_id", "created_at"),
        Index("ix_fix_proposals_status", "org_id", "status"),
    )


class FixLlmUsage(Base):
    """Append-only ledger of LLM-backed proposer calls.

    Drives quota enforcement (SAST per-scan/per-period, DAST per-period) and
    end-of-period billing for PAYG charges. ``free_quota_consumed`` is 1 if
    this call drew from the free allowance; 0 once the org has tipped into
    PAYG. The Stripe invoicing job sums ``payg_cost_usd`` per period.
    """
    __tablename__ = "fix_llm_usage"
    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("orgs.id", ondelete="CASCADE"), nullable=False)
    scan_id: Mapped[str | None] = mapped_column(UUID(as_uuid=False), ForeignKey("scans.id", ondelete="SET NULL"))
    proposal_id: Mapped[str | None] = mapped_column(UUID(as_uuid=False), ForeignKey("fix_proposals.id", ondelete="SET NULL"))
    kind: Mapped[str] = mapped_column(String(16), nullable=False)  # sast | dast
    model: Mapped[str] = mapped_column(String(64), nullable=False)
    input_tokens: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    output_tokens: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    free_quota_consumed: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    payg_cost_usd: Mapped[float] = mapped_column(nullable=False, default=0.0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (
        Index("ix_fix_llm_usage_org_created", "org_id", "created_at"),
        Index("ix_fix_llm_usage_scan_kind", "scan_id", "kind"),
    )


class BulkFixTask(Base):
    """Async task tracker for the ``fix-all`` bulk endpoints.

    The work itself runs in a Celery worker (``tasks/bulk_fix_task.py``);
    this row is the source of truth for status + progress so the
    frontend can poll a single ``GET /fix-tasks/{id}`` endpoint without
    coupling to Celery's result backend. ``results`` mirrors the old
    synchronous ``BulkFixSummary`` payload — once status flips to
    ``completed``, the same UI rendering code that handled the old
    inline response works unchanged.
    """
    __tablename__ = "bulk_fix_tasks"
    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(UUID(as_uuid=False), nullable=False)
    workspace_id: Mapped[str] = mapped_column(UUID(as_uuid=False), nullable=False)
    user_id: Mapped[str] = mapped_column(UUID(as_uuid=False), nullable=False)
    # Exactly one of these two is non-null per row.
    scan_id: Mapped[str | None] = mapped_column(UUID(as_uuid=False), nullable=True)
    repo_scan_id: Mapped[str | None] = mapped_column(UUID(as_uuid=False), nullable=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="queued")
    total_findings: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    completed_findings: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    results: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        Index("bulk_fix_tasks_org_created_idx", "org_id", "created_at"),
    )


# ─────────────────────── GitHub repo scanning ───────────────────────

class RepoIntegration(Base):
    """An installation of the Pencheff GitHub App on a user's/org's account."""
    __tablename__ = "repo_integrations"
    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("orgs.id", ondelete="CASCADE"), nullable=False, index=True)
    workspace_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False, index=True)
    provider: Mapped[str] = mapped_column(String(32), nullable=False, default="github")
    installation_id: Mapped[str] = mapped_column(String(64), nullable=False)
    account_login: Mapped[str] = mapped_column(String(200), nullable=False)
    account_type: Mapped[str] = mapped_column(String(32), nullable=False, default="User")  # User | Organization
    avatar_url: Mapped[str | None] = mapped_column(String(1024))
    installed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    removed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        UniqueConstraint("provider", "installation_id", name="uq_repo_integrations_provider_install"),
        Index("ix_repo_integrations_org", "org_id"),
    )


class Repository(Base):
    """A repository made available to Pencheff.

    Three valid states:
      * ``provider == "github"`` + ``integration_id`` set → GitHub App
        installation: private repos, push webhooks, Dependabot.
      * ``provider == "github"`` + ``integration_id`` NULL → public URL
        clone: anonymous shallow clone, no webhooks, no Dependabot.
      * ``provider == "local"`` + ``local_path`` set → host folder read
        in place by the worker.

    The repo-scan task branches on ``provider`` and ``integration_id`` —
    same scanners, same ``RepoScan`` / ``RepoFinding`` rows.
    """
    __tablename__ = "repositories"
    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("orgs.id", ondelete="CASCADE"), nullable=False, index=True)
    workspace_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False, index=True)
    integration_id: Mapped[str | None] = mapped_column(UUID(as_uuid=False), ForeignKey("repo_integrations.id", ondelete="CASCADE"), index=True)
    provider: Mapped[str] = mapped_column(String(32), nullable=False, default="github")
    provider_repo_id: Mapped[str] = mapped_column(String(64), nullable=False)
    owner: Mapped[str] = mapped_column(String(200), nullable=False)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    full_name: Mapped[str] = mapped_column(String(400), nullable=False)
    default_branch: Mapped[str] = mapped_column(String(200), nullable=False, default="main")
    private: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    html_url: Mapped[str] = mapped_column(String(1024), nullable=False)
    language: Mapped[str | None] = mapped_column(String(64))
    # Filesystem path for ``provider == "local"`` repos. Must be readable
    # by the Celery worker (mount it into the container if you're running
    # in Docker). Ignored for GitHub repos.
    local_path: Mapped[str | None] = mapped_column(Text)
    # Fernet-encrypted Personal Access Token. Set when the user registered
    # this repo via the "Private GitHub (PAT)" path on /targets/new. The
    # repo-scan task reads it via decrypt_credentials() and uses it as the
    # x-access-token password for ``git clone``. NEVER returned by any API
    # endpoint; the encrypted blob never leaves the DB.
    token_encrypted: Mapped[bytes | None] = mapped_column(LargeBinary)
    auto_scan_on_push: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    last_scan_id: Mapped[str | None] = mapped_column(UUID(as_uuid=False))
    last_scan_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (
        UniqueConstraint("provider", "provider_repo_id", name="uq_repositories_provider_repo"),
        Index("ix_repositories_org", "org_id"),
    )


class RepoScan(Base):
    """A scan run against a connected repository (separate from DAST Scan)."""
    __tablename__ = "repo_scans"
    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("orgs.id", ondelete="CASCADE"), nullable=False, index=True)
    workspace_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False, index=True)
    engagement_id: Mapped[str | None] = mapped_column(UUID(as_uuid=False), ForeignKey("engagements.id", ondelete="SET NULL"))
    repository_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("repositories.id", ondelete="CASCADE"), nullable=False, index=True)
    commit_sha: Mapped[str | None] = mapped_column(String(64))
    ref: Mapped[str | None] = mapped_column(String(256))
    trigger: Mapped[str] = mapped_column(String(32), nullable=False, default="manual")  # manual | webhook | schedule
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="queued")
    scanners: Mapped[list | None] = mapped_column(JSONB)
    stats: Mapped[dict | None] = mapped_column(JSONB)  # per-scanner counts, durations, exit codes
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    error: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (
        Index("ix_repo_scans_repo_created", "repository_id", "created_at"),
    )


class RepoFinding(Base):
    """A single finding produced by one of the repo scanners."""
    __tablename__ = "repo_findings"
    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    repo_scan_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("repo_scans.id", ondelete="CASCADE"), nullable=False, index=True)
    repository_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("repositories.id", ondelete="CASCADE"), nullable=False, index=True)
    engagement_id: Mapped[str | None] = mapped_column(UUID(as_uuid=False), ForeignKey("engagements.id", ondelete="SET NULL"))
    scanner: Mapped[str] = mapped_column(String(32), nullable=False)  # semgrep | osv | ghsa | gitleaks | yara | trivy_iac | checkov
    rule_id: Mapped[str | None] = mapped_column(String(200))
    severity: Mapped[str] = mapped_column(String(16), nullable=False, default="medium")
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    file_path: Mapped[str | None] = mapped_column(String(1024))
    line_start: Mapped[int | None] = mapped_column(Integer)
    line_end: Mapped[int | None] = mapped_column(Integer)
    code_snippet: Mapped[str | None] = mapped_column(Text)
    cve: Mapped[str | None] = mapped_column(String(64))
    package: Mapped[str | None] = mapped_column(String(200))
    installed_version: Mapped[str | None] = mapped_column(String(64))
    fixed_version: Mapped[str | None] = mapped_column(String(64))
    raw: Mapped[dict | None] = mapped_column(JSONB)
    ai_explanation: Mapped[str | None] = mapped_column(Text)
    fix_status: Mapped[str] = mapped_column(String(32), nullable=False, default="none")  # none | proposed | pr_open | merged
    fix_pr_url: Mapped[str | None] = mapped_column(String(1024))
    suppressed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    # Set by AI false-positive triage (services/repo_fp_triage.py) — mirrors the
    # DAST Finding model. ``suppress_reason="ai_false_positive"`` when the LLM
    # verified the finding is a false positive (e.g. parameterized SQL that
    # bandit's B608 heuristic over-flags); notes carry the model + justification.
    suppress_reason: Mapped[str | None] = mapped_column(String(64))
    suppress_notes: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (
        Index("ix_repo_findings_scan_severity", "repo_scan_id", "severity"),
        Index("ix_repo_findings_repo_scanner", "repository_id", "scanner"),
    )


# ────────────────────────── Engagements + collaboration ──────────────────────────


class Engagement(Base):
    """A multi-day pentest container. Owns OAST + traffic + notes + members."""
    __tablename__ = "engagements"
    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("orgs.id", ondelete="CASCADE"), nullable=False, index=True)
    workspace_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    slug: Mapped[str] = mapped_column(String(64), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="open")
    oast_domain: Mapped[str | None] = mapped_column(String(255))
    oast_token: Mapped[str | None] = mapped_column(String(128))
    oast_container_id: Mapped[str | None] = mapped_column(String(128))
    oast_mode: Mapped[str] = mapped_column(String(16), nullable=False, default="shared")
    retention_days: Mapped[int] = mapped_column(Integer, nullable=False, default=90)
    created_by_user_id: Mapped[str | None] = mapped_column(UUID(as_uuid=False), ForeignKey("users.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Optional STRIDE / DREAD threat model attached to the engagement.
    # Generated via POST /engagements/{id}/threat-model or by the
    # ThreatModelAgent during the swarm's pre-recon phase. Drives module
    # priority in the scan dispatcher when present (see services.scan_profile).
    threat_model: Mapped[dict | None] = mapped_column(JSONB)
    threat_model_updated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True)
    )

    __table_args__ = (
        UniqueConstraint("workspace_id", "slug", name="uq_engagements_workspace_slug"),
    )


class EngagementMember(Base):
    __tablename__ = "engagement_members"
    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    engagement_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("engagements.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    role: Mapped[str] = mapped_column(String(16), nullable=False, default="analyst")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (
        UniqueConstraint("engagement_id", "user_id", name="uq_engagement_members_eng_user"),
    )


class ProxyTraffic(Base):
    """Captured request/response flow from the browser extension or mitmproxy."""
    __tablename__ = "proxy_traffic"
    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    engagement_id: Mapped[str | None] = mapped_column(UUID(as_uuid=False), ForeignKey("engagements.id", ondelete="SET NULL"))
    proxy_session_id: Mapped[str | None] = mapped_column(UUID(as_uuid=False), ForeignKey("proxy_sessions.id", ondelete="SET NULL"))
    workspace_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False, index=True)
    captured_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    source: Mapped[str] = mapped_column(String(32), nullable=False, default="extension")
    method: Mapped[str] = mapped_column(String(16), nullable=False)
    url: Mapped[str] = mapped_column(Text, nullable=False)
    host: Mapped[str] = mapped_column(String(512), nullable=False)
    path: Mapped[str] = mapped_column(Text, nullable=False, default="")
    query: Mapped[dict | None] = mapped_column(JSONB)
    request_headers: Mapped[dict | None] = mapped_column(JSONB)
    request_body: Mapped[str | None] = mapped_column(Text)
    request_body_truncated: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    response_status: Mapped[int | None] = mapped_column(Integer)
    response_headers: Mapped[dict | None] = mapped_column(JSONB)
    response_body: Mapped[str | None] = mapped_column(Text)
    response_body_truncated: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    response_size: Mapped[int | None] = mapped_column(BigInteger)
    duration_ms: Mapped[int | None] = mapped_column(Integer)
    tab_id: Mapped[int | None] = mapped_column(Integer)
    frame_id: Mapped[int | None] = mapped_column(Integer)
    initiator: Mapped[str | None] = mapped_column(String(2048))
    body_capture: Mapped[str] = mapped_column(String(16), nullable=False, default="full")
    is_starred: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    tags: Mapped[list[str] | None] = mapped_column(ARRAY(String))
    notes: Mapped[str | None] = mapped_column(Text)
    ws_frames: Mapped[list | None] = mapped_column(JSONB)
    # ``fts_doc`` is a generated tsvector column. We don't map it as an
    # attribute — queries reference it by literal SQL.


class EngagementIngestToken(Base):
    __tablename__ = "engagement_ingest_tokens"
    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    engagement_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("engagements.id", ondelete="CASCADE"), nullable=False, index=True)
    workspace_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False, index=True)
    token_hash: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    pairing_code: Mapped[str | None] = mapped_column(String(32), unique=True)
    created_by_user_id: Mapped[str | None] = mapped_column(UUID(as_uuid=False), ForeignKey("users.id", ondelete="SET NULL"))
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


# ─────────────────────── Repeater + Intruder ───────────────────────


class RepeaterTab(Base):
    __tablename__ = "repeater_tabs"
    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    engagement_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("engagements.id", ondelete="CASCADE"), nullable=False, index=True)
    workspace_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False, default="Untitled")
    request_method: Mapped[str] = mapped_column(String(16), nullable=False, default="GET")
    request_url: Mapped[str] = mapped_column(Text, nullable=False)
    request_headers: Mapped[dict | None] = mapped_column(JSONB)
    request_body: Mapped[str | None] = mapped_column(Text)
    pinned: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    notes: Mapped[str | None] = mapped_column(Text)
    source_traffic_id: Mapped[str | None] = mapped_column(UUID(as_uuid=False), ForeignKey("proxy_traffic.id", ondelete="SET NULL"))
    created_by_user_id: Mapped[str | None] = mapped_column(UUID(as_uuid=False), ForeignKey("users.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class RepeaterResponse(Base):
    __tablename__ = "repeater_responses"
    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    tab_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("repeater_tabs.id", ondelete="CASCADE"), nullable=False, index=True)
    sent_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    request_snapshot: Mapped[dict] = mapped_column(JSONB, nullable=False)
    response_status: Mapped[int | None] = mapped_column(Integer)
    response_headers: Mapped[dict | None] = mapped_column(JSONB)
    response_body: Mapped[str | None] = mapped_column(Text)
    duration_ms: Mapped[int | None] = mapped_column(Integer)
    sent_by_user_id: Mapped[str | None] = mapped_column(UUID(as_uuid=False), ForeignKey("users.id", ondelete="SET NULL"))


class IntruderPayloadSet(Base):
    __tablename__ = "intruder_payload_sets"
    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    workspace_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    kind: Mapped[str] = mapped_column(String(32), nullable=False, default="wordlist")
    source: Mapped[str | None] = mapped_column(Text)
    entries: Mapped[list | None] = mapped_column(JSONB)
    entries_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class IntruderAttack(Base):
    __tablename__ = "intruder_attacks"
    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    engagement_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("engagements.id", ondelete="CASCADE"), nullable=False, index=True)
    workspace_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False, default="Attack")
    request_template: Mapped[dict] = mapped_column(JSONB, nullable=False)
    payload_set_id: Mapped[str | None] = mapped_column(UUID(as_uuid=False), ForeignKey("intruder_payload_sets.id", ondelete="SET NULL"))
    attack_type: Mapped[str] = mapped_column(String(32), nullable=False, default="sniper")
    concurrency: Mapped[int] = mapped_column(Integer, nullable=False, default=5)
    rate_limit: Mapped[int] = mapped_column(Integer, nullable=False, default=20)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="queued")
    progress_pct: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_by_user_id: Mapped[str | None] = mapped_column(UUID(as_uuid=False), ForeignKey("users.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class IntruderResult(Base):
    __tablename__ = "intruder_results"
    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    attack_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("intruder_attacks.id", ondelete="CASCADE"), nullable=False, index=True)
    payload: Mapped[str] = mapped_column(Text, nullable=False)
    request_snapshot: Mapped[dict | None] = mapped_column(JSONB)
    response_status: Mapped[int | None] = mapped_column(Integer)
    response_length: Mapped[int | None] = mapped_column(Integer)
    response_time_ms: Mapped[int | None] = mapped_column(Integer)
    grep_match: Mapped[list[str] | None] = mapped_column(ARRAY(String))
    diff_score: Mapped[float | None] = mapped_column()
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


# ─────────────────────── Unified findings + notes + branding ───────────────────────


class UnifiedFinding(Base):
    """A correlation edge between a primary finding and a related finding."""
    __tablename__ = "unified_findings"
    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    engagement_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("engagements.id", ondelete="CASCADE"), nullable=False, index=True)
    primary_finding_kind: Mapped[str] = mapped_column(String(16), nullable=False)
    primary_finding_id: Mapped[str] = mapped_column(UUID(as_uuid=False), nullable=False)
    related_finding_kind: Mapped[str] = mapped_column(String(16), nullable=False)
    related_finding_id: Mapped[str] = mapped_column(UUID(as_uuid=False), nullable=False)
    link_kind: Mapped[str] = mapped_column(String(32), nullable=False)
    confidence: Mapped[float] = mapped_column(nullable=False, default=0.5)
    rationale: Mapped[str | None] = mapped_column(Text)
    generated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class EngagementNote(Base):
    __tablename__ = "engagement_notes"
    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    engagement_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("engagements.id", ondelete="CASCADE"), nullable=False, index=True)
    kind: Mapped[str] = mapped_column(String(32), nullable=False, default="general")
    target_kind: Mapped[str | None] = mapped_column(String(32))
    target_id: Mapped[str | None] = mapped_column(String(64))
    body_md: Mapped[str] = mapped_column(Text, nullable=False, default="")
    pinned: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_by_user_id: Mapped[str | None] = mapped_column(UUID(as_uuid=False), ForeignKey("users.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class WorkspaceBranding(Base):
    __tablename__ = "workspace_branding"
    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    workspace_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("workspaces.id", ondelete="CASCADE"), unique=True, nullable=False)
    logo_url: Mapped[str | None] = mapped_column(String(2048))
    primary_color: Mapped[str | None] = mapped_column(String(16))
    secondary_color: Mapped[str | None] = mapped_column(String(16))
    opening_letter_md: Mapped[str | None] = mapped_column(Text)
    methodology_md: Mapped[str | None] = mapped_column(Text)
    footer_text: Mapped[str | None] = mapped_column(String(500))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


# ─────────────────────── Swarm LLM call traces ───────────────────────


class ScanLLMTrace(Base):
    """One row per chat-completions call from the swarm orchestrator.

    Captures the full request/response for replay and audit. Token columns
    are nullable because not every provider returns a complete breakdown.
    """
    __tablename__ = "scan_llm_traces"
    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    scan_id: Mapped[str] = mapped_column(
        UUID(as_uuid=False),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    agent_name: Mapped[str] = mapped_column(String(64), nullable=False)
    turn: Mapped[int] = mapped_column(Integer, nullable=False)
    request_messages: Mapped[list] = mapped_column(JSONB, nullable=False)
    request_tools_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    response_content: Mapped[str | None] = mapped_column(Text)
    response_tool_calls: Mapped[list | None] = mapped_column(JSONB)
    response_reasoning: Mapped[str | None] = mapped_column(Text)
    prompt_tokens: Mapped[int | None] = mapped_column(Integer)
    completion_tokens: Mapped[int | None] = mapped_column(Integer)
    cached_tokens: Mapped[int | None] = mapped_column(Integer)
    reasoning_tokens: Mapped[int | None] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class RuntimeSpan(Base):
    """One OpenTelemetry-style span in a runtime-protection trace.

    Workspace-scoped (not scan-scoped like ``ScanLLMTrace``) — these come
    from the hosted gateway and the embeddable SDK as customers run their
    own agents in production. Spans group into a trace via ``trace_id`` +
    ``parent_span_id``. ``kind`` partitions the span tree into the runtime-
    protection concepts the viewer renders: an LLM call, a tool call, a
    firewall decision, a detector verdict, or the enclosing request.
    """
    __tablename__ = "runtime_spans"
    # span_id (OTel). PK so child spans can reference it as parent.
    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    workspace_id: Mapped[str] = mapped_column(
        UUID(as_uuid=False),
        ForeignKey("workspaces.id", ondelete="CASCADE"),
        nullable=False,
    )
    trace_id: Mapped[str] = mapped_column(String(64), nullable=False)
    parent_span_id: Mapped[str | None] = mapped_column(String(64))
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    # request | llm | tool | firewall | detector | other
    kind: Mapped[str] = mapped_column(String(32), nullable=False, default="other")
    # ok | blocked | error
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="ok")
    # gateway | sdk
    source: Mapped[str] = mapped_column(String(16), nullable=False, default="gateway")
    target_id: Mapped[str | None] = mapped_column(UUID(as_uuid=False))
    start_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    end_time: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    duration_ms: Mapped[int | None] = mapped_column(Integer)
    # OTel GenAI-style attributes: model, token counts, tool name, firewall
    # decision, detector category, etc. Free-form per kind.
    attributes: Mapped[dict | None] = mapped_column(JSONB)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    __table_args__ = (
        # List traces for a workspace, newest first.
        Index("ix_runtime_spans_ws_created", "workspace_id", "created_at"),
        # Fetch all spans in one trace (detail view).
        Index("ix_runtime_spans_ws_trace", "workspace_id", "trace_id"),
    )


# ─────────────────────────── PENCHEFF_API_KEY ───────────────────────────


class ApiKey(Base):
    """A user-issued API key for programmatic access.

    Keys are scoped to a single ``org_id``; ``workspace_id`` may be a
    specific workspace (member-issuable) or ``NULL`` meaning "all
    workspaces in this org" (only org owners/admins can mint these).

    The plaintext key is shown to the operator exactly once at creation.
    Only ``key_hash`` (SHA-256, hex) is persisted; lookup uses ``prefix``
    (the first 8 chars of the random portion, after the ``pcf_live_``
    sentinel) for an indexed point-fetch followed by a constant-time
    hash comparison.
    """

    __tablename__ = "api_keys"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    user_id: Mapped[str] = mapped_column(
        UUID(as_uuid=False),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    org_id: Mapped[str] = mapped_column(
        UUID(as_uuid=False),
        ForeignKey("orgs.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    workspace_id: Mapped[str | None] = mapped_column(
        UUID(as_uuid=False),
        ForeignKey("workspaces.id", ondelete="CASCADE"),
        index=True,
    )
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    prefix: Mapped[str] = mapped_column(String(16), nullable=False, unique=True, index=True)
    key_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    scopes: Mapped[list[str]] = mapped_column(ARRAY(String(64)), nullable=False, default=list)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


# ─────────────────────── Agentic Fix-all flow ───────────────────────

class AgenticFixRun(Base):
    """One row per "Fix all (agent)" invocation.

    The agent loop runs in either the server-side Celery worker
    (``runtime='server'``) or the desktop's Pencheff Studio
    (``runtime='desktop'``). See the design spec at
    ``docs/superpowers/specs/2026-05-23-agentic-fixer-design.md``.

    Exactly one of ``scan_id`` / ``repo_scan_id`` is non-null per row —
    a single agent run targets either a DAST scan or a repo (SAST)
    scan, never both. Enforced via CHECK constraint.
    """
    __tablename__ = "agentic_fix_runs"
    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(UUID(as_uuid=False), nullable=False, index=True)
    workspace_id: Mapped[str] = mapped_column(UUID(as_uuid=False), nullable=False, index=True)
    user_id: Mapped[str] = mapped_column(UUID(as_uuid=False), nullable=False)
    scan_id: Mapped[str | None] = mapped_column(UUID(as_uuid=False), nullable=True)
    repo_scan_id: Mapped[str | None] = mapped_column(UUID(as_uuid=False), nullable=True)
    repository_id: Mapped[str | None] = mapped_column(
        UUID(as_uuid=False),
        ForeignKey("repositories.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    runtime: Mapped[str] = mapped_column(String(16), nullable=False, default="server")
    # queued | cloning | running | committing | pushing | done | failed | canceled
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="queued")
    findings_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    # ``None`` means legacy select-all behavior; a list scopes this run to
    # operator-selected findings and survives the async queue handoff.
    selected_finding_ids: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    iterations: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    current_step: Mapped[str | None] = mapped_column(Text, nullable=True)
    branch_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    pr_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    system_prompt: Mapped[str | None] = mapped_column(Text, nullable=True)
    model: Mapped[str] = mapped_column(String(64), nullable=False)
    max_iterations: Mapped[int] = mapped_column(Integer, nullable=False, default=30)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Flipped by the cancel endpoint; the worker polls between
    # iterations and bails when it sees this True.
    cancel_requested: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    __table_args__ = (
        Index("ix_agentic_fix_runs_workspace_created", "workspace_id", "created_at"),
    )


class AgenticFixUsage(Base):
    """Per Anthropic Messages-API call token + cost record.

    Aggregated by ``workspace_id + created_at`` for per-workspace
    month-to-date spend used by the plan-tier limit checker.
    ``cost_usd_cents`` is computed at row-write time from the model
    price table — denormalised so re-running historical reports
    doesn't need a price-history join.
    """
    __tablename__ = "agentic_fix_usage"
    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    run_id: Mapped[str] = mapped_column(
        UUID(as_uuid=False),
        ForeignKey("agentic_fix_runs.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    workspace_id: Mapped[str] = mapped_column(UUID(as_uuid=False), nullable=False, index=True)
    iteration: Mapped[int] = mapped_column(Integer, nullable=False)
    model: Mapped[str] = mapped_column(String(64), nullable=False)
    input_tokens: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    output_tokens: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    cache_read_input_tokens: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    cache_creation_input_tokens: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    cost_usd_cents: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    __table_args__ = (
        Index("ix_agentic_fix_usage_workspace_created", "workspace_id", "created_at"),
    )


class AgenticFixStep(Base):
    """Audit trail of every tool call the agent made.

    Drives the live progress UI (SSE stream consumes new rows) and
    backfills ``AuditLog`` entries for compliance. Tool inputs are
    stored verbatim except for shell-tool ``command`` strings which
    pass through a secret-redaction filter before persistence.
    """
    __tablename__ = "agentic_fix_steps"
    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    run_id: Mapped[str] = mapped_column(
        UUID(as_uuid=False),
        ForeignKey("agentic_fix_runs.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    iteration: Mapped[int] = mapped_column(Integer, nullable=False)
    step_index: Mapped[int] = mapped_column(Integer, nullable=False)
    tool_name: Mapped[str] = mapped_column(String(64), nullable=False)
    tool_input: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    tool_output_truncated: Mapped[str | None] = mapped_column(Text, nullable=True)
    tool_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    duration_ms: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    __table_args__ = (
        Index("ix_agentic_fix_steps_run_iter", "run_id", "iteration", "step_index"),
    )


class WorkstationCompliance(Base):
    """Compliance state uploaded by Pencheff Studio."""
    __tablename__ = "workstation_compliance"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("orgs.id", ondelete="CASCADE"), nullable=False, index=True)
    workspace_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, unique=True, index=True)

    studio_installed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, server_default="true")
    monitors_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, server_default="true")
    overall_device_score: Mapped[int] = mapped_column(Integer, nullable=False, default=100, server_default="100")
    overall_file_status: Mapped[str] = mapped_column(String(32), nullable=False, default="Clean", server_default="Clean")

    device_checks_json: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    file_checks_json: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()
    )


# ─────────────────────── Security Lake audit tables ───────────────────────


class LakeIngestion(Base):
    """One row per (scan, source) ingested into the Security Lake. Drives idempotency."""
    __tablename__ = "lake_ingestion"
    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    scan_id: Mapped[str] = mapped_column(String(64), nullable=False)
    source: Mapped[str] = mapped_column(String(16), nullable=False)
    org_id: Mapped[str | None] = mapped_column(UUID(as_uuid=False))
    appended_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    quarantined_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="ok")  # ok | partial | failed
    error: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    __table_args__ = (UniqueConstraint("scan_id", "source", name="uq_lake_ingestion_scan_source"),)


class LakeQuarantine(Base):
    """A finding that failed OCSF mapping/validation and was not written to the lake."""
    __tablename__ = "lake_quarantine"
    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    scan_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    source: Mapped[str] = mapped_column(String(16), nullable=False)
    org_id: Mapped[str | None] = mapped_column(UUID(as_uuid=False))
    error: Mapped[str] = mapped_column(Text, nullable=False)
    finding_repr: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class LlmProvider(Base):
    """An org-supplied LLM provider config (BYO-LLM).

    Typed/native provider; the API key is Fernet-encrypted in
    ``api_key_encrypted`` (via services/credentials.encrypt_credentials with a
    {"api_key": ...} dict) and is NEVER returned by any endpoint. Exactly one
    provider per org is "active", tracked by Org.active_llm_provider_id.
    """
    __tablename__ = "llm_providers"
    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(
        UUID(as_uuid=False), ForeignKey("orgs.id", ondelete="CASCADE"),
        nullable=False, index=True)
    label: Mapped[str] = mapped_column(String(120), nullable=False)
    provider: Mapped[str] = mapped_column(String(32), nullable=False)
    model: Mapped[str] = mapped_column(String(200), nullable=False)
    base_url: Mapped[str | None] = mapped_column(String(1024))
    api_key_encrypted: Mapped[bytes | None] = mapped_column(LargeBinary)
    azure_deployment: Mapped[str | None] = mapped_column(String(200))
    azure_api_version: Mapped[str | None] = mapped_column(String(40))
    extra: Mapped[dict | None] = mapped_column(JSONB)
    created_by: Mapped[str | None] = mapped_column(
        UUID(as_uuid=False), ForeignKey("users.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now())

    __table_args__ = (
        UniqueConstraint("org_id", "label", name="uq_llm_providers_org_label"),
        Index("ix_llm_providers_org", "org_id"),
    )
