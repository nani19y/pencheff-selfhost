"""initial schema

Revision ID: 0001
Revises:
Create Date: 2026-04-17
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "0001"
down_revision: Union[str, None] = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "orgs",
        sa.Column("id", postgresql.UUID(as_uuid=False), primary_key=True),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("plan", sa.String(32), nullable=False, server_default="free"),
        sa.Column("stripe_customer_id", sa.String(64)),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_table(
        "users",
        sa.Column("id", postgresql.UUID(as_uuid=False), primary_key=True),
        sa.Column("email", sa.String(320), nullable=False, unique=True),
        sa.Column("name", sa.String(200)),
        sa.Column("password_hash", sa.String(255)),
        sa.Column("google_sub", sa.String(128), unique=True),
        sa.Column("org_id", postgresql.UUID(as_uuid=False), sa.ForeignKey("orgs.id", ondelete="CASCADE"), nullable=False),
        sa.Column("is_active", sa.Boolean, nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_users_email", "users", ["email"])
    op.create_table(
        "subscriptions",
        sa.Column("id", postgresql.UUID(as_uuid=False), primary_key=True),
        sa.Column("org_id", postgresql.UUID(as_uuid=False), sa.ForeignKey("orgs.id", ondelete="CASCADE"), nullable=False),
        sa.Column("stripe_sub_id", sa.String(64), nullable=False, unique=True),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("plan", sa.String(32), nullable=False),
        sa.Column("current_period_end", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_subscriptions_org_id", "subscriptions", ["org_id"])
    op.create_table(
        "targets",
        sa.Column("id", postgresql.UUID(as_uuid=False), primary_key=True),
        sa.Column("org_id", postgresql.UUID(as_uuid=False), sa.ForeignKey("orgs.id", ondelete="CASCADE"), nullable=False),
        sa.Column("user_id", postgresql.UUID(as_uuid=False), sa.ForeignKey("users.id", ondelete="SET NULL")),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("base_url", sa.String(2048), nullable=False),
        sa.Column("scope", postgresql.ARRAY(sa.String)),
        sa.Column("exclude_paths", postgresql.ARRAY(sa.String)),
        sa.Column("credentials_encrypted", sa.LargeBinary),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_targets_org_id", "targets", ["org_id"])
    op.create_table(
        "scans",
        sa.Column("id", postgresql.UUID(as_uuid=False), primary_key=True),
        sa.Column("target_id", postgresql.UUID(as_uuid=False), sa.ForeignKey("targets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("org_id", postgresql.UUID(as_uuid=False), sa.ForeignKey("orgs.id", ondelete="CASCADE"), nullable=False),
        sa.Column("user_id", postgresql.UUID(as_uuid=False), sa.ForeignKey("users.id", ondelete="SET NULL")),
        sa.Column("status", sa.String(32), nullable=False, server_default="queued"),
        sa.Column("profile", sa.String(32), nullable=False, server_default="standard"),
        sa.Column("pencheff_session_id", sa.String(64)),
        sa.Column("progress_pct", sa.Integer, nullable=False, server_default="0"),
        sa.Column("current_stage", sa.String(64)),
        sa.Column("summary", postgresql.JSONB),
        sa.Column("grade", sa.String(1)),
        sa.Column("score", sa.Integer),
        sa.Column("error", sa.Text),
        sa.Column("started_at", sa.DateTime(timezone=True)),
        sa.Column("finished_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_scans_target_id", "scans", ["target_id"])
    op.create_index("ix_scans_org_id", "scans", ["org_id"])
    op.create_index("ix_scans_status", "scans", ["status"])
    op.create_table(
        "findings",
        sa.Column("id", postgresql.UUID(as_uuid=False), primary_key=True),
        sa.Column("scan_id", postgresql.UUID(as_uuid=False), sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False),
        sa.Column("pencheff_finding_id", sa.String(64)),
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("category", sa.String(64), nullable=False),
        sa.Column("owasp_category", sa.String(32)),
        sa.Column("cwe_id", sa.String(32)),
        sa.Column("cvss_score", sa.Float),
        sa.Column("cvss_vector", sa.String(200)),
        sa.Column("endpoint", sa.String(2048)),
        sa.Column("parameter", sa.String(200)),
        sa.Column("description", sa.Text),
        sa.Column("remediation", sa.Text),
        sa.Column("evidence", postgresql.JSONB),
        sa.Column("references", postgresql.ARRAY(sa.String)),
        sa.Column("verification_status", sa.String(32), nullable=False, server_default="unverified"),
        sa.Column("suppressed", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("suppress_reason", sa.String(64)),
        sa.Column("suppress_notes", sa.Text),
        sa.Column("last_rechecked_at", sa.DateTime(timezone=True)),
        sa.Column("recheck_status", sa.String(32)),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_findings_scan_id", "findings", ["scan_id"])
    op.create_index("ix_findings_severity", "findings", ["severity"])
    op.create_index("ix_findings_scan_severity", "findings", ["scan_id", "severity"])
    op.create_table(
        "reports",
        sa.Column("id", postgresql.UUID(as_uuid=False), primary_key=True),
        sa.Column("scan_id", postgresql.UUID(as_uuid=False), sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False),
        sa.Column("format", sa.String(16), nullable=False),
        sa.Column("status", sa.String(32), nullable=False, server_default="pending"),
        sa.Column("storage_path", sa.String(1024)),
        sa.Column("bytes", sa.BigInteger),
        sa.Column("generated_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_reports_scan_id", "reports", ["scan_id"])
    op.create_table(
        "audit_logs",
        sa.Column("id", postgresql.UUID(as_uuid=False), primary_key=True),
        sa.Column("user_id", postgresql.UUID(as_uuid=False), sa.ForeignKey("users.id", ondelete="SET NULL")),
        sa.Column("org_id", postgresql.UUID(as_uuid=False), sa.ForeignKey("orgs.id", ondelete="SET NULL")),
        sa.Column("action", sa.String(64), nullable=False),
        sa.Column("entity_type", sa.String(64)),
        sa.Column("entity_id", sa.String(64)),
        sa.Column("meta", postgresql.JSONB),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )


def downgrade() -> None:
    op.drop_table("audit_logs")
    op.drop_table("reports")
    op.drop_table("findings")
    op.drop_table("scans")
    op.drop_table("targets")
    op.drop_table("subscriptions")
    op.drop_table("users")
    op.drop_table("orgs")
