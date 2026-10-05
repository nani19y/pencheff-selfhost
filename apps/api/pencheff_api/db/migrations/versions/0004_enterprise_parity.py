"""Extended scanning tables: schedules, assets, integrations, SBOMs, deps, proxy sessions, collab.

Revision ID: 0004
Revises: 0003
Create Date: 2026-04-21
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0004"
down_revision: Union[str, None] = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # scan_schedules
    op.create_table(
        "scan_schedules",
        sa.Column("id", postgresql.UUID(as_uuid=False), primary_key=True),
        sa.Column("org_id", postgresql.UUID(as_uuid=False),
                  sa.ForeignKey("orgs.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("target_id", postgresql.UUID(as_uuid=False),
                  sa.ForeignKey("targets.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("owner_user_id", postgresql.UUID(as_uuid=False),
                  sa.ForeignKey("users.id", ondelete="SET NULL")),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("cron_expression", sa.String(128), nullable=False),
        sa.Column("profile", sa.String(64), nullable=False, server_default="standard"),
        sa.Column("policy_yaml", sa.Text),
        sa.Column("enabled", sa.Boolean, nullable=False, server_default=sa.text("true")),
        sa.Column("last_run_at", sa.DateTime(timezone=True)),
        sa.Column("next_run_at", sa.DateTime(timezone=True), index=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # assets
    op.create_table(
        "assets",
        sa.Column("id", postgresql.UUID(as_uuid=False), primary_key=True),
        sa.Column("org_id", postgresql.UUID(as_uuid=False),
                  sa.ForeignKey("orgs.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("type", sa.String(32), nullable=False),
        sa.Column("value", sa.String(2048), nullable=False),
        sa.Column("meta", postgresql.JSONB),
        sa.Column("first_seen", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("last_seen", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("org_id", "type", "value", name="uq_assets_org_type_value"),
    )
    op.create_index("ix_assets_org_type", "assets", ["org_id", "type"])

    # integrations
    op.create_table(
        "integrations",
        sa.Column("id", postgresql.UUID(as_uuid=False), primary_key=True),
        sa.Column("org_id", postgresql.UUID(as_uuid=False),
                  sa.ForeignKey("orgs.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("kind", sa.String(32), nullable=False),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("config_encrypted", sa.LargeBinary),
        sa.Column("enabled", sa.Boolean, nullable=False, server_default=sa.text("true")),
        sa.Column("severity_filter", sa.String(16), nullable=False, server_default="high"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # sboms
    op.create_table(
        "sboms",
        sa.Column("id", postgresql.UUID(as_uuid=False), primary_key=True),
        sa.Column("scan_id", postgresql.UUID(as_uuid=False),
                  sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("format", sa.String(32), nullable=False),
        sa.Column("content", postgresql.JSONB),
        sa.Column("component_count", sa.Integer),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # dependencies
    op.create_table(
        "dependencies",
        sa.Column("id", postgresql.UUID(as_uuid=False), primary_key=True),
        sa.Column("scan_id", postgresql.UUID(as_uuid=False),
                  sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("ecosystem", sa.String(32), nullable=False),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("version", sa.String(64), nullable=False),
        sa.Column("license", sa.String(128)),
        sa.Column("scope", sa.String(16), nullable=False, server_default="runtime"),
        sa.Column("vulnerabilities", postgresql.JSONB),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # proxy_sessions
    op.create_table(
        "proxy_sessions",
        sa.Column("id", postgresql.UUID(as_uuid=False), primary_key=True),
        sa.Column("scan_id", postgresql.UUID(as_uuid=False),
                  sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("port", sa.Integer, nullable=False),
        sa.Column("mode", sa.String(32), nullable=False, server_default="mitmproxy"),
        sa.Column("request_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("started_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("stopped_at", sa.DateTime(timezone=True)),
    )

    # finding_comments
    op.create_table(
        "finding_comments",
        sa.Column("id", postgresql.UUID(as_uuid=False), primary_key=True),
        sa.Column("finding_id", postgresql.UUID(as_uuid=False),
                  sa.ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("user_id", postgresql.UUID(as_uuid=False),
                  sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("body", sa.Text, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # finding_assignments
    op.create_table(
        "finding_assignments",
        sa.Column("finding_id", postgresql.UUID(as_uuid=False),
                  sa.ForeignKey("findings.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("assignee_user_id", postgresql.UUID(as_uuid=False),
                  sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("assigner_user_id", postgresql.UUID(as_uuid=False),
                  sa.ForeignKey("users.id", ondelete="SET NULL")),
        sa.Column("assigned_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # finding_tags
    op.create_table(
        "finding_tags",
        sa.Column("finding_id", postgresql.UUID(as_uuid=False),
                  sa.ForeignKey("findings.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("tag", sa.String(64), primary_key=True),
    )

    # Finding SLA + EPSS/KEV risk columns
    op.add_column("findings", sa.Column("sla_days", sa.Integer))
    op.add_column("findings", sa.Column("due_date", sa.DateTime(timezone=True)))
    op.add_column("findings", sa.Column("resolved_at", sa.DateTime(timezone=True)))
    op.add_column("findings", sa.Column("sla_breached", sa.Boolean, nullable=False, server_default=sa.text("false")))
    op.add_column("findings", sa.Column("epss", sa.Float))
    op.add_column("findings", sa.Column("kev", sa.Boolean, nullable=False, server_default=sa.text("false")))
    op.add_column("findings", sa.Column("risk_score", sa.Float))


def downgrade() -> None:
    for col in ("risk_score", "kev", "epss", "sla_breached", "resolved_at", "due_date", "sla_days"):
        op.drop_column("findings", col)
    op.drop_table("finding_tags")
    op.drop_table("finding_assignments")
    op.drop_table("finding_comments")
    op.drop_table("proxy_sessions")
    op.drop_table("dependencies")
    op.drop_table("sboms")
    op.drop_table("integrations")
    op.drop_index("ix_assets_org_type", table_name="assets")
    op.drop_table("assets")
    op.drop_table("scan_schedules")
