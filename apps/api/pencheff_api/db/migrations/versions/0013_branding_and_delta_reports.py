"""Workspace branding + report.kind / engagement / compared_scan.

Revision ID: 0013
Revises: 0012
Create Date: 2026-04-26
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0013"
down_revision: Union[str, None] = "0012"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "workspace_branding",
        sa.Column("id", postgresql.UUID(as_uuid=False), primary_key=True),
        sa.Column("workspace_id", postgresql.UUID(as_uuid=False),
                  sa.ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False, unique=True),
        sa.Column("logo_url", sa.String(2048), nullable=True),
        sa.Column("primary_color", sa.String(16), nullable=True),
        sa.Column("secondary_color", sa.String(16), nullable=True),
        sa.Column("opening_letter_md", sa.Text, nullable=True),
        sa.Column("methodology_md", sa.Text, nullable=True),
        sa.Column("footer_text", sa.String(500), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )

    op.add_column(
        "reports",
        sa.Column("kind", sa.String(32), nullable=False, server_default="point_in_time"),
    )
    op.add_column(
        "reports",
        sa.Column(
            "engagement_id",
            postgresql.UUID(as_uuid=False),
            sa.ForeignKey("engagements.id", ondelete="SET NULL"),
            nullable=True,
        ),
    )
    op.add_column(
        "reports",
        sa.Column(
            "compared_scan_id",
            postgresql.UUID(as_uuid=False),
            sa.ForeignKey("scans.id", ondelete="SET NULL"),
            nullable=True,
        ),
    )
    op.create_index("ix_reports_engagement", "reports", ["engagement_id"])


def downgrade() -> None:
    op.drop_index("ix_reports_engagement", table_name="reports")
    op.drop_column("reports", "compared_scan_id")
    op.drop_column("reports", "engagement_id")
    op.drop_column("reports", "kind")
    op.drop_table("workspace_branding")
