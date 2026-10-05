"""security lake audit tables

Revision ID: 0054
Revises: 0053
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0054"
down_revision = "0053"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "lake_ingestion",
        sa.Column("id", postgresql.UUID(as_uuid=False), primary_key=True),
        sa.Column("scan_id", sa.String(64), nullable=False),
        sa.Column("source", sa.String(16), nullable=False),
        sa.Column("org_id", postgresql.UUID(as_uuid=False), nullable=True),
        sa.Column("appended_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("quarantined_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("status", sa.String(16), nullable=False, server_default="ok"),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("scan_id", "source", name="uq_lake_ingestion_scan_source"),
    )
    op.create_table(
        "lake_quarantine",
        sa.Column("id", postgresql.UUID(as_uuid=False), primary_key=True),
        sa.Column("scan_id", sa.String(64), nullable=False),
        sa.Column("source", sa.String(16), nullable=False),
        sa.Column("org_id", postgresql.UUID(as_uuid=False), nullable=True),
        sa.Column("error", sa.Text(), nullable=False),
        sa.Column("finding_repr", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_lake_quarantine_scan_id", "lake_quarantine", ["scan_id"])


def downgrade() -> None:
    op.drop_index("ix_lake_quarantine_scan_id", table_name="lake_quarantine")
    op.drop_table("lake_quarantine")
    op.drop_table("lake_ingestion")
