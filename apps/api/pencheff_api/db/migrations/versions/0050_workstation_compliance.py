"""Workstation Compliance.

Revision ID: 0050
Revises: 0049
Create Date: 2026-05-24
"""
from __future__ import annotations

from typing import Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql


revision: str = "0050"
down_revision: Union[str, None] = "0049"
branch_labels: Union[str, tuple, None] = None
depends_on: Union[str, tuple, None] = None


def upgrade() -> None:
    op.create_table(
        "workstation_compliance",
        sa.Column("id", postgresql.UUID(as_uuid=False), primary_key=True),
        sa.Column("org_id", postgresql.UUID(as_uuid=False), sa.ForeignKey("orgs.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("workspace_id", postgresql.UUID(as_uuid=False), sa.ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("user_id", postgresql.UUID(as_uuid=False), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, unique=True, index=True),
        sa.Column("studio_installed", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("monitors_enabled", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("overall_device_score", sa.Integer(), nullable=False, server_default="100"),
        sa.Column("overall_file_status", sa.String(32), nullable=False, server_default="Clean"),
        sa.Column("device_checks_json", postgresql.JSONB, nullable=True),
        sa.Column("file_checks_json", postgresql.JSONB, nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )


def downgrade() -> None:
    op.drop_table("workstation_compliance")
