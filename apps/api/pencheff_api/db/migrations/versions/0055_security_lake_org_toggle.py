"""security lake per-org enable/disable toggle

Revision ID: 0055
Revises: 0054
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0055"
down_revision = "0054"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("orgs", sa.Column(
        "security_lake_enabled", sa.Boolean(), nullable=False, server_default="false"))
    op.add_column("orgs", sa.Column(
        "security_lake_disabled_at", sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    op.drop_column("orgs", "security_lake_disabled_at")
    op.drop_column("orgs", "security_lake_enabled")
