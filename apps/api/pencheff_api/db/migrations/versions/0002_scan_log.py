"""Persist scan progress log

Adds a nullable JSONB ``log`` column to the ``scans`` table so that the
live progress stream can be rehydrated on page reload.

Revision ID: 0002
Revises: 0001
Create Date: 2026-04-18
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "0002"
down_revision: Union[str, None] = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "scans",
        sa.Column("log", postgresql.JSONB, nullable=True),
    )


def downgrade() -> None:
    op.drop_column("scans", "log")
