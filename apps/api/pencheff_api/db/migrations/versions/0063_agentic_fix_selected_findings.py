"""Persist the finding subset selected for an agentic fix run.

Revision ID: 0063
Revises: 0062
"""
from typing import Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql


revision: str = "0063"
down_revision: Union[str, None] = "0062"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "agentic_fix_runs",
        sa.Column("selected_finding_ids", postgresql.JSONB(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("agentic_fix_runs", "selected_finding_ids")
