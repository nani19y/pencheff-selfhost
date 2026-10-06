"""Persist the finding subset selected for an agentic fix run.

Revision ID: 0072
Revises: 0071
"""
from typing import Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql


revision: str = "0072"
down_revision: Union[str, None] = "0071"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "agentic_fix_runs",
        sa.Column("selected_finding_ids", postgresql.JSONB(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("agentic_fix_runs", "selected_finding_ids")
