"""Add Scan.use_ai — operator AI toggle chosen at commission time.

Revision ID: 0051
Revises: 0050
Create Date: 2026-05-29

When False the scan runner forces deterministic-only mode (no agent/swarm,
no AI triage, no AI grading) regardless of plan. Default = true so every
existing scan keeps its current implicit behaviour.
"""
from __future__ import annotations

from typing import Union

import sqlalchemy as sa
from alembic import op


revision: str = "0051"
down_revision: Union[str, None] = "0050"
branch_labels: Union[str, tuple, None] = None
depends_on: Union[str, tuple, None] = None


def upgrade() -> None:
    op.add_column(
        "scans",
        sa.Column(
            "use_ai",
            sa.Boolean(),
            nullable=False,
            server_default=sa.true(),
        ),
    )


def downgrade() -> None:
    op.drop_column("scans", "use_ai")
