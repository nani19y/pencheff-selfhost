"""Per-org counter for combined deterministic+autonomous scans.

Revision ID: 0035
Revises: 0034
Create Date: 2026-05-04

Free-plan orgs get a fixed quota of combined-mode scans (configured via
``FREE_PLAN_OPTION_3_QUOTA``). Once exhausted, ``services/dispatch_mode.py``
downgrades them to the autonomous-only path. The counter lives on the
org row so it survives across workspaces and scans.
"""
from typing import Union

import sqlalchemy as sa
from alembic import op


revision: str = "0035"
down_revision: Union[str, None] = "0034"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "orgs",
        sa.Column(
            "option_3_scans_used",
            sa.Integer,
            nullable=False,
            server_default="0",
        ),
    )


def downgrade() -> None:
    op.drop_column("orgs", "option_3_scans_used")
