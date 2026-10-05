"""Add Org.allow_private_targets — RFC1918 opt-in gate for host-kind targets.

Revision ID: 0047
Revises: 0046
Create Date: 2026-05-17

Sub-project A of the Mythos-style OS exploit ladder. Default = false: every
existing org gets the conservative "no private hosts" policy. Admins opt in
through routers/orgs.py with a stronger disclosure (see spec §4).
"""
from __future__ import annotations

from typing import Union

import sqlalchemy as sa
from alembic import op


revision: str = "0047"
down_revision: Union[str, None] = "0046"
branch_labels: Union[str, tuple, None] = None
depends_on: Union[str, tuple, None] = None


def upgrade() -> None:
    op.add_column(
        "orgs",
        sa.Column(
            "allow_private_targets",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
    )


def downgrade() -> None:
    op.drop_column("orgs", "allow_private_targets")
