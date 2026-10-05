"""Reserved revision — no-op chain stub.

Revision ID: 0030
Revises: 0029
Create Date: 2026-05-02

This revision originally created the ``attack_surface_snapshots`` table
(Phase 4.14, CTEM). Withdrawn before production. See
[0029_reserved.py](0029_reserved.py) and
[0032_drop_unused_tables.py](0032_drop_unused_tables.py).
"""
from typing import Union


revision: str = "0030"
down_revision: Union[str, None] = "0029"
branch_labels = None
depends_on = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
