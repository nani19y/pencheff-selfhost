"""Reserved revision — no-op chain stub.

Revision ID: 0031
Revises: 0030
Create Date: 2026-05-02

This revision originally created the ``llm_campaigns`` and
``llm_campaign_runs`` tables (Phase 2.7 closeout). Withdrawn before
production. See [0029_reserved.py](0029_reserved.py) and
[0032_drop_unused_tables.py](0032_drop_unused_tables.py).
"""
from typing import Union


revision: str = "0031"
down_revision: Union[str, None] = "0030"
branch_labels = None
depends_on = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
