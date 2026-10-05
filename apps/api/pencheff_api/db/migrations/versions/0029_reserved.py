"""Reserved revision — no-op chain stub.

Revision ID: 0029
Revises: 0028
Create Date: 2026-05-02

This revision originally created the ``ptaas_requests`` table (Phase
4.13). That feature was withdrawn before any production deploy reached
this revision cleanly — but some development environments DID advance
their ``alembic_version`` row to 0029 (or higher) before the rollback
landed.

The revision id is preserved as a no-op so that alembic can resolve
its chain on those environments. The actual cleanup — dropping any
tables that may have been partially created — happens in
[0032_drop_unused_tables.py](0032_drop_unused_tables.py).

Fresh deployments walk through this stub harmlessly.
"""
from typing import Union


revision: str = "0029"
down_revision: Union[str, None] = "0028"
branch_labels = None
depends_on = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
