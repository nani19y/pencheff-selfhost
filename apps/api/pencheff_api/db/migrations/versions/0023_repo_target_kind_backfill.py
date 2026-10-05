"""Backfill repository target kind.

Revision ID: 0023
Revises: 0022
Create Date: 2026-04-29

Repository mirror targets must serialize and behave as kind='repo'. A bug in
the runtime mirror creation path left newly-created mirror rows with the model
default kind='url' after migration 0022. This backfills those rows.
"""
from typing import Union

from alembic import op

revision: str = "0023"
down_revision: Union[str, None] = "0022"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        "UPDATE targets SET kind = 'repo' "
        "WHERE repository_id IS NOT NULL AND kind <> 'repo'"
    )


def downgrade() -> None:
    # Data correction only. Do not intentionally reintroduce stale kinds.
    pass
