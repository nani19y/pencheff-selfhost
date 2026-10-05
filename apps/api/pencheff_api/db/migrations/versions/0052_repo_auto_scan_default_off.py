"""Flip Repository.auto_scan_on_push to default OFF + disable existing rows.

Revision ID: 0052
Revises: 0051
Create Date: 2026-06-07

auto_scan_on_push originally defaulted to true (migration 0006). With GitHub
App push webhooks now enabled, that means every connected repo would scan on
every default-branch push. We make it opt-in instead:

  - server_default → false  (new DB-level inserts)
  - existing rows  → false  (so already-synced repos don't surprise-scan;
                             the per-repo toggle was UI-disabled for App repos
                             and inert for public/PAT repos, so no repo was
                             intentionally on)

The model-level default also changes to False, which governs the four ORM
insert sites (webhook sync, manual sync, local + public-URL register).
"""
from __future__ import annotations

from typing import Union

import sqlalchemy as sa
from alembic import op


revision: str = "0052"
down_revision: Union[str, None] = "0051"
branch_labels: Union[str, tuple, None] = None
depends_on: Union[str, tuple, None] = None


def upgrade() -> None:
    op.alter_column(
        "repositories",
        "auto_scan_on_push",
        server_default=sa.false(),
        existing_type=sa.Boolean(),
        existing_nullable=False,
    )
    op.execute("UPDATE repositories SET auto_scan_on_push = false")


def downgrade() -> None:
    op.alter_column(
        "repositories",
        "auto_scan_on_push",
        server_default=sa.true(),
        existing_type=sa.Boolean(),
        existing_nullable=False,
    )
