"""Ephemeral local repos: upload-scan-discard flow.

Revision ID: 0015
Revises: 0014
Create Date: 2026-04-26

Adds:
  * ``repositories.ephemeral`` — true when the repo was created from a
    one-shot upload through ``POST /repos/scan-upload``. The scan task
    cleans up the on-disk extraction dir + sets ``removed_at`` on
    completion (success or failure), so the repo disappears from the
    listing automatically while the scan + findings remain queryable.
  * ``repositories.removed_at`` — soft-delete marker. The repos listing
    endpoint filters ``removed_at IS NULL``. Hard delete still works,
    but deleting the row also cascades to RepoScans + RepoFindings; the
    soft-remove keeps the audit trail.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0015"
down_revision: Union[str, None] = "0014"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "repositories",
        sa.Column("ephemeral", sa.Boolean, nullable=False, server_default=sa.false()),
    )
    op.add_column(
        "repositories",
        sa.Column("removed_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index(
        "ix_repositories_active",
        "repositories",
        ["workspace_id"],
        postgresql_where=sa.text("removed_at IS NULL"),
    )


def downgrade() -> None:
    op.drop_index("ix_repositories_active", table_name="repositories")
    op.drop_column("repositories", "removed_at")
    op.drop_column("repositories", "ephemeral")
