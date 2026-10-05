"""Drop ephemeral repos: simplify to GitHub + local-folder only.

Revision ID: 0016
Revises: 0015
Create Date: 2026-04-26

Removes the one-shot upload-and-discard flow. Both connect paths are now
persistent: GitHub repos (App-installed or public-URL) and local folders
stay in the table until the user deletes them. The ``ephemeral`` and
``removed_at`` columns + the ``ix_repositories_active`` partial index go
away with this migration.

Any leftover ephemeral rows are dropped first so the column removals
don't leave orphan findings.
"""
from typing import Union

import sqlalchemy as sa
from alembic import op

revision: str = "0016"
down_revision: Union[str, None] = "0015"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("DELETE FROM repositories WHERE ephemeral = TRUE")
    op.drop_index("ix_repositories_active", table_name="repositories")
    op.drop_column("repositories", "removed_at")
    op.drop_column("repositories", "ephemeral")


def downgrade() -> None:
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
