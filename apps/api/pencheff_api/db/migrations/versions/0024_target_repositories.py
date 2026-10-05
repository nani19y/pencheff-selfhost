"""Many-to-many: URL targets can have multiple attached repositories.

Revision ID: 0024
Revises: 0023
Create Date: 2026-05-01

Adds the ``target_repositories`` join table so a single URL Target may
declare multiple attached Repositories for SAST coverage. The pencheff
plugin already supports per-session multi-repo attachment; this table is
how the UI / API persists that selection per Target so the scan worker
can hydrate the list when a scan starts.

  * ``ON DELETE CASCADE`` on ``target_id`` — removing a target cleans
    up its associations automatically.
  * ``ON DELETE RESTRICT`` on ``repository_id`` — repos that are attached
    to one or more URL targets cannot be deleted; the API enforces this
    too with a friendlier error message, but the FK is the safety net.
  * Composite primary key ``(target_id, repository_id)`` rules out
    duplicate associations.
"""
from typing import Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0024"
down_revision: Union[str, None] = "0023"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "target_repositories",
        sa.Column(
            "target_id",
            postgresql.UUID(as_uuid=False),
            sa.ForeignKey("targets.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "repository_id",
            postgresql.UUID(as_uuid=False),
            sa.ForeignKey("repositories.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint(
            "target_id", "repository_id", name="pk_target_repositories"
        ),
    )
    # Reverse-direction lookup: "which targets is this repo attached to?"
    # — used to block repo deletion and to surface usage in the repos page.
    op.create_index(
        "ix_target_repositories_repository_id",
        "target_repositories",
        ["repository_id"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_target_repositories_repository_id",
        table_name="target_repositories",
    )
    op.drop_table("target_repositories")
