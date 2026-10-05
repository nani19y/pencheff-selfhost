"""Repos as first-class Targets — every Repository auto-mirrors as a Target.

Revision ID: 0019
Revises: 0018
Create Date: 2026-04-28

Adds ``targets.repository_id`` (FK → ``repositories.id``, ``ON DELETE
CASCADE``) so a Target can mirror a Repository. The Target is a passive
display row — repo-scans still flow through ``RepoScan`` / ``RepoFinding``.
This lets the integrations target multi-select, the Targets dashboard,
and any other consumer of ``GET /targets`` show repos alongside DAST URLs.

Backfill creates one mirror Target for every existing Repository that
doesn't already have one. The ``NOT EXISTS`` guard makes it idempotent
so re-running the migration (or re-applying after a manual partial run)
never duplicates rows.

Direction: Target → Repository, never the reverse. Deleting the Target
alone leaves the Repository intact (the source of truth for scanning
stays under ``/repos``).
"""
from typing import Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0019"
down_revision: Union[str, None] = "0018"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "targets",
        sa.Column(
            "repository_id",
            postgresql.UUID(as_uuid=False),
            sa.ForeignKey("repositories.id", ondelete="CASCADE"),
            nullable=True,
        ),
    )
    op.create_index(
        "ix_targets_repository_id",
        "targets",
        ["repository_id"],
        unique=False,
    )

    # Backfill: one mirror Target per Repository that doesn't already have
    # one. ``NOT EXISTS`` clamp keeps the migration idempotent.
    #
    # ``targets.id`` is a native PG ``uuid`` column. The ``UUID(as_uuid=False)``
    # in the model only changes the Python repr — the SQL column type is
    # still ``uuid``. So ``gen_random_uuid()`` returns the right type and
    # we must NOT cast it to ``text``: doing so trips
    # ``column "id" is of type uuid but expression is of type text``.
    op.execute(
        """
        INSERT INTO targets (
            id, org_id, workspace_id, name, base_url,
            repository_id, created_at
        )
        SELECT
            gen_random_uuid(),
            r.org_id,
            r.workspace_id,
            r.full_name,
            r.html_url,
            r.id,
            now()
        FROM repositories r
        WHERE NOT EXISTS (
            SELECT 1 FROM targets t WHERE t.repository_id = r.id
        )
        """
    )


def downgrade() -> None:
    # Drop the mirror Targets first so the FK can come off cleanly.
    # Plain DAST URL targets (repository_id IS NULL) are untouched.
    op.execute("DELETE FROM targets WHERE repository_id IS NOT NULL")
    op.drop_index("ix_targets_repository_id", table_name="targets")
    op.drop_column("targets", "repository_id")
