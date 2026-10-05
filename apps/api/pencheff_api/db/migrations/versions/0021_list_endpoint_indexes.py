"""List-endpoint composite indexes for targets + scans.

Revision ID: 0021
Revises: 0020
Create Date: 2026-04-28

Adds three composite indexes to make the hot list endpoints
(/targets, /scans, /scans?target_id=…) index-only scans instead of
heap scan + in-memory sort. Each handler does
``WHERE workspace_id = ? ORDER BY created_at DESC`` (or
``WHERE target_id = ? ORDER BY created_at DESC``); without these
indexes Postgres falls back to the single-column workspace_id /
target_id index and then sorts the matched rows by created_at, which
is what was costing the dashboard 1–2s on workspaces with a few
hundred scans.

Indexes:
  - ``ix_targets_workspace_created`` on targets(workspace_id, created_at)
  - ``ix_scans_workspace_created``   on scans(workspace_id, created_at)
  - ``ix_scans_target_created``      on scans(target_id, created_at)

CONCURRENTLY is intentionally NOT used — the migration runs at
container startup before uvicorn boots, so a brief table-lock is
acceptable and keeps the migration transactional. If you run this
against a busy production DB out-of-band, prefer a manual
``CREATE INDEX CONCURRENTLY`` and then ``alembic stamp 0021``.
"""
from typing import Union

from alembic import op

revision: str = "0021"
down_revision: Union[str, None] = "0020"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_index(
        "ix_targets_workspace_created",
        "targets",
        ["workspace_id", "created_at"],
    )
    op.create_index(
        "ix_scans_workspace_created",
        "scans",
        ["workspace_id", "created_at"],
    )
    op.create_index(
        "ix_scans_target_created",
        "scans",
        ["target_id", "created_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_scans_target_created", table_name="scans")
    op.drop_index("ix_scans_workspace_created", table_name="scans")
    op.drop_index("ix_targets_workspace_created", table_name="targets")
