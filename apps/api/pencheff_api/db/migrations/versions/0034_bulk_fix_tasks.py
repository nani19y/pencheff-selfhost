"""Bulk-fix-all task tracking table.

Revision ID: 0034
Revises: 0033
Create Date: 2026-05-03

The ``POST /scans/{id}/fix-all`` and ``POST /repo-scans/{id}/fix-all``
endpoints used to run synchronously, processing every finding inline
on the request thread. For batches of more than ~5 findings this
exceeded reverse-proxy timeouts (Cloudflare Free's 100s in particular)
and surfaced as an opaque 500 even though the API was still working.

This table backs the new async pattern:

  1. ``POST .../fix-all`` inserts a row here, enqueues a Celery task,
     and returns ``202 Accepted`` with the row's ``id``.
  2. The worker processes findings, updating ``completed_findings``
     periodically and writing the final ``results`` JSON when done.
  3. The frontend polls ``GET /fix-tasks/{id}`` until ``status`` is
     ``completed`` or ``failed``.

``results`` mirrors the old synchronous ``BulkFixSummary`` shape so
the UI rendering code stays unchanged once the task completes.
"""
from typing import Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql


revision: str = "0034"
down_revision: Union[str, None] = "0033"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "bulk_fix_tasks",
        sa.Column("id", postgresql.UUID(as_uuid=False),
                  primary_key=True, nullable=False),
        sa.Column("org_id", postgresql.UUID(as_uuid=False), nullable=False),
        sa.Column("workspace_id", postgresql.UUID(as_uuid=False), nullable=False),
        sa.Column("user_id", postgresql.UUID(as_uuid=False), nullable=False),
        # Exactly one of these is non-null. A CHECK constraint would be
        # nicer than a runtime guard but it complicates fixture seeding;
        # the router enforces the invariant at write time.
        sa.Column("scan_id", postgresql.UUID(as_uuid=False), nullable=True),
        sa.Column("repo_scan_id", postgresql.UUID(as_uuid=False), nullable=True),
        sa.Column("status", sa.String(16), nullable=False,
                  server_default="queued"),
        sa.Column("total_findings", sa.Integer, nullable=False,
                  server_default="0"),
        sa.Column("completed_findings", sa.Integer, nullable=False,
                  server_default="0"),
        # ``results`` mirrors BulkFixSummary on success / partial-success.
        # ``error`` is set when the task itself crashed (not when individual
        # findings failed — those are recorded in results).
        sa.Column("results", postgresql.JSONB, nullable=True),
        sa.Column("error", sa.Text, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index(
        "bulk_fix_tasks_org_created_idx",
        "bulk_fix_tasks",
        ["org_id", sa.text("created_at DESC")],
    )


def downgrade() -> None:
    op.drop_index("bulk_fix_tasks_org_created_idx",
                  table_name="bulk_fix_tasks")
    op.drop_table("bulk_fix_tasks")
