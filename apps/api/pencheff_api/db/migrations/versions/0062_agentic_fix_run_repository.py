"""Agentic fix run attached repository.

Revision ID: 0062
Revises: 0061
Create Date: 2026-06-21

Scan-scoped agentic fixes need to know which source repository attached to
the target should be cloned by the worker. Repo-scan runs keep using
``repo_scan_id``; this nullable pointer is only populated for ``scan_id`` runs.
"""
from __future__ import annotations

from typing import Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql


revision: str = "0062"
down_revision: Union[str, None] = "0061"
branch_labels: Union[str, tuple, None] = None
depends_on: Union[str, tuple, None] = None


def upgrade() -> None:
    op.add_column(
        "agentic_fix_runs",
        sa.Column("repository_id", postgresql.UUID(as_uuid=False), nullable=True),
    )
    op.create_foreign_key(
        "fk_agentic_fix_runs_repository_id",
        "agentic_fix_runs",
        "repositories",
        ["repository_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_index(
        "ix_agentic_fix_runs_repository_id",
        "agentic_fix_runs",
        ["repository_id"],
    )


def downgrade() -> None:
    op.drop_index("ix_agentic_fix_runs_repository_id", table_name="agentic_fix_runs")
    op.drop_constraint(
        "fk_agentic_fix_runs_repository_id",
        "agentic_fix_runs",
        type_="foreignkey",
    )
    op.drop_column("agentic_fix_runs", "repository_id")
