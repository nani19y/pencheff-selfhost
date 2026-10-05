"""Local repos: optional integration + local_path column.

Revision ID: 0014
Revises: 0013
Create Date: 2026-04-26

A "repo" no longer has to come from a GitHub installation. The user can
register a directory on the worker's filesystem; subsequent scans skip the
GitHub clone path and run scanners directly against ``local_path``. Same
``RepoScan`` / ``RepoFinding`` infrastructure, no parallel pipeline.

Schema impact is small:
  * ``repositories.integration_id`` becomes nullable (local repos have no
    GitHub install).
  * New ``repositories.local_path`` (text, nullable).
  * Existing ``repositories.provider`` defaults to ``"github"`` already and
    accepts ``"local"`` after this migration. No enum change needed.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0014"
down_revision: Union[str, None] = "0013"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.alter_column("repositories", "integration_id", nullable=True)
    op.add_column("repositories", sa.Column("local_path", sa.Text, nullable=True))


def downgrade() -> None:
    # NOTE: any local rows (integration_id IS NULL) must be deleted before
    # tightening the column back, or the alter will fail.
    op.execute("DELETE FROM repositories WHERE integration_id IS NULL")
    op.drop_column("repositories", "local_path")
    op.alter_column("repositories", "integration_id", nullable=False)
