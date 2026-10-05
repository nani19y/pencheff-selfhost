"""repo_findings: add suppress_reason + suppress_notes (AI false-positive triage)

Revision ID: 0057
Revises: 0056
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0057"
down_revision = "0056"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("repo_findings", sa.Column("suppress_reason", sa.String(64), nullable=True))
    op.add_column("repo_findings", sa.Column("suppress_notes", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column("repo_findings", "suppress_notes")
    op.drop_column("repo_findings", "suppress_reason")
