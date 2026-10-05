"""Repository SBOMs.

Revision ID: 0038
Revises: 0037
Create Date: 2026-05-06
"""

from typing import Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0038"
down_revision: Union[str, None] = "0037"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "repo_sboms",
        sa.Column("id", postgresql.UUID(as_uuid=False), primary_key=True),
        sa.Column(
            "repository_id",
            postgresql.UUID(as_uuid=False),
            sa.ForeignKey("repositories.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("commit_sha", sa.String(64)),
        sa.Column("format", sa.String(32), nullable=False),
        sa.Column("content", postgresql.JSONB),
        sa.Column("component_count", sa.Integer),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_repo_sboms_repo_created", "repo_sboms", ["repository_id", "created_at"])


def downgrade() -> None:
    op.drop_index("ix_repo_sboms_repo_created", table_name="repo_sboms")
    op.drop_table("repo_sboms")

