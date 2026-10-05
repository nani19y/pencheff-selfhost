"""Engagement notes + traffic retention.

Revision ID: 0012
Revises: 0011
Create Date: 2026-04-26
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0012"
down_revision: Union[str, None] = "0011"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "engagement_notes",
        sa.Column("id", postgresql.UUID(as_uuid=False), primary_key=True),
        sa.Column("engagement_id", postgresql.UUID(as_uuid=False),
                  sa.ForeignKey("engagements.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("kind", sa.String(32), nullable=False, server_default="general"),
        sa.Column("target_kind", sa.String(32), nullable=True),
        sa.Column("target_id", sa.String(64), nullable=True),
        sa.Column("body_md", sa.Text, nullable=False, server_default=""),
        sa.Column("pinned", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("created_by_user_id", postgresql.UUID(as_uuid=False),
                  sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.execute(
        """
        ALTER TABLE engagement_notes
        ADD COLUMN fts_doc tsvector
        GENERATED ALWAYS AS (
            to_tsvector('simple', coalesce(body_md, ''))
        ) STORED
        """
    )
    op.create_index(
        "ix_engagement_notes_fts", "engagement_notes", ["fts_doc"], postgresql_using="gin"
    )

    # WS frame capture for proxied target-app WebSockets.
    op.add_column(
        "proxy_traffic",
        sa.Column("ws_frames", postgresql.JSONB, nullable=True),
    )


def downgrade() -> None:
    op.drop_column("proxy_traffic", "ws_frames")
    op.drop_index("ix_engagement_notes_fts", table_name="engagement_notes")
    op.drop_table("engagement_notes")
