"""Browser-extension proxy ingest tables.

Revision ID: 0008
Revises: 0007
Create Date: 2026-04-26

Adds:
  * ``proxy_traffic`` — captured request/response flows from the browser
    extension (and, in time, mitmproxy + replay) with a generated ``fts_doc``
    tsvector for full-text search across url + bodies.
  * ``engagement_ingest_tokens`` — per-engagement bearer tokens the
    extension presents on every batch upload. Stored hashed.

The new ``engagement_id`` FK is left nullable here. The companion migration
0009 introduces the ``engagements`` table proper. Until then, traffic can
still land scoped to a workspace and be re-linked later.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0008"
down_revision: Union[str, None] = "0007"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "proxy_traffic",
        sa.Column("id", postgresql.UUID(as_uuid=False), primary_key=True),
        sa.Column("engagement_id", postgresql.UUID(as_uuid=False), nullable=True, index=True),
        sa.Column("proxy_session_id", postgresql.UUID(as_uuid=False),
                  sa.ForeignKey("proxy_sessions.id", ondelete="SET NULL"), nullable=True),
        sa.Column("workspace_id", postgresql.UUID(as_uuid=False),
                  sa.ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False),
        sa.Column("captured_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("source", sa.String(32), nullable=False, server_default="extension"),
        sa.Column("method", sa.String(16), nullable=False),
        sa.Column("url", sa.Text, nullable=False),
        sa.Column("host", sa.String(512), nullable=False),
        sa.Column("path", sa.Text, nullable=False, server_default=""),
        sa.Column("query", postgresql.JSONB, nullable=True),
        sa.Column("request_headers", postgresql.JSONB, nullable=True),
        sa.Column("request_body", sa.Text, nullable=True),
        sa.Column("request_body_truncated", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("response_status", sa.Integer, nullable=True),
        sa.Column("response_headers", postgresql.JSONB, nullable=True),
        sa.Column("response_body", sa.Text, nullable=True),
        sa.Column("response_body_truncated", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("response_size", sa.BigInteger, nullable=True),
        sa.Column("duration_ms", sa.Integer, nullable=True),
        sa.Column("tab_id", sa.Integer, nullable=True),
        sa.Column("frame_id", sa.Integer, nullable=True),
        sa.Column("initiator", sa.String(2048), nullable=True),
        sa.Column("body_capture", sa.String(16), nullable=False, server_default="full"),
        sa.Column("is_starred", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("tags", postgresql.ARRAY(sa.String), nullable=True),
        sa.Column("notes", sa.Text, nullable=True),
    )

    # Generated tsvector for FTS — combines url + request body + response body.
    op.execute(
        """
        ALTER TABLE proxy_traffic
        ADD COLUMN fts_doc tsvector
        GENERATED ALWAYS AS (
            setweight(to_tsvector('simple', coalesce(url, '')), 'A') ||
            setweight(to_tsvector('simple', coalesce(request_body, '')), 'C') ||
            setweight(to_tsvector('simple', coalesce(response_body, '')), 'C')
        ) STORED
        """
    )
    op.create_index(
        "ix_proxy_traffic_fts", "proxy_traffic", ["fts_doc"], postgresql_using="gin"
    )
    op.create_index(
        "ix_proxy_traffic_workspace_captured",
        "proxy_traffic", ["workspace_id", sa.text("captured_at DESC")],
    )
    op.create_index(
        "ix_proxy_traffic_engagement_captured",
        "proxy_traffic", ["engagement_id", sa.text("captured_at DESC")],
    )
    op.create_index("ix_proxy_traffic_host", "proxy_traffic", ["host"])

    op.create_table(
        "engagement_ingest_tokens",
        sa.Column("id", postgresql.UUID(as_uuid=False), primary_key=True),
        sa.Column("engagement_id", postgresql.UUID(as_uuid=False), nullable=False, index=True),
        sa.Column("workspace_id", postgresql.UUID(as_uuid=False),
                  sa.ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("token_hash", sa.String(128), unique=True, nullable=False),
        sa.Column("pairing_code", sa.String(32), unique=True, nullable=True),
        sa.Column("created_by_user_id", postgresql.UUID(as_uuid=False),
                  sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("engagement_ingest_tokens")
    op.drop_index("ix_proxy_traffic_host", table_name="proxy_traffic")
    op.drop_index("ix_proxy_traffic_engagement_captured", table_name="proxy_traffic")
    op.drop_index("ix_proxy_traffic_workspace_captured", table_name="proxy_traffic")
    op.drop_index("ix_proxy_traffic_fts", table_name="proxy_traffic")
    op.drop_table("proxy_traffic")
