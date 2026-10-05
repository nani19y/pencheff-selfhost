"""Repeater + Intruder primitives.

Revision ID: 0010
Revises: 0009
Create Date: 2026-04-26
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0010"
down_revision: Union[str, None] = "0009"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "repeater_tabs",
        sa.Column("id", postgresql.UUID(as_uuid=False), primary_key=True),
        sa.Column("engagement_id", postgresql.UUID(as_uuid=False),
                  sa.ForeignKey("engagements.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("workspace_id", postgresql.UUID(as_uuid=False),
                  sa.ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("name", sa.String(200), nullable=False, server_default="Untitled"),
        sa.Column("request_method", sa.String(16), nullable=False, server_default="GET"),
        sa.Column("request_url", sa.Text, nullable=False),
        sa.Column("request_headers", postgresql.JSONB, nullable=True),
        sa.Column("request_body", sa.Text, nullable=True),
        sa.Column("pinned", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("notes", sa.Text, nullable=True),
        sa.Column("source_traffic_id", postgresql.UUID(as_uuid=False),
                  sa.ForeignKey("proxy_traffic.id", ondelete="SET NULL"), nullable=True),
        sa.Column("created_by_user_id", postgresql.UUID(as_uuid=False),
                  sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )

    op.create_table(
        "repeater_responses",
        sa.Column("id", postgresql.UUID(as_uuid=False), primary_key=True),
        sa.Column("tab_id", postgresql.UUID(as_uuid=False),
                  sa.ForeignKey("repeater_tabs.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("sent_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("request_snapshot", postgresql.JSONB, nullable=False),
        sa.Column("response_status", sa.Integer, nullable=True),
        sa.Column("response_headers", postgresql.JSONB, nullable=True),
        sa.Column("response_body", sa.Text, nullable=True),
        sa.Column("duration_ms", sa.Integer, nullable=True),
        sa.Column("sent_by_user_id", postgresql.UUID(as_uuid=False),
                  sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
    )

    op.create_table(
        "intruder_payload_sets",
        sa.Column("id", postgresql.UUID(as_uuid=False), primary_key=True),
        sa.Column("workspace_id", postgresql.UUID(as_uuid=False),
                  sa.ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("kind", sa.String(32), nullable=False, server_default="wordlist"),
        sa.Column("source", sa.Text, nullable=True),
        sa.Column("entries", postgresql.JSONB, nullable=True),
        sa.Column("entries_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )

    op.create_table(
        "intruder_attacks",
        sa.Column("id", postgresql.UUID(as_uuid=False), primary_key=True),
        sa.Column("engagement_id", postgresql.UUID(as_uuid=False),
                  sa.ForeignKey("engagements.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("workspace_id", postgresql.UUID(as_uuid=False),
                  sa.ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("name", sa.String(200), nullable=False, server_default="Attack"),
        sa.Column("request_template", postgresql.JSONB, nullable=False),
        sa.Column("payload_set_id", postgresql.UUID(as_uuid=False),
                  sa.ForeignKey("intruder_payload_sets.id", ondelete="SET NULL"), nullable=True),
        sa.Column("attack_type", sa.String(32), nullable=False, server_default="sniper"),
        sa.Column("concurrency", sa.Integer, nullable=False, server_default="5"),
        sa.Column("rate_limit", sa.Integer, nullable=False, server_default="20"),
        sa.Column("status", sa.String(32), nullable=False, server_default="queued"),
        sa.Column("progress_pct", sa.Integer, nullable=False, server_default="0"),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_by_user_id", postgresql.UUID(as_uuid=False),
                  sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )

    op.create_table(
        "intruder_results",
        sa.Column("id", postgresql.UUID(as_uuid=False), primary_key=True),
        sa.Column("attack_id", postgresql.UUID(as_uuid=False),
                  sa.ForeignKey("intruder_attacks.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("payload", sa.Text, nullable=False),
        sa.Column("request_snapshot", postgresql.JSONB, nullable=True),
        sa.Column("response_status", sa.Integer, nullable=True),
        sa.Column("response_length", sa.Integer, nullable=True),
        sa.Column("response_time_ms", sa.Integer, nullable=True),
        sa.Column("grep_match", postgresql.ARRAY(sa.String), nullable=True),
        sa.Column("diff_score", sa.Float, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_intruder_results_attack_status", "intruder_results", ["attack_id", "response_status"])


def downgrade() -> None:
    op.drop_index("ix_intruder_results_attack_status", table_name="intruder_results")
    op.drop_table("intruder_results")
    op.drop_table("intruder_attacks")
    op.drop_table("intruder_payload_sets")
    op.drop_table("repeater_responses")
    op.drop_table("repeater_tabs")
