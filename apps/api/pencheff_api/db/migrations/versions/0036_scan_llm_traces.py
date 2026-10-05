"""Persist per-LLM-call traces for swarm agents.

Revision ID: 0036
Revises: 0035
Create Date: 2026-05-05

One row per chat-completions call from the swarm orchestrator. The
request_messages and response_tool_calls payloads can be large; both
are JSONB so PostgreSQL compresses them. Token columns are nullable
because not every provider returns the full breakdown.
"""
from typing import Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql


revision: str = "0036"
down_revision: Union[str, None] = "0035"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "scan_llm_traces",
        sa.Column("id", postgresql.UUID(as_uuid=False), primary_key=True),
        sa.Column(
            "scan_id",
            postgresql.UUID(as_uuid=False),
            sa.ForeignKey("scans.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("agent_name", sa.String(64), nullable=False),
        sa.Column("turn", sa.Integer, nullable=False),
        sa.Column("request_messages", postgresql.JSONB, nullable=False),
        sa.Column("request_tools_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("response_content", sa.Text),
        sa.Column("response_tool_calls", postgresql.JSONB),
        sa.Column("response_reasoning", sa.Text),
        sa.Column("prompt_tokens", sa.Integer),
        sa.Column("completion_tokens", sa.Integer),
        sa.Column("cached_tokens", sa.Integer),
        sa.Column("reasoning_tokens", sa.Integer),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )
    op.create_index(
        "ix_scan_llm_traces_scan_created",
        "scan_llm_traces",
        ["scan_id", "created_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_scan_llm_traces_scan_created", table_name="scan_llm_traces")
    op.drop_table("scan_llm_traces")
