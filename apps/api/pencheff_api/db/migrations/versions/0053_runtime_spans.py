"""Runtime-protection tracing: runtime_spans table.

Revision ID: 0053
Revises: 0052
Create Date: 2026-06-07

Workspace-scoped OpenTelemetry-style spans emitted by the hosted guardrail
gateway and (later) the embeddable SDK. Spans group into a trace via
``trace_id`` + ``parent_span_id``.
"""
from __future__ import annotations

from typing import Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB


revision: str = "0053"
down_revision: Union[str, None] = "0052"
branch_labels: Union[str, tuple, None] = None
depends_on: Union[str, tuple, None] = None


def upgrade() -> None:
    op.create_table(
        "runtime_spans",
        sa.Column("id", sa.dialects.postgresql.UUID(as_uuid=False), primary_key=True),
        sa.Column(
            "workspace_id",
            sa.dialects.postgresql.UUID(as_uuid=False),
            sa.ForeignKey("workspaces.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("trace_id", sa.String(64), nullable=False),
        sa.Column("parent_span_id", sa.String(64), nullable=True),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("kind", sa.String(32), nullable=False, server_default="other"),
        sa.Column("status", sa.String(16), nullable=False, server_default="ok"),
        sa.Column("source", sa.String(16), nullable=False, server_default="gateway"),
        sa.Column("target_id", sa.dialects.postgresql.UUID(as_uuid=False), nullable=True),
        sa.Column("start_time", sa.DateTime(timezone=True), nullable=False),
        sa.Column("end_time", sa.DateTime(timezone=True), nullable=True),
        sa.Column("duration_ms", sa.Integer, nullable=True),
        sa.Column("attributes", JSONB, nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )
    op.create_index(
        "ix_runtime_spans_ws_created", "runtime_spans", ["workspace_id", "created_at"],
    )
    op.create_index(
        "ix_runtime_spans_ws_trace", "runtime_spans", ["workspace_id", "trace_id"],
    )


def downgrade() -> None:
    op.drop_index("ix_runtime_spans_ws_trace", table_name="runtime_spans")
    op.drop_index("ix_runtime_spans_ws_created", table_name="runtime_spans")
    op.drop_table("runtime_spans")
