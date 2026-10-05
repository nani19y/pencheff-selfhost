"""Agentic Fix Run — tables for the agentic Fix-all workflow.

Revision ID: 0049
Revises: 0048
Create Date: 2026-05-23

Three new tables backing the agentic fixer (see
``docs/superpowers/specs/2026-05-23-agentic-fixer-design.md``):

* ``agentic_fix_runs`` — one row per Fix-all (agent) invocation.
  Source of truth for status, branch name, PR URL, etc.
* ``agentic_fix_usage`` — token + cost accounting, one row per
  Anthropic Messages API call. Aggregated into per-workspace MTD spend
  by the billing layer.
* ``agentic_fix_steps`` — audit trail of every tool call the agent
  made. Drives the progress UI + populates AuditLog.

The legacy ``bulk_fix_tasks`` row stays untouched — the per-finding
fix-all flow remains available as the "legacy fix" mode.
"""
from __future__ import annotations

from typing import Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql


revision: str = "0049"
down_revision: Union[str, None] = "0048"
branch_labels: Union[str, tuple, None] = None
depends_on: Union[str, tuple, None] = None


def upgrade() -> None:
    op.create_table(
        "agentic_fix_runs",
        sa.Column("id", postgresql.UUID(as_uuid=False), primary_key=True),
        sa.Column("org_id", postgresql.UUID(as_uuid=False), nullable=False, index=True),
        sa.Column("workspace_id", postgresql.UUID(as_uuid=False), nullable=False, index=True),
        sa.Column("user_id", postgresql.UUID(as_uuid=False), nullable=False),
        sa.Column("scan_id", postgresql.UUID(as_uuid=False), nullable=True),
        sa.Column("repo_scan_id", postgresql.UUID(as_uuid=False), nullable=True),
        sa.Column("runtime", sa.String(16), nullable=False, server_default="server"),
        sa.Column("status", sa.String(16), nullable=False, server_default="queued"),
        sa.Column("findings_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("iterations", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("current_step", sa.Text(), nullable=True),
        sa.Column("branch_name", sa.String(255), nullable=True),
        sa.Column("pr_url", sa.Text(), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("system_prompt", sa.Text(), nullable=True),
        sa.Column("model", sa.String(64), nullable=False),
        sa.Column("max_iterations", sa.Integer(), nullable=False, server_default="30"),
        sa.Column("created_at", sa.DateTime(timezone=True),
                  nullable=False, server_default=sa.func.now()),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        # Cancellation flag set by the cancel endpoint; the worker
        # polls between iterations and bails when this flips.
        sa.Column("cancel_requested", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.CheckConstraint(
            "(scan_id IS NULL) <> (repo_scan_id IS NULL)",
            name="ck_agentic_fix_runs_exactly_one_scan_ref",
        ),
        sa.CheckConstraint(
            "runtime IN ('server', 'desktop')",
            name="ck_agentic_fix_runs_runtime",
        ),
    )
    op.create_index(
        "ix_agentic_fix_runs_workspace_created",
        "agentic_fix_runs",
        ["workspace_id", "created_at"],
    )
    op.create_index(
        "ix_agentic_fix_runs_scan",
        "agentic_fix_runs",
        ["scan_id"],
        postgresql_where=sa.text("scan_id IS NOT NULL"),
    )
    op.create_index(
        "ix_agentic_fix_runs_repo_scan",
        "agentic_fix_runs",
        ["repo_scan_id"],
        postgresql_where=sa.text("repo_scan_id IS NOT NULL"),
    )

    op.create_table(
        "agentic_fix_usage",
        sa.Column("id", postgresql.UUID(as_uuid=False), primary_key=True),
        sa.Column("run_id", postgresql.UUID(as_uuid=False),
                  sa.ForeignKey("agentic_fix_runs.id", ondelete="CASCADE"),
                  nullable=False, index=True),
        sa.Column("workspace_id", postgresql.UUID(as_uuid=False), nullable=False, index=True),
        sa.Column("iteration", sa.Integer(), nullable=False),
        sa.Column("model", sa.String(64), nullable=False),
        sa.Column("input_tokens", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("output_tokens", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("cache_read_input_tokens", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("cache_creation_input_tokens", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("cost_usd_cents", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True),
                  nullable=False, server_default=sa.func.now()),
    )
    op.create_index(
        "ix_agentic_fix_usage_workspace_created",
        "agentic_fix_usage",
        ["workspace_id", "created_at"],
    )

    op.create_table(
        "agentic_fix_steps",
        sa.Column("id", postgresql.UUID(as_uuid=False), primary_key=True),
        sa.Column("run_id", postgresql.UUID(as_uuid=False),
                  sa.ForeignKey("agentic_fix_runs.id", ondelete="CASCADE"),
                  nullable=False, index=True),
        sa.Column("iteration", sa.Integer(), nullable=False),
        sa.Column("step_index", sa.Integer(), nullable=False),
        sa.Column("tool_name", sa.String(64), nullable=False),
        sa.Column("tool_input", postgresql.JSONB, nullable=True),
        sa.Column("tool_output_truncated", sa.Text(), nullable=True),
        sa.Column("tool_error", sa.Text(), nullable=True),
        sa.Column("duration_ms", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True),
                  nullable=False, server_default=sa.func.now()),
    )
    op.create_index(
        "ix_agentic_fix_steps_run_iter",
        "agentic_fix_steps",
        ["run_id", "iteration", "step_index"],
    )


def downgrade() -> None:
    op.drop_index("ix_agentic_fix_steps_run_iter", table_name="agentic_fix_steps")
    op.drop_table("agentic_fix_steps")
    op.drop_index("ix_agentic_fix_usage_workspace_created", table_name="agentic_fix_usage")
    op.drop_table("agentic_fix_usage")
    op.drop_index("ix_agentic_fix_runs_repo_scan", table_name="agentic_fix_runs")
    op.drop_index("ix_agentic_fix_runs_scan", table_name="agentic_fix_runs")
    op.drop_index("ix_agentic_fix_runs_workspace_created", table_name="agentic_fix_runs")
    op.drop_table("agentic_fix_runs")
