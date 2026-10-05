"""Fix proposals + LLM usage ledger.

Revision ID: 0025
Revises: 0024
Create Date: 2026-05-01

Adds two tables that power the "propose fix → open PR" flow:

  * ``fix_proposals`` — one row per generated proposal. Carries the unified
    diff, the file(s) it touches, the source (scanner-native autofix vs
    LLM-generated), and post-apply pointers (branch, PR URL). Findings are
    polymorphic — a proposal may target either a DAST ``findings`` row or a
    repo-scan ``repo_findings`` row, distinguished by ``finding_kind``.
  * ``fix_llm_usage`` — append-only ledger of LLM-backed proposer calls.
    Drives the per-scan SAST quota, the per-period DAST quota, and end-of-
    period PAYG billing. ``free_quota_consumed`` is 1 when the call drew
    against the free allowance, 0 once the org has tipped into PAYG.
"""
from typing import Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0025"
down_revision: Union[str, None] = "0024"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "fix_proposals",
        sa.Column("id", postgresql.UUID(as_uuid=False), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("org_id", postgresql.UUID(as_uuid=False),
                  sa.ForeignKey("orgs.id", ondelete="CASCADE"), nullable=False),
        sa.Column("workspace_id", postgresql.UUID(as_uuid=False),
                  sa.ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False),
        sa.Column("scan_id", postgresql.UUID(as_uuid=False),
                  sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=True),
        sa.Column("repo_scan_id", postgresql.UUID(as_uuid=False),
                  sa.ForeignKey("repo_scans.id", ondelete="CASCADE"), nullable=True),
        sa.Column("finding_kind", sa.String(16), nullable=False),  # "sast" | "dast"
        sa.Column("finding_id", postgresql.UUID(as_uuid=False), nullable=False),
        sa.Column("repository_id", postgresql.UUID(as_uuid=False),
                  sa.ForeignKey("repositories.id", ondelete="SET NULL"), nullable=True),
        sa.Column("status", sa.String(32), nullable=False, server_default="draft"),
        sa.Column("source", sa.String(32), nullable=False),  # "scanner" | "llm"
        sa.Column("diff", sa.Text, nullable=False),
        sa.Column("target_files", postgresql.JSONB, nullable=True),
        sa.Column("provenance_confidence", sa.Float, nullable=True),
        sa.Column("provenance_reasoning", sa.Text, nullable=True),
        sa.Column("llm_input_tokens", sa.Integer, nullable=True),
        sa.Column("llm_output_tokens", sa.Integer, nullable=True),
        sa.Column("cost_usd", sa.Float, nullable=True),
        sa.Column("branch_name", sa.String(200), nullable=True),
        sa.Column("pr_url", sa.String(1024), nullable=True),
        sa.Column("commit_sha", sa.String(64), nullable=True),
        sa.Column("error", sa.Text, nullable=True),
        sa.Column("created_by", postgresql.UUID(as_uuid=False),
                  sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True),
                  server_default=sa.func.now(), nullable=False),
        sa.Column("applied_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_fix_proposals_finding",
                    "fix_proposals", ["finding_kind", "finding_id"])
    op.create_index("ix_fix_proposals_org_created",
                    "fix_proposals", ["org_id", "created_at"])
    op.create_index("ix_fix_proposals_status",
                    "fix_proposals", ["org_id", "status"])

    op.create_table(
        "fix_llm_usage",
        sa.Column("id", postgresql.UUID(as_uuid=False), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("org_id", postgresql.UUID(as_uuid=False),
                  sa.ForeignKey("orgs.id", ondelete="CASCADE"), nullable=False),
        sa.Column("scan_id", postgresql.UUID(as_uuid=False),
                  sa.ForeignKey("scans.id", ondelete="SET NULL"), nullable=True),
        sa.Column("proposal_id", postgresql.UUID(as_uuid=False),
                  sa.ForeignKey("fix_proposals.id", ondelete="SET NULL"), nullable=True),
        sa.Column("kind", sa.String(16), nullable=False),  # "sast" | "dast"
        sa.Column("model", sa.String(64), nullable=False),
        sa.Column("input_tokens", sa.Integer, nullable=False, server_default="0"),
        sa.Column("output_tokens", sa.Integer, nullable=False, server_default="0"),
        sa.Column("free_quota_consumed", sa.Integer, nullable=False, server_default="0"),
        sa.Column("payg_cost_usd", sa.Float, nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True),
                  server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_fix_llm_usage_org_created",
                    "fix_llm_usage", ["org_id", "created_at"])
    op.create_index("ix_fix_llm_usage_scan_kind",
                    "fix_llm_usage", ["scan_id", "kind"])


def downgrade() -> None:
    op.drop_index("ix_fix_llm_usage_scan_kind", table_name="fix_llm_usage")
    op.drop_index("ix_fix_llm_usage_org_created", table_name="fix_llm_usage")
    op.drop_table("fix_llm_usage")
    op.drop_index("ix_fix_proposals_status", table_name="fix_proposals")
    op.drop_index("ix_fix_proposals_org_created", table_name="fix_proposals")
    op.drop_index("ix_fix_proposals_finding", table_name="fix_proposals")
    op.drop_table("fix_proposals")
