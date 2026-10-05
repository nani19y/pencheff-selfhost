"""AI Triage 2.0 walkthrough cache on findings.

Revision ID: 0028
Revises: 0027
Create Date: 2026-05-02

Adds ``findings.ai_triage`` (JSONB) — caches the DeepSeek-generated
exploitability walkthrough so we don't re-bill the LLM each time the
dashboard renders a finding detail page.

Distinct from ``ai_explanation`` (which holds the legacy
overview/impact/prevention/scenarios shape). Keeping them separate so
operators on the legacy explanation flow aren't surprised by a schema
change, and so the Pro-only triage column can be permission-gated
without forcing a JSONB key-rename.
"""
from typing import Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql


revision: str = "0028"
down_revision: Union[str, None] = "0027"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "findings",
        sa.Column("ai_triage", postgresql.JSONB, nullable=True),
    )


def downgrade() -> None:
    op.drop_column("findings", "ai_triage")
