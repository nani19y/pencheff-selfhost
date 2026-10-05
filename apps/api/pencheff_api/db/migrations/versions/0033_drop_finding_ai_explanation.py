"""Drop findings.ai_explanation column.

Revision ID: 0033
Revises: 0032
Create Date: 2026-05-03

The "Analyst's Brief" feature (per-finding LLM-generated overview /
impact / prevention / scenarios shown in the DAST finding detail page)
has been removed. The cache column ``findings.ai_explanation`` is no
longer read or written by any application code, so it's dropped here.

The sibling ``findings.ai_triage`` column (AI Triage 2.0) is unrelated
and remains. The ``repo_findings.ai_explanation`` column (SAST flow)
is also unrelated — different table, different shape (Text, not JSONB)
— and remains.

``IF EXISTS`` so the migration succeeds whether the column was added
by 0003_finding_explanation.py and is still present, or has already
been dropped manually.
"""
from typing import Union

from alembic import op


revision: str = "0033"
down_revision: Union[str, None] = "0032"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE findings DROP COLUMN IF EXISTS ai_explanation")


def downgrade() -> None:
    # Intentionally empty. The Analyst's Brief feature has been removed
    # from the codebase; recreating the column on downgrade would
    # leave NULLs everywhere and there's no application code to
    # populate it. If the feature comes back, it ships its own
    # forward migration.
    pass
