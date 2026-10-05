"""Per-scan operator consent payload.

Revision ID: 0037
Revises: 0036
Create Date: 2026-05-06

Every scan now requires explicit operator consent describing which
AI-driven actions it has authorised. The payload is JSONB so the
disclosure surface can evolve without migrations.

Existing rows are backfilled with a sentinel
``{"version": 1, "acknowledged": true, "authorization_text":
"PRE_CONSENT_SCAN: created before consent screen launched",
"disclosed_actions": ["passive_recon"]}`` so historical scans
remain valid.
"""
from typing import Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql


revision: str = "0037"
down_revision: Union[str, None] = "0036"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "scans",
        sa.Column("consent_payload", postgresql.JSONB, nullable=True),
    )
    op.execute(
        "UPDATE scans SET consent_payload = '"
        '{"version": 1, "acknowledged": true, "authorization_text": '
        '"PRE_CONSENT_SCAN: created before consent screen launched", '
        '"disclosed_actions": ["passive_recon"]}'
        "'::jsonb WHERE consent_payload IS NULL"
    )


def downgrade() -> None:
    op.drop_column("scans", "consent_payload")
