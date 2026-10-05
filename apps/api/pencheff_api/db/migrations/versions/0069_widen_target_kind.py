"""widen targets.kind 16→32: newer kinds overflow VARCHAR(16)

``serverless_function`` (19), ``load_balancer_cdn`` (17), and
``browser_extension`` (17) exceed the original String(16) column, so
registering those targets raised StringDataRightTruncationError → HTTP 500.
The 500 escapes the CORS middleware, so the browser only saw "Failed to
fetch". Widen to 32 to match the other kind discriminator columns.

Revision ID: 0069
Revises: 0068
Create Date: 2026-07-29
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0069"
down_revision = "0063"  # ponytail: CE skips SaaS migrations 0064-0068; chain 0063->0069
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.alter_column(
        "targets",
        "kind",
        type_=sa.String(32),
        existing_type=sa.String(16),
        existing_nullable=False,
    )


def downgrade() -> None:
    op.alter_column(
        "targets",
        "kind",
        type_=sa.String(16),
        existing_type=sa.String(32),
        existing_nullable=False,
    )
