"""add findings.hackable — AI-agent exploitability verdict

Revision ID: 0071
Revises: 0070
"""
from alembic import op
import sqlalchemy as sa

revision = "0071"
down_revision = "0069"  # ponytail: CE skips SaaS migration 0070 (campaigns); chain 0069->0071
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("findings", sa.Column("hackable", sa.Boolean(), nullable=True))


def downgrade() -> None:
    op.drop_column("findings", "hackable")
