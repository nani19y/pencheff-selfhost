"""custom LLM providers (BYO-LLM): llm_providers table + orgs.active_llm_provider_id

Revision ID: 0056
Revises: 0055
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0056"
down_revision = "0055"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "llm_providers",
        sa.Column("id", postgresql.UUID(as_uuid=False), primary_key=True),
        sa.Column("org_id", postgresql.UUID(as_uuid=False),
                  sa.ForeignKey("orgs.id", ondelete="CASCADE"), nullable=False),
        sa.Column("label", sa.String(120), nullable=False),
        sa.Column("provider", sa.String(32), nullable=False),
        sa.Column("model", sa.String(200), nullable=False),
        sa.Column("base_url", sa.String(1024), nullable=True),
        sa.Column("api_key_encrypted", sa.LargeBinary(), nullable=True),
        sa.Column("azure_deployment", sa.String(200), nullable=True),
        sa.Column("azure_api_version", sa.String(40), nullable=True),
        sa.Column("extra", postgresql.JSONB(), nullable=True),
        sa.Column("created_by", postgresql.UUID(as_uuid=False),
                  sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True),
                  server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("org_id", "label", name="uq_llm_providers_org_label"),
    )
    op.create_index("ix_llm_providers_org", "llm_providers", ["org_id"])
    op.add_column(
        "orgs",
        sa.Column("active_llm_provider_id", postgresql.UUID(as_uuid=False), nullable=True),
    )
    op.create_foreign_key(
        "fk_orgs_active_llm_provider", "orgs", "llm_providers",
        ["active_llm_provider_id"], ["id"], ondelete="SET NULL",
    )


def downgrade() -> None:
    op.drop_constraint("fk_orgs_active_llm_provider", "orgs", type_="foreignkey")
    op.drop_column("orgs", "active_llm_provider_id")
    op.drop_index("ix_llm_providers_org", table_name="llm_providers")
    op.drop_table("llm_providers")
