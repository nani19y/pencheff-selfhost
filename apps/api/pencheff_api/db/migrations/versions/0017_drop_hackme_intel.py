"""Drop hackme intel pass: remove scan_artifacts table.

Revision ID: 0017
Revises: 0016
Create Date: 2026-04-27

The hackme/attack-simulation feature is being removed. The
``scan_artifacts`` table held crawled content chunks + MiniLM
embeddings for the agent's ``recall_intel`` tool. Both the model and
the consumers are gone, so drop the table.

The pgvector extension itself is left in place — dropping it is a
no-op for performance and risks breaking any sibling deployment that
provisioned the same extension. Future cleanup can drop it explicitly
if every environment is confirmed clean.
"""
from typing import Union

import sqlalchemy as sa
from alembic import op

revision: str = "0017"
down_revision: Union[str, None] = "0016"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.drop_index("ix_scan_artifacts_scan_chunk", table_name="scan_artifacts")
    op.drop_table("scan_artifacts")


def downgrade() -> None:
    # Recreate the table without the vector column — the embedding
    # backing was the whole point, so a downgrade restores schema shape
    # only, not behaviour. JSONB stands in for the dropped Vector(384)
    # so the migration runs even on Postgres instances without pgvector.
    op.create_table(
        "scan_artifacts",
        sa.Column("id", sa.dialects.postgresql.UUID(as_uuid=False), primary_key=True),
        sa.Column("scan_id", sa.dialects.postgresql.UUID(as_uuid=False),
                  sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False),
        sa.Column("source_url", sa.String(2048), nullable=False),
        sa.Column("content_type", sa.String(64), nullable=False),
        sa.Column("chunk_idx", sa.Integer, nullable=False, server_default="0"),
        sa.Column("content", sa.Text, nullable=False),
        sa.Column("embedding", sa.dialects.postgresql.JSONB),
        sa.Column("metadata_", sa.dialects.postgresql.JSONB),
        sa.Column("collected_at", sa.DateTime(timezone=True),
                  server_default=sa.text("now()"), nullable=False),
    )
    op.create_index(
        "ix_scan_artifacts_scan_chunk", "scan_artifacts", ["scan_id", "chunk_idx"]
    )
