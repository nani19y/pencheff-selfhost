"""Hackme intel pass: pgvector-backed scan_artifacts table.

Stores crawled content (HTML, JS, response bodies) from a hackme scan plus
MiniLM-L6-v2 (384-dim) embeddings of each chunk. The agent's
``recall_intel`` tool queries these vectors to guide exploitation.

Revision ID: 0005
Revises: 0004
Create Date: 2026-04-22
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0005"
down_revision: Union[str, None] = "0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Enable pgvector. The ``pgvector/pgvector:pg16`` image ships the
    # extension files; this call just registers the types for the DB.
    op.execute("CREATE EXTENSION IF NOT EXISTS vector")

    op.create_table(
        "scan_artifacts",
        sa.Column("id", postgresql.UUID(as_uuid=False), primary_key=True),
        sa.Column(
            "scan_id",
            postgresql.UUID(as_uuid=False),
            sa.ForeignKey("scans.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        sa.Column("source_url", sa.String(2048), nullable=False),
        sa.Column(
            "content_type",
            sa.String(64),
            nullable=False,
            server_default="text/html",
        ),
        sa.Column("chunk_idx", sa.Integer, nullable=False, server_default="0"),
        sa.Column("content", sa.Text, nullable=False),
        sa.Column(
            "metadata_",
            postgresql.JSONB,
            nullable=True,
            comment="labels the intel extractor attached (secrets, emails, etc.)",
        ),
        sa.Column(
            "collected_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )

    # Add the real ``vector(384)`` column via raw SQL — alembic's type
    # system doesn't know about pgvector without a plugin we don't want
    # to install just for one column. MiniLM-L6-v2 emits 384 dims.
    op.execute("ALTER TABLE scan_artifacts ADD COLUMN embedding vector(384)")

    # HNSW index for cosine similarity. Unlike IVFFLAT, HNSW handles
    # empty tables gracefully (no training pass required) and stays
    # fast as rows are appended mid-scan. pgvector/pgvector:pg16 ships
    # pgvector ≥0.7 which includes HNSW.
    op.execute(
        "CREATE INDEX ix_scan_artifacts_embedding_cosine "
        "ON scan_artifacts USING hnsw (embedding vector_cosine_ops)"
    )

    # Composite lookup for the common access pattern: "all chunks for a scan".
    op.create_index(
        "ix_scan_artifacts_scan_chunk",
        "scan_artifacts",
        ["scan_id", "chunk_idx"],
    )


def downgrade() -> None:
    op.drop_index("ix_scan_artifacts_scan_chunk", table_name="scan_artifacts")
    op.execute("DROP INDEX IF EXISTS ix_scan_artifacts_embedding_cosine")
    op.drop_table("scan_artifacts")
    # Leave the extension installed — other features may use it and
    # dropping it would cascade into anything else that references vector.
