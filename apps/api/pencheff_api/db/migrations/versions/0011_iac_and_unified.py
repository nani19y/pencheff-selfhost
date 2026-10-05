"""IaC scanners + unified cross-reference table.

Revision ID: 0011
Revises: 0010
Create Date: 2026-04-26

The ``unified_findings`` table is *not* a denormalized copy — it is a graph
of edges between primary findings (DAST/SAST/SCA/IaC/secret) the correlation
service produced. The unified-view endpoint joins these edges with the
underlying ``findings`` and ``repo_findings`` tables.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0011"
down_revision: Union[str, None] = "0010"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "unified_findings",
        sa.Column("id", postgresql.UUID(as_uuid=False), primary_key=True),
        sa.Column("engagement_id", postgresql.UUID(as_uuid=False),
                  sa.ForeignKey("engagements.id", ondelete="CASCADE"), nullable=False, index=True),
        # primary side
        sa.Column("primary_finding_kind", sa.String(16), nullable=False),
        sa.Column("primary_finding_id", postgresql.UUID(as_uuid=False), nullable=False),
        # related side
        sa.Column("related_finding_kind", sa.String(16), nullable=False),
        sa.Column("related_finding_id", postgresql.UUID(as_uuid=False), nullable=False),
        sa.Column("link_kind", sa.String(32), nullable=False),
        sa.Column("confidence", sa.Float, nullable=False, server_default="0.5"),
        sa.Column("rationale", sa.Text, nullable=True),
        sa.Column("generated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint(
            "engagement_id",
            "primary_finding_kind", "primary_finding_id",
            "related_finding_kind", "related_finding_id",
            "link_kind",
            name="uq_unified_finding_edge",
        ),
    )
    op.create_index(
        "ix_unified_findings_primary",
        "unified_findings",
        ["primary_finding_kind", "primary_finding_id"],
    )
    op.create_index(
        "ix_unified_findings_related",
        "unified_findings",
        ["related_finding_kind", "related_finding_id"],
    )

    # Both Trivy IaC and Checkov findings are stored in repo_findings via
    # scanner='trivy_iac' / scanner='checkov'. No new column needed.


def downgrade() -> None:
    op.drop_index("ix_unified_findings_related", table_name="unified_findings")
    op.drop_index("ix_unified_findings_primary", table_name="unified_findings")
    op.drop_table("unified_findings")
