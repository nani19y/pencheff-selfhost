"""rag target kind — Target.kind is String(16); 'rag' needs no DDL.

Revision ID: 0059
Revises: 0058

Marker migration mirroring the mcp/host/memory kind additions
(feature: RAG/Vector DB scanner).

Target.kind is a plain String(16) column, not a database enum, so
accepting a new value requires no schema change. This no-op revision
preserves the alembic chain so that future migrations can chain off it
and the audit trail reflects when the rag target kind was introduced.
"""
from typing import Union


revision: str = "0059"
down_revision: Union[str, None] = "0058"
branch_labels = None
depends_on = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
