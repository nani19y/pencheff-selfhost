"""voice target kind — Target.kind is String(16); 'voice' needs no DDL.

Revision ID: 0061
Revises: 0060

Marker migration mirroring the ml_model/rag/mcp/host/memory kind additions
(feature: Voice / Speech-AI scanning — dispatch + frontend).

Target.kind is a plain String(16) column, not a database enum, so
accepting a new value requires no schema change. This no-op revision
preserves the alembic chain so that future migrations can chain off it
and the audit trail reflects when the voice target kind was introduced.
"""
from typing import Union


revision: str = "0061"
down_revision: Union[str, None] = "0060"
branch_labels = None
depends_on = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
