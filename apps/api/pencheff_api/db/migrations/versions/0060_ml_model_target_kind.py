"""ml_model target kind — Target.kind is String(16); 'ml_model' needs no DDL.

Revision ID: 0060
Revises: 0059

Marker migration mirroring the rag/mcp/host/memory kind additions
(feature: ML model static artifact scanner).

Target.kind is a plain String(16) column, not a database enum, so
accepting a new value requires no schema change. This no-op revision
preserves the alembic chain so that future migrations can chain off it
and the audit trail reflects when the ml_model target kind was introduced.
"""
from typing import Union


revision: str = "0060"
down_revision: Union[str, None] = "0059"
branch_labels = None
depends_on = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
