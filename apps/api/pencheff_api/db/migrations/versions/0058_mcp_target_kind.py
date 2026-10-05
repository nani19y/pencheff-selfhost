"""mcp target kind — Target.kind is String(16); 'mcp' needs no DDL.

Revision ID: 0058
Revises: 0057

Marker migration mirroring the host/memory kind additions
(feature: MCP/AI Agents scanner).

Target.kind is a plain String(16) column, not a database enum, so
accepting a new value requires no schema change. This no-op revision
preserves the alembic chain so that future migrations can chain off it
and the audit trail reflects when the mcp target kind was introduced.
"""
from typing import Union


revision: str = "0058"
down_revision: Union[str, None] = "0057"
branch_labels = None
depends_on = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
