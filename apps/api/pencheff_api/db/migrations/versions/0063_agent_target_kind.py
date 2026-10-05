"""agent target kind — reclassify agent-source MCP rows to kind='agent'.

Revision ID: 0063
Revises: 0062

Target.kind is String(16) (no DDL). Existing agents were stored as kind='mcp'
with source_type agent_http/agent_browser; move them to kind='agent' and sync
the embedded kind_config.kind. Reversible.
"""
from typing import Union
from alembic import op

revision: str = "0063"
down_revision: Union[str, None] = "0062"
branch_labels = None
depends_on = None

_UP = """
UPDATE targets
   SET kind = 'agent',
       kind_config = jsonb_set(kind_config, '{kind}', '"agent"')
 WHERE kind = 'mcp'
   AND kind_config ->> 'source_type' IN ('agent_http','agent_browser')
"""
_DOWN = """
UPDATE targets
   SET kind = 'mcp',
       kind_config = jsonb_set(kind_config, '{kind}', '"mcp"')
 WHERE kind = 'agent'
   AND kind_config ->> 'source_type' IN ('agent_http','agent_browser')
"""


def upgrade() -> None:
    op.execute(_UP)


def downgrade() -> None:
    op.execute(_DOWN)
