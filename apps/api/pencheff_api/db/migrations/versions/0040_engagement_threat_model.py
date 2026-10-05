"""Engagement-scoped STRIDE / DREAD threat model.

Adds two columns to ``engagements``:

- ``threat_model`` JSONB — the structured output of the deterministic
  generator (assets[], threats[], method, scoring metadata).
- ``threat_model_updated_at`` — wall-clock of the last successful
  generate / patch, displayed on the dashboard so operators can tell at
  a glance whether the model is stale.

Revision ID: 0040
Revises: 0039
Create Date: 2026-05-08
"""

from typing import Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0040"
down_revision: Union[str, None] = "0039"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "engagements",
        sa.Column("threat_model", postgresql.JSONB, nullable=True),
    )
    op.add_column(
        "engagements",
        sa.Column(
            "threat_model_updated_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )


def downgrade() -> None:
    op.drop_column("engagements", "threat_model_updated_at")
    op.drop_column("engagements", "threat_model")
