"""Per-target scope + per-event filtering on integrations.

Revision ID: 0018
Revises: 0017
Create Date: 2026-04-28

Adds two array columns to the ``integrations`` table:

* ``target_ids`` — when NULL or empty, the integration fires for every
  target in the workspace (current behaviour). When populated, only
  scans on those specific targets fire events to this integration.
* ``events`` — when NULL or empty, every lifecycle event fires
  (``scan_started``, ``scan_done``, ``scan_failed``, ``finding_new``,
  ``finding_changed``). When populated, only the listed event types
  fire. Lets users wire e.g. a critical-only PagerDuty for failures
  while a Slack channel takes per-finding alerts.

Both columns default to NULL so the migration is backwards-compatible
with every existing integration row.
"""
from typing import Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0018"
down_revision: Union[str, None] = "0017"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "integrations",
        sa.Column(
            "target_ids",
            postgresql.ARRAY(postgresql.UUID(as_uuid=False)),
            nullable=True,
        ),
    )
    op.add_column(
        "integrations",
        sa.Column(
            "events",
            postgresql.ARRAY(sa.String(length=32)),
            nullable=True,
        ),
    )
    # GIN index for membership lookups when fanning out — selecting all
    # integrations where ``<scan target_id> = ANY(target_ids)`` would
    # otherwise table-scan the integrations table on every scan event.
    op.create_index(
        "ix_integrations_target_ids",
        "integrations",
        ["target_ids"],
        postgresql_using="gin",
    )
    op.create_index(
        "ix_integrations_events",
        "integrations",
        ["events"],
        postgresql_using="gin",
    )


def downgrade() -> None:
    op.drop_index("ix_integrations_events", table_name="integrations")
    op.drop_index("ix_integrations_target_ids", table_name="integrations")
    op.drop_column("integrations", "events")
    op.drop_column("integrations", "target_ids")
