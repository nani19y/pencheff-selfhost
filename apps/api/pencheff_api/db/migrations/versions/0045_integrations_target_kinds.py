"""integrations.target_kinds — per-integration target-kind opt-in list

Revision ID: 0045
Revises: 0044
Create Date: 2026-05-16

Adds ``integrations.target_kinds`` JSONB column carrying the list of
``Target.kind`` values this integration fires for. Resolves S-06 from the
GATE 2 validation: new target kinds (container_image, k8s_cluster, etc.)
must not accidentally flood existing webhook channels configured for DAST
scans only.

Backfill: existing rows get ``["url", "repo", "llm"]`` — their pre-feature
scope. New integrations created after this migration default to all kinds at
the application layer (router-side), surfaced as an opt-in toggle in the
integrations admin UI.

Note: ``Integration.kind`` (already exists, meaning the integration TYPE —
Slack / Teams / PagerDuty) is separate from this new ``target_kinds`` column
(meaning which Target.kind values this integration covers). The name was
chosen to avoid the naming collision.
"""
from __future__ import annotations

from typing import Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB


revision: str = "0045"
down_revision: Union[str, None] = "0044"
branch_labels: Union[str, tuple, None] = None
depends_on: Union[str, tuple, None] = None


def upgrade() -> None:
    op.add_column(
        "integrations",
        sa.Column("target_kinds", JSONB, nullable=True),
    )
    # Backfill: scope existing integrations to their pre-feature kind set so
    # new kinds don't silently spam configured channels.
    op.execute(
        "UPDATE integrations SET target_kinds = '[\"url\", \"repo\", \"llm\"]'::jsonb "
        "WHERE target_kinds IS NULL"
    )


def downgrade() -> None:
    op.drop_column("integrations", "target_kinds")
