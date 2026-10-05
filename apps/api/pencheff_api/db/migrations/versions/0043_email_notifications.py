"""Email notification recipients on Scan, Target, Workspace.

Revision ID: 0043
Revises: 0042
Create Date: 2026-05-09

Adds three JSONB array columns powering the email features:

* ``scans.notify_emails`` — one-shot recipient list captured at scan
  commission time; the runner dispatches a "scan complete" email here
  when the scan finishes (success or failure).
* ``targets.weekly_digest_emails`` — per-target subscription. The
  Mondays 9am UTC ``weekly-digest`` Celery beat task fans out a digest
  email per target whose list is non-empty.
* ``workspaces.weekly_digest_emails`` — per-workspace rollup
  subscription. The same beat task also walks workspaces with a
  populated list and sends a single digest covering every target.

JSONB rather than a join table because (a) lists are short — at most
a handful of recipients per subscription, (b) order doesn't matter,
(c) we never query "which targets does this email subscribe to,"
which is the only case where a relational layout would win.
"""
from __future__ import annotations

from typing import Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB


revision: str = "0043"
down_revision: Union[str, None] = "0042"
branch_labels: Union[str, tuple, None] = None
depends_on: Union[str, tuple, None] = None


def upgrade() -> None:
    op.add_column(
        "scans",
        sa.Column("notify_emails", JSONB, nullable=True),
    )
    op.add_column(
        "targets",
        sa.Column("weekly_digest_emails", JSONB, nullable=True),
    )
    op.add_column(
        "workspaces",
        sa.Column("weekly_digest_emails", JSONB, nullable=True),
    )


def downgrade() -> None:
    op.drop_column("workspaces", "weekly_digest_emails")
    op.drop_column("targets", "weekly_digest_emails")
    op.drop_column("scans", "notify_emails")
