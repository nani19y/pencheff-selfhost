"""scan_schedules.timezone — IANA tz for cron interpretation.

Revision ID: 0046
Revises: 0045
Create Date: 2026-05-16

Fixes the silent timezone bug in services/scheduler.compute_next_run:
cron expressions were interpreted in UTC, so a FE-stored "30 21 * * *"
(labeled "9:30 PM IST" by the operator's local clock) actually fired at
21:30 UTC = 03:00 IST the next day — a 5h30m drift.

Adds a ``timezone`` column on ``scan_schedules`` with server_default
"UTC" so pre-existing rows keep their current behavior (they were
de-facto UTC by accident). New rows from the FE pass the operator's
IANA timezone explicitly.
"""
from __future__ import annotations

from typing import Union

import sqlalchemy as sa
from alembic import op


revision: str = "0046"
down_revision: Union[str, None] = "0045"
branch_labels: Union[str, tuple, None] = None
depends_on: Union[str, tuple, None] = None


def upgrade() -> None:
    op.add_column(
        "scan_schedules",
        sa.Column(
            "timezone",
            sa.String(length=64),
            nullable=False,
            server_default="UTC",
        ),
    )


def downgrade() -> None:
    op.drop_column("scan_schedules", "timezone")
