"""SSVC decision column on findings.

Revision ID: 0026
Revises: 0025
Create Date: 2026-05-02

Adds ``findings.ssvc_decision`` so the prioritisation engine can persist
the SSVC action class (track | track_star | attend | act) computed from
CVSS × EPSS × KEV × exposure. The dashboard sorts by ``risk_score``
(already present from migration 0004) and displays the SSVC class as a
secondary signal — colour-coded chips next to each finding.

The column is nullable because:
  * Pre-existing findings won't have it computed and we don't want to
    block the migration on a backfill.
  * SSVC requires CVSS to be present — findings discovered by tools that
    don't emit CVSS (some custom DAST checks) will leave it null.
"""
from typing import Union

import sqlalchemy as sa
from alembic import op


revision: str = "0026"
down_revision: Union[str, None] = "0025"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "findings",
        sa.Column("ssvc_decision", sa.String(length=16), nullable=True),
    )
    # Index supports the dashboard's "filter by SSVC=act" facet without
    # forcing a full table scan when finding counts grow large.
    op.create_index(
        "ix_findings_ssvc_decision",
        "findings", ["ssvc_decision"],
    )


def downgrade() -> None:
    op.drop_index("ix_findings_ssvc_decision", table_name="findings")
    op.drop_column("findings", "ssvc_decision")
