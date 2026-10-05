"""Reachability column on findings.

Revision ID: 0027
Revises: 0026
Create Date: 2026-05-02

Adds ``findings.reachability`` so every finding carries one of:
  ``exploited`` — Pencheff DAST live-verified the issue (or an active
                  verifier replay reproduced it)
  ``reachable`` — SAST taint trace OR SCA usage probe found the package
                  is actually imported by source code
  ``present``   — code/package matches a vulnerable signature, no usage
                  evidence found
  ``unknown``   — pre-classification or insufficient signal

This is the moat vs Snyk: their reachability is binary (reachable / not).
Pencheff's three-tier badge separates "we proved this is exploitable" from
"the dataflow says it could be" from "the code looks like it could be" —
and dashboards sort by it.

Existing rows get NULL on upgrade; the next scan_runner pass populates
them. The dashboard renders NULL as "unknown".
"""
from typing import Union

import sqlalchemy as sa
from alembic import op


revision: str = "0027"
down_revision: Union[str, None] = "0026"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "findings",
        sa.Column("reachability", sa.String(length=16), nullable=True),
    )
    # Composite index supports the dashboard's most-common query:
    # "show me everything `exploited` for this scan, then `reachable`."
    op.create_index(
        "ix_findings_reachability_severity",
        "findings", ["reachability", "severity"],
    )


def downgrade() -> None:
    op.drop_index("ix_findings_reachability_severity", table_name="findings")
    op.drop_column("findings", "reachability")
