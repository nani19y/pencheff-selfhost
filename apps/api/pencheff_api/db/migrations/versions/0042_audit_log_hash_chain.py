"""audit_logs: hash-chain + observability correlation columns.

Revision ID: 0042
Revises: 0041
Create Date: 2026-05-08

The pre-existing ``audit_logs`` table (introduced earlier; see models.py)
captures user-action audit rows but is not tamper-evident. This
revision adds:

* ``prev_hash`` / ``row_hash`` — sha256 chain. Each row's hash covers
  the previous row's hash plus the canonical-JSON representation of
  this row. Any modification of a historical row (even at the DB
  level) breaks every subsequent hash, and the
  ``GET /audit/verify`` endpoint surfaces the tamper.
* ``trace_id`` — joins audit rows to ``otel_spans`` so an operator
  reviewing an audit entry can pivot straight into the request's
  trace waterfall.
* ``request_ip`` / ``user_agent`` — provenance fields the existing
  schema lacked, expected by SOC2-style audit reviews.
* ``request_body_diff`` — the redacted (via observability/redact.py)
  body of the mutating request, truncated to 16KB. Captured in the
  audit middleware so we don't need a per-route ``request.state``
  diff hook.

DB-level ``REVOKE UPDATE, DELETE`` is intentionally NOT applied here.
Self-hosted Pencheff deployments typically use a single role for both
the app and the retention task, so a hard REVOKE would also block the
hourly prune. Tamper-evidence is enforced by the hash chain itself.
Operators who run a separate ``audit_admin`` role for retention can
``REVOKE`` from the app role manually as a follow-up.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql


revision: str = "0042"
down_revision: Union[str, None] = "0041"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "audit_logs",
        sa.Column("prev_hash", postgresql.BYTEA, nullable=True),
    )
    op.add_column(
        "audit_logs",
        sa.Column("row_hash", postgresql.BYTEA, nullable=True),
    )
    op.add_column(
        "audit_logs",
        sa.Column("trace_id", postgresql.BYTEA, nullable=True),
    )
    op.add_column(
        "audit_logs",
        sa.Column("request_ip", postgresql.INET, nullable=True),
    )
    op.add_column(
        "audit_logs",
        sa.Column("user_agent", sa.Text(), nullable=True),
    )
    op.add_column(
        "audit_logs",
        sa.Column("request_body_diff", postgresql.JSONB, nullable=True),
    )

    op.create_index(
        "ix_audit_logs_trace_id",
        "audit_logs",
        ["trace_id"],
        postgresql_where=sa.text("trace_id IS NOT NULL"),
    )
    op.create_index(
        "ix_audit_logs_created_at",
        "audit_logs",
        [sa.text("created_at DESC")],
    )


def downgrade() -> None:
    op.drop_index("ix_audit_logs_created_at", table_name="audit_logs")
    op.drop_index("ix_audit_logs_trace_id", table_name="audit_logs")
    op.drop_column("audit_logs", "request_body_diff")
    op.drop_column("audit_logs", "user_agent")
    op.drop_column("audit_logs", "request_ip")
    op.drop_column("audit_logs", "trace_id")
    op.drop_column("audit_logs", "row_hash")
    op.drop_column("audit_logs", "prev_hash")
