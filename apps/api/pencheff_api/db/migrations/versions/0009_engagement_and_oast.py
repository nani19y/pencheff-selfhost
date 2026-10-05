"""Engagements + per-engagement OAST + engagement_id FK fan-out.

Revision ID: 0009
Revises: 0008
Create Date: 2026-04-26

Adds the ``Engagement`` layer between ``Workspace`` and the existing scan
artifacts. Old single-shot scans keep working — every new ``engagement_id``
column is nullable. Closing an engagement releases its provisioned
interactsh container; the lifecycle service (engagement_oast.py) calls
``revoke_oast`` on close.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0009"
down_revision: Union[str, None] = "0008"
branch_labels = None
depends_on = None


_ENGAGEMENT_LINKED_TABLES: tuple[str, ...] = (
    "scans",
    "repo_scans",
    "findings",
    "repo_findings",
    "proxy_sessions",
    "targets",
)


def upgrade() -> None:
    op.create_table(
        "engagements",
        sa.Column("id", postgresql.UUID(as_uuid=False), primary_key=True),
        sa.Column("org_id", postgresql.UUID(as_uuid=False),
                  sa.ForeignKey("orgs.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("workspace_id", postgresql.UUID(as_uuid=False),
                  sa.ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("slug", sa.String(64), nullable=False),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("status", sa.String(16), nullable=False, server_default="open"),
        sa.Column("oast_domain", sa.String(255), nullable=True),
        sa.Column("oast_token", sa.String(128), nullable=True),
        sa.Column("oast_container_id", sa.String(128), nullable=True),
        sa.Column("oast_mode", sa.String(16), nullable=False, server_default="shared"),
        sa.Column("retention_days", sa.Integer, nullable=False, server_default="90"),
        sa.Column("created_by_user_id", postgresql.UUID(as_uuid=False),
                  sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("workspace_id", "slug", name="uq_engagements_workspace_slug"),
    )

    op.create_table(
        "engagement_members",
        sa.Column("id", postgresql.UUID(as_uuid=False), primary_key=True),
        sa.Column("engagement_id", postgresql.UUID(as_uuid=False),
                  sa.ForeignKey("engagements.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("user_id", postgresql.UUID(as_uuid=False),
                  sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("role", sa.String(16), nullable=False, server_default="analyst"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("engagement_id", "user_id", name="uq_engagement_members_eng_user"),
    )

    # Add nullable engagement_id FKs to all in-scope tables.
    for tbl in _ENGAGEMENT_LINKED_TABLES:
        op.add_column(
            tbl,
            sa.Column(
                "engagement_id",
                postgresql.UUID(as_uuid=False),
                sa.ForeignKey("engagements.id", ondelete="SET NULL"),
                nullable=True,
            ),
        )
        op.create_index(f"ix_{tbl}_engagement", tbl, ["engagement_id"])

    # Backfill the FK on proxy_traffic (added in 0008 as nullable, no FK)
    op.create_foreign_key(
        "fk_proxy_traffic_engagement",
        "proxy_traffic",
        "engagements",
        ["engagement_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_foreign_key(
        "fk_engagement_ingest_tokens_engagement",
        "engagement_ingest_tokens",
        "engagements",
        ["engagement_id"],
        ["id"],
        ondelete="CASCADE",
    )


def downgrade() -> None:
    op.drop_constraint(
        "fk_engagement_ingest_tokens_engagement",
        "engagement_ingest_tokens",
        type_="foreignkey",
    )
    op.drop_constraint(
        "fk_proxy_traffic_engagement", "proxy_traffic", type_="foreignkey"
    )
    for tbl in reversed(_ENGAGEMENT_LINKED_TABLES):
        op.drop_index(f"ix_{tbl}_engagement", table_name=tbl)
        op.drop_column(tbl, "engagement_id")
    op.drop_table("engagement_members")
    op.drop_table("engagements")
