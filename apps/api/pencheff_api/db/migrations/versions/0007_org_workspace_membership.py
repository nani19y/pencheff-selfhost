"""Organizations → Workspaces with membership + per-workspace quotas.

Revision ID: 0007
Revises: 0006
Create Date: 2026-04-23

Adds:
  * ``workspaces`` (Org → Workspace) with an auto-created "Default" workspace
    per existing org.
  * ``org_members`` (n:n User↔Org with role owner|admin|member) — backfilled
    from each User's deprecated ``users.org_id`` as role=owner.
  * ``org_invites`` for pending email invitations.
  * ``workspace_id`` NOT NULL on the eight resource tables that previously
    scoped directly by org (targets, scans, assets, scan_schedules,
    integrations, repo_integrations, repositories, repo_scans). Existing
    rows are backfilled to the org's "Default" workspace.
  * ``workspace_id`` nullable on audit_logs for future event correlation.
  * ``users.org_id`` relaxed to nullable; kept one release for rollback.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0007"
down_revision: Union[str, None] = "0006"
branch_labels = None
depends_on = None


# Tables that gain a NOT NULL ``workspace_id`` column.
_WORKSPACE_SCOPED_TABLES: tuple[str, ...] = (
    "targets",
    "scans",
    "assets",
    "scan_schedules",
    "integrations",
    "repo_integrations",
    "repositories",
    "repo_scans",
)


def upgrade() -> None:
    # 1. New tables ─────────────────────────────────────────────────────────
    op.create_table(
        "workspaces",
        sa.Column("id", postgresql.UUID(as_uuid=False), primary_key=True),
        sa.Column("org_id", postgresql.UUID(as_uuid=False),
                  sa.ForeignKey("orgs.id", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("slug", sa.String(64), nullable=False),
        sa.Column("created_by_user_id", postgresql.UUID(as_uuid=False),
                  sa.ForeignKey("users.id", ondelete="SET NULL")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("org_id", "slug", name="uq_workspaces_org_slug"),
    )
    op.create_index("ix_workspaces_org", "workspaces", ["org_id"])

    op.create_table(
        "org_members",
        sa.Column("id", postgresql.UUID(as_uuid=False), primary_key=True),
        sa.Column("org_id", postgresql.UUID(as_uuid=False),
                  sa.ForeignKey("orgs.id", ondelete="CASCADE"), nullable=False),
        sa.Column("user_id", postgresql.UUID(as_uuid=False),
                  sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("role", sa.String(16), nullable=False, server_default="member"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("org_id", "user_id", name="uq_org_members_org_user"),
    )
    op.create_index("ix_org_members_org", "org_members", ["org_id"])
    op.create_index("ix_org_members_user", "org_members", ["user_id"])

    op.create_table(
        "org_invites",
        sa.Column("id", postgresql.UUID(as_uuid=False), primary_key=True),
        sa.Column("org_id", postgresql.UUID(as_uuid=False),
                  sa.ForeignKey("orgs.id", ondelete="CASCADE"), nullable=False),
        sa.Column("email", sa.String(320), nullable=False),
        sa.Column("role", sa.String(16), nullable=False, server_default="member"),
        sa.Column("token_hash", sa.String(128), nullable=False, unique=True),
        sa.Column("invited_by_user_id", postgresql.UUID(as_uuid=False),
                  sa.ForeignKey("users.id", ondelete="SET NULL")),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("accepted_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_org_invites_org", "org_invites", ["org_id"])
    op.create_index("ix_org_invites_email", "org_invites", ["email"])

    # 2. Backfill a "Default" workspace per existing org ───────────────────
    #    gen_random_uuid() requires pgcrypto — the PK columns are real
    #    ``uuid`` types (SQLAlchemy's UUID(as_uuid=False) just maps the
    #    Python value to/from ``str``) so the cast has to stay UUID, not text.
    op.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto")
    op.execute(
        """
        INSERT INTO workspaces (id, org_id, name, slug, created_at)
        SELECT gen_random_uuid(), id, 'Default', 'default', now()
        FROM orgs
        """
    )

    # 3. Backfill org_members from users.org_id (role = owner) ─────────────
    op.execute(
        """
        INSERT INTO org_members (id, org_id, user_id, role, created_at)
        SELECT gen_random_uuid(), org_id, id, 'owner', now()
        FROM users
        WHERE org_id IS NOT NULL
        """
    )

    # 4. Add workspace_id to each resource table (nullable, then backfill) ─
    for tbl in _WORKSPACE_SCOPED_TABLES:
        op.add_column(
            tbl,
            sa.Column(
                "workspace_id",
                postgresql.UUID(as_uuid=False),
                sa.ForeignKey("workspaces.id", ondelete="CASCADE"),
                nullable=True,
            ),
        )
        op.execute(
            f"""
            UPDATE {tbl} t
            SET workspace_id = w.id
            FROM workspaces w
            WHERE w.org_id = t.org_id
              AND w.slug = 'default'
            """
        )
        op.alter_column(tbl, "workspace_id", nullable=False)
        op.create_index(f"ix_{tbl}_workspace", tbl, ["workspace_id"])

    # 5. Swap the asset uniqueness to (workspace_id, type, value) ──────────
    op.drop_constraint("uq_assets_org_type_value", "assets", type_="unique")
    op.create_unique_constraint(
        "uq_assets_workspace_type_value", "assets", ["workspace_id", "type", "value"]
    )
    op.drop_index("ix_assets_org_type", table_name="assets")
    op.create_index("ix_assets_workspace_type", "assets", ["workspace_id", "type"])

    # 6. audit_logs gets a nullable workspace_id (no backfill — historical).
    op.add_column(
        "audit_logs",
        sa.Column(
            "workspace_id",
            postgresql.UUID(as_uuid=False),
            sa.ForeignKey("workspaces.id", ondelete="SET NULL"),
            nullable=True,
        ),
    )

    # 7. Relax users.org_id to nullable (single-org FK is deprecated) ──────
    op.alter_column("users", "org_id", nullable=True)


def downgrade() -> None:
    op.alter_column("users", "org_id", nullable=False)
    op.drop_column("audit_logs", "workspace_id")

    op.drop_index("ix_assets_workspace_type", table_name="assets")
    op.create_index("ix_assets_org_type", "assets", ["org_id", "type"])
    op.drop_constraint("uq_assets_workspace_type_value", "assets", type_="unique")
    op.create_unique_constraint(
        "uq_assets_org_type_value", "assets", ["org_id", "type", "value"]
    )

    for tbl in reversed(_WORKSPACE_SCOPED_TABLES):
        op.drop_index(f"ix_{tbl}_workspace", table_name=tbl)
        op.drop_column(tbl, "workspace_id")

    op.drop_index("ix_org_invites_email", table_name="org_invites")
    op.drop_index("ix_org_invites_org", table_name="org_invites")
    op.drop_table("org_invites")

    op.drop_index("ix_org_members_user", table_name="org_members")
    op.drop_index("ix_org_members_org", table_name="org_members")
    op.drop_table("org_members")

    op.drop_index("ix_workspaces_org", table_name="workspaces")
    op.drop_table("workspaces")
