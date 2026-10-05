"""GitHub repo scanning — integrations, repositories, repo scans, repo findings.

Revision ID: 0006
Revises: 0005
Create Date: 2026-04-22
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0006"
down_revision: Union[str, None] = "0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "repo_integrations",
        sa.Column("id", postgresql.UUID(as_uuid=False), primary_key=True),
        sa.Column("org_id", postgresql.UUID(as_uuid=False),
                  sa.ForeignKey("orgs.id", ondelete="CASCADE"), nullable=False),
        sa.Column("provider", sa.String(32), nullable=False, server_default="github"),
        sa.Column("installation_id", sa.String(64), nullable=False),
        sa.Column("account_login", sa.String(200), nullable=False),
        sa.Column("account_type", sa.String(32), nullable=False, server_default="User"),
        sa.Column("avatar_url", sa.String(1024)),
        sa.Column("installed_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("removed_at", sa.DateTime(timezone=True)),
        sa.UniqueConstraint("provider", "installation_id",
                            name="uq_repo_integrations_provider_install"),
    )
    op.create_index("ix_repo_integrations_org", "repo_integrations", ["org_id"])

    op.create_table(
        "repositories",
        sa.Column("id", postgresql.UUID(as_uuid=False), primary_key=True),
        sa.Column("org_id", postgresql.UUID(as_uuid=False),
                  sa.ForeignKey("orgs.id", ondelete="CASCADE"), nullable=False),
        sa.Column("integration_id", postgresql.UUID(as_uuid=False),
                  sa.ForeignKey("repo_integrations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("provider", sa.String(32), nullable=False, server_default="github"),
        sa.Column("provider_repo_id", sa.String(64), nullable=False),
        sa.Column("owner", sa.String(200), nullable=False),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("full_name", sa.String(400), nullable=False),
        sa.Column("default_branch", sa.String(200), nullable=False, server_default="main"),
        sa.Column("private", sa.Boolean, nullable=False, server_default=sa.text("false")),
        sa.Column("html_url", sa.String(1024), nullable=False),
        sa.Column("language", sa.String(64)),
        sa.Column("auto_scan_on_push", sa.Boolean, nullable=False, server_default=sa.text("true")),
        sa.Column("last_scan_id", postgresql.UUID(as_uuid=False)),
        sa.Column("last_scan_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("provider", "provider_repo_id",
                            name="uq_repositories_provider_repo"),
    )
    op.create_index("ix_repositories_org", "repositories", ["org_id"])

    op.create_table(
        "repo_scans",
        sa.Column("id", postgresql.UUID(as_uuid=False), primary_key=True),
        sa.Column("org_id", postgresql.UUID(as_uuid=False),
                  sa.ForeignKey("orgs.id", ondelete="CASCADE"), nullable=False),
        sa.Column("repository_id", postgresql.UUID(as_uuid=False),
                  sa.ForeignKey("repositories.id", ondelete="CASCADE"), nullable=False),
        sa.Column("commit_sha", sa.String(64)),
        sa.Column("ref", sa.String(256)),
        sa.Column("trigger", sa.String(32), nullable=False, server_default="manual"),
        sa.Column("status", sa.String(32), nullable=False, server_default="queued"),
        sa.Column("scanners", postgresql.JSONB),
        sa.Column("stats", postgresql.JSONB),
        sa.Column("started_at", sa.DateTime(timezone=True)),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
        sa.Column("error", sa.Text),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_repo_scans_repo_created",
                    "repo_scans", ["repository_id", "created_at"])

    op.create_table(
        "repo_findings",
        sa.Column("id", postgresql.UUID(as_uuid=False), primary_key=True),
        sa.Column("repo_scan_id", postgresql.UUID(as_uuid=False),
                  sa.ForeignKey("repo_scans.id", ondelete="CASCADE"), nullable=False),
        sa.Column("repository_id", postgresql.UUID(as_uuid=False),
                  sa.ForeignKey("repositories.id", ondelete="CASCADE"), nullable=False),
        sa.Column("scanner", sa.String(32), nullable=False),
        sa.Column("rule_id", sa.String(200)),
        sa.Column("severity", sa.String(16), nullable=False, server_default="medium"),
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("description", sa.Text),
        sa.Column("file_path", sa.String(1024)),
        sa.Column("line_start", sa.Integer),
        sa.Column("line_end", sa.Integer),
        sa.Column("code_snippet", sa.Text),
        sa.Column("cve", sa.String(64)),
        sa.Column("package", sa.String(200)),
        sa.Column("installed_version", sa.String(64)),
        sa.Column("fixed_version", sa.String(64)),
        sa.Column("raw", postgresql.JSONB),
        sa.Column("ai_explanation", sa.Text),
        sa.Column("fix_status", sa.String(32), nullable=False, server_default="none"),
        sa.Column("fix_pr_url", sa.String(1024)),
        sa.Column("suppressed", sa.Boolean, nullable=False, server_default=sa.text("false")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_repo_findings_scan_severity",
                    "repo_findings", ["repo_scan_id", "severity"])
    op.create_index("ix_repo_findings_repo_scanner",
                    "repo_findings", ["repository_id", "scanner"])


def downgrade() -> None:
    op.drop_index("ix_repo_findings_repo_scanner", table_name="repo_findings")
    op.drop_index("ix_repo_findings_scan_severity", table_name="repo_findings")
    op.drop_table("repo_findings")
    op.drop_index("ix_repo_scans_repo_created", table_name="repo_scans")
    op.drop_table("repo_scans")
    op.drop_index("ix_repositories_org", table_name="repositories")
    op.drop_table("repositories")
    op.drop_index("ix_repo_integrations_org", table_name="repo_integrations")
    op.drop_table("repo_integrations")
