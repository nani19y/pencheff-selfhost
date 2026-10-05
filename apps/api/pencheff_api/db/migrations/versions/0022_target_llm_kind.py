"""Target.kind discriminator + llm_config column.

Revision ID: 0022
Revises: 0021
Create Date: 2026-04-28

Adds two columns to the ``targets`` table so we can register a third
target kind alongside ``url`` and ``repo``: an ``llm`` endpoint subject
to red-team probing.

  * ``kind`` (String(16), default 'url') — explicit discriminator.
    Backfilled to 'repo' for any row whose ``repository_id`` is not
    NULL (the legacy implicit signal). Future inserts must specify
    kind explicitly so we drop the server_default after backfill.
  * ``llm_config`` (JSONB) — non-secret LLM target configuration:
    provider preset, model name, system prompt baseline, custom
    request template + response JSONPath. Secrets stay in the
    existing Fernet-encrypted ``credentials_encrypted`` blob.

Also adds ``ix_targets_workspace_kind_created`` so the dashboard can
filter targets by kind without a heap scan as the workload grows.
"""
from typing import Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0022"
down_revision: Union[str, None] = "0021"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Step 1: add kind with a server_default so existing rows are valid
    # the moment the column appears.
    op.add_column(
        "targets",
        sa.Column(
            "kind",
            sa.String(16),
            nullable=False,
            server_default="url",
        ),
    )
    # Step 2: add the JSONB llm_config column. Nullable; URL/repo
    # targets leave it NULL.
    op.add_column(
        "targets",
        sa.Column(
            "llm_config",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
        ),
    )
    # Step 3: backfill kind = 'repo' for the legacy mirror rows so the
    # API layer no longer has to compute kind from repository_id.
    op.execute(
        "UPDATE targets SET kind = 'repo' WHERE repository_id IS NOT NULL"
    )
    # Step 4: drop the server_default. Future inserts must specify kind
    # so a forgotten kind on a new code path raises rather than
    # silently filing as 'url'.
    op.alter_column("targets", "kind", server_default=None)
    # Step 5: composite index for the per-kind list endpoints
    # (/targets?kind=llm). Extends the existing
    # ix_targets_workspace_created so the kind filter is index-only.
    op.create_index(
        "ix_targets_workspace_kind_created",
        "targets",
        ["workspace_id", "kind", "created_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_targets_workspace_kind_created", table_name="targets")
    op.drop_column("targets", "llm_config")
    op.drop_column("targets", "kind")
