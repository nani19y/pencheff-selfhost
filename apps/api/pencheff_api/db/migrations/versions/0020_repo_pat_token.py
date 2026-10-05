"""PAT-authenticated private repository support.

Revision ID: 0020
Revises: 0019
Create Date: 2026-04-28

Adds ``repositories.token_encrypted`` so users who don't want to install
the GitHub App can paste a Personal Access Token (PAT) instead. The PAT
is stored Fernet-encrypted (same scheme as Target.credentials_encrypted)
and used as the ``x-access-token`` password for ``git clone`` in the
worker's repo-scan task. The PAT is never logged or returned through any
API surface — it only lands on the model row at registration time and is
read directly by ``run_repo_scan``.

Existing public-URL repos and GitHub-App-driven repos are unaffected:
``token_encrypted`` defaults to NULL and the scan task branches on
``token_encrypted IS NOT NULL`` only as a third clone strategy after
GitHub App install (which still wins when both are set).
"""
from typing import Union

import sqlalchemy as sa
from alembic import op

revision: str = "0020"
down_revision: Union[str, None] = "0019"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "repositories",
        sa.Column("token_encrypted", sa.LargeBinary(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("repositories", "token_encrypted")
