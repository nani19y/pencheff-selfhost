"""multi-kind scan pipelines

Revision ID: 0044
Revises: 0043
Create Date: 2026-05-16

Additive foundation for kind-aware scan pipelines (feature 001-multi-target-scan-pipelines).

Adds four nullable JSONB / LargeBinary / Boolean columns. No data backfill, no
constraints beyond NOT NULL DEFAULT on ``orgs.force_deterministic_only`` — safe on
PG ≥ 11 (default applied in-place, no heap rewrite).

* ``targets.kind_config`` — JSONB per-kind config for the 11 new non-llm kinds
  (web_app, rest_api, graphql, websocket, grpc, source_code, cicd_pipeline, iac,
  container_image, k8s_cluster, package_registry, sbom). Validated server-side by
  the ``KindConfig`` Pydantic discriminated union in ``schemas/targets.py``.
  Existing ``targets.llm_config`` keeps authoritative status for ``kind="llm"``.

* ``targets.kind_credentials_encrypted`` — Fernet-encrypted LargeBinary for kinds
  whose secrets don't fit the existing flat ``Credentials`` schema:
  ``container_image`` (registry auth tuples), ``k8s_cluster`` (kubeconfig YAML),
  ``cicd_pipeline`` (provider tokens / GitHub App private keys), ``source_code``
  with ``auth_type=github_app``. Same Fernet key (``settings.fernet_key``) and
  rotation policy as the existing ``targets.credentials_encrypted`` column.

* ``scans.kind_payload`` — JSONB per-scan operational overrides + derived payload.
  Server-derives from ``Target.kind_config`` at scan-creation time; clients may
  send a partial override (e.g., container_image digest pin for this run).
  Existing url/llm scans leave this NULL.

* ``orgs.force_deterministic_only`` — Boolean kill switch for AI orchestration on
  this org. Set by admin/owner only (RBAC enforced at the API layer in
  ``routers/orgs.py``). When true, ``dispatch_mode.resolve_dispatch_mode`` short-
  circuits to ``"deterministic_only"`` regardless of plan, quota, or beta override.

Downgrade drops all four columns.
"""
from __future__ import annotations

from typing import Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB


revision: str = "0044"
down_revision: Union[str, None] = "0043"
branch_labels: Union[str, tuple, None] = None
depends_on: Union[str, tuple, None] = None


def upgrade() -> None:
    op.add_column(
        "targets",
        sa.Column("kind_config", JSONB, nullable=True),
    )
    op.add_column(
        "targets",
        sa.Column("kind_credentials_encrypted", sa.LargeBinary(), nullable=True),
    )
    op.add_column(
        "scans",
        sa.Column("kind_payload", JSONB, nullable=True),
    )
    op.add_column(
        "orgs",
        sa.Column(
            "force_deterministic_only",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
    )


def downgrade() -> None:
    op.drop_column("orgs", "force_deterministic_only")
    op.drop_column("scans", "kind_payload")
    op.drop_column("targets", "kind_credentials_encrypted")
    op.drop_column("targets", "kind_config")
