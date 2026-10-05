"""Target.disciplines — security-program tags (KSPM, ASPM, AI-SPM, …).

Revision ID: 0048
Revises: 0047
Create Date: 2026-05-21

A Target can carry one or more discipline tags. Each discipline maps to a
fixed set of compatible target kinds in schemas/targets.py::DISCIPLINE_TO_KINDS
(KSPM/KIEM → k8s_cluster; CWPP → container_image + k8s_cluster + host; ASPM →
web_app + rest_api + source_code; API Security → rest_api + graphql;
AI Red Teaming / AI-SPM → llm; SBOM analysis → sbom). Disciplines are surfaced
in the UI as a "By Discipline" tab on Step 1 of /targets/new — selecting one
auto-checks the underlying target-type cards.

Default NULL: every pre-existing row is untagged. The list endpoints + edit
forms read NULL as an empty list so behaviour is unchanged for legacy rows.
"""
from __future__ import annotations

from typing import Union

import sqlalchemy as sa
from alembic import op


revision: str = "0048"
down_revision: Union[str, None] = "0047"
branch_labels: Union[str, tuple, None] = None
depends_on: Union[str, tuple, None] = None


def upgrade() -> None:
    op.add_column(
        "targets",
        sa.Column("disciplines", sa.ARRAY(sa.String()), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("targets", "disciplines")
