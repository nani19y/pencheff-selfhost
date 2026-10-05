"""Drop unused tables from withdrawn features.

Revision ID: 0032
Revises: 0031
Create Date: 2026-05-02

A no-op for fresh deployments. Acts as a safety net for any environment
where the original 0029/0030/0031 migrations had been applied (or
partially applied) before those features were removed:

  * ``ptaas_requests``               (was Phase 4.13, original revision 0029)
  * ``attack_surface_snapshots``     (was Phase 4.14, original revision 0030)
  * ``llm_campaign_runs``, ``llm_campaigns``  (was Phase 2.7 closeout, 0031)

The drop migration sits at 0032 — past the highest revision the broken
feature migrations reached — so it runs unconditionally for any DB that
got even a partial way through the original chain. Stub files at 0029,
0030, 0031 keep the chain intact for fresh DBs that never saw the
buggy migrations.

All four use ``IF EXISTS`` so this migration succeeds whether the
tables were ever created or not. Cascade is included so any downstream
indexes are removed alongside the tables.
"""
from typing import Union

from alembic import op


revision: str = "0032"
down_revision: Union[str, None] = "0031"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Order matters when CASCADE is unavailable — drop dependent tables
    # first. With CASCADE Postgres will sort it out either way.
    op.execute("DROP TABLE IF EXISTS llm_campaign_runs CASCADE")
    op.execute("DROP TABLE IF EXISTS llm_campaigns CASCADE")
    op.execute("DROP TABLE IF EXISTS attack_surface_snapshots CASCADE")
    op.execute("DROP TABLE IF EXISTS ptaas_requests CASCADE")


def downgrade() -> None:
    # Intentionally empty. The dropped tables belonged to features that
    # have been removed from the codebase; recreating them on downgrade
    # would orphan rows with no model to read them. If those features
    # come back, they'll ship their own forward migrations.
    pass
