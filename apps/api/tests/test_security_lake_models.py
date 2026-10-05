from __future__ import annotations

from pencheff_api.db.models import LakeIngestion, LakeQuarantine


def test_lake_ingestion_columns():
    cols = set(LakeIngestion.__table__.columns.keys())
    assert {"id", "scan_id", "source", "org_id", "appended_count",
            "quarantined_count", "status", "error", "created_at"} <= cols
    # idempotency: one ingestion row per (scan_id, source)
    uniques = {tuple(sorted(c.name for c in con.columns))
               for con in LakeIngestion.__table__.constraints
               if con.__class__.__name__ == "UniqueConstraint"}
    assert ("scan_id", "source") in uniques


def test_lake_quarantine_columns():
    cols = set(LakeQuarantine.__table__.columns.keys())
    assert {"id", "scan_id", "source", "org_id", "error", "finding_repr",
            "created_at"} <= cols


def test_migration_0054_chains_from_0053():
    import importlib
    mod = importlib.import_module(
        "pencheff_api.db.migrations.versions.0054_security_lake_tables")
    assert mod.revision == "0054"
    assert mod.down_revision == "0053"
    assert hasattr(mod, "upgrade") and hasattr(mod, "downgrade")
