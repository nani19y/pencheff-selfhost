from __future__ import annotations

from pencheff_api.db.models import Org


def test_org_has_security_lake_columns():
    cols = Org.__table__.columns
    assert "security_lake_enabled" in cols
    assert "security_lake_disabled_at" in cols
    assert cols["security_lake_enabled"].default.arg is False
    sd = cols["security_lake_enabled"].server_default.arg
    assert str(getattr(sd, "text", sd)) == "false"
    assert cols["security_lake_disabled_at"].nullable is True


def test_migration_0055_chains_from_0054():
    import importlib
    m = importlib.import_module(
        "pencheff_api.db.migrations.versions.0055_security_lake_org_toggle")
    assert m.revision == "0055"
    assert m.down_revision == "0054"
    assert hasattr(m, "upgrade") and hasattr(m, "downgrade")
