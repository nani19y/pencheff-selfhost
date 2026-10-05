import asyncio
import sys
import types
import pencheff_api.services.scan_runner as sr


def _install_fake_server(monkeypatch, fake_srv):
    """Make ``import pencheff.server as srv`` resolve to ``fake_srv``.

    Patching only ``sys.modules`` is insufficient once the real
    ``pencheff.server`` submodule has been imported by an earlier test: the
    ``import pencheff.server`` statement then resolves ``srv`` from the parent
    package's ``server`` attribute, not from ``sys.modules``. Patch both so the
    test is order-independent.
    """
    monkeypatch.setitem(sys.modules, "pencheff.server", fake_srv)
    parent = sys.modules.get("pencheff")
    if parent is not None:
        monkeypatch.setattr(parent, "server", fake_srv, raising=False)


def test_run_ml_scan_invokes_tool(monkeypatch):
    called = {}

    async def _fake_scan_ml_model(session_id=None, ml_config=None):
        called["session_id"] = session_id
        called["ml_config"] = ml_config
        return {"new_findings": 0}

    fake_srv = types.SimpleNamespace(scan_ml_model=_fake_scan_ml_model)
    _install_fake_server(monkeypatch, fake_srv)

    psession = types.SimpleNamespace(id="sess1", ml_config={"kind": "ml_model", "source_type": "file_url", "url": "https://h/m.pkl"})

    asyncio.run(sr._run_ml_scan(scan_id="scan1", psession=psession, profile="quick",
                                db_session_factory=None))
    assert called["session_id"] == "sess1"
    assert called["ml_config"]["source_type"] == "file_url"


def test_run_ml_scan_missing_tool_is_non_fatal(monkeypatch):
    fake_srv = types.SimpleNamespace()   # no scan_ml_model attr
    _install_fake_server(monkeypatch, fake_srv)
    psession = types.SimpleNamespace(id="s", ml_config={})
    # must not raise
    asyncio.run(sr._run_ml_scan(scan_id="x", psession=psession, profile="quick", db_session_factory=None))
