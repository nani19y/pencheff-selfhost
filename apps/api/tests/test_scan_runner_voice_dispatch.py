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


def test_run_voice_scan_invokes_tool(monkeypatch):
    called = {}

    async def _fake_scan_voice(session_id=None, voice_config=None):
        called["session_id"] = session_id
        called["voice_config"] = voice_config
        return {"new_findings": 0}

    fake_srv = types.SimpleNamespace(scan_voice=_fake_scan_voice)
    _install_fake_server(monkeypatch, fake_srv)

    psession = types.SimpleNamespace(id="sess1", voice_config={"kind": "voice", "source_type": "stt_endpoint", "url": "https://h/stt"})

    asyncio.run(sr._run_voice_scan(scan_id="scan1", psession=psession, profile="quick",
                                   db_session_factory=None))
    assert called["session_id"] == "sess1"
    assert called["voice_config"]["source_type"] == "stt_endpoint"


def test_run_voice_scan_missing_tool_is_non_fatal(monkeypatch):
    fake_srv = types.SimpleNamespace()   # no scan_voice attr
    _install_fake_server(monkeypatch, fake_srv)
    psession = types.SimpleNamespace(id="s", voice_config={})
    # must not raise
    asyncio.run(sr._run_voice_scan(scan_id="x", psession=psession, profile="quick", db_session_factory=None))
