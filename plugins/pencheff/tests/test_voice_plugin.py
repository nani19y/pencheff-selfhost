import asyncio
import pencheff.server as server


def test_scan_voice_tool_runs_static_noop(monkeypatch):
    # create_session auto-registers the session in the module-level store, so we
    # use the id it assigns (mirrors test_ml_plugin.py — there is no SESSIONS dict).
    sess = server.create_session(target_url="https://h/stt", depth="quick")
    fn = server.scan_voice.fn if hasattr(server.scan_voice, "fn") else server.scan_voice
    res = asyncio.run(fn(sess.id, {"kind": "voice", "source_type": "stt_endpoint", "url": "https://h/stt"}))
    # no live transport wired → 0 findings, but the tool returns the standard shape
    assert "new_findings" in res and "total_findings" in res
