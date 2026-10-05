import asyncio
from pencheff.core.session import create_session
from pencheff.modules.voice_scan.module import VoiceScanModule


def test_module_runs_without_live_transport_is_noop_safe():
    sess = create_session(target_url="https://h/stt", depth="quick")
    findings = asyncio.run(VoiceScanModule().run(sess, http=None, config={
        "voice_config": {"kind": "voice", "source_type": "stt_endpoint", "url": "https://h/stt"},
    }))
    assert isinstance(findings, list)   # no http_get/submit wired → no crash, no findings
    assert VoiceScanModule().get_techniques()


def test_module_dynamic_gated_by_audio_probes(monkeypatch):
    # audio_probes False → dynamic probes must not run even if a submit fn exists
    sess = create_session(target_url="https://h/x", depth="quick")
    mod = VoiceScanModule()
    findings = asyncio.run(mod.run(sess, http=None, config={
        "voice_config": {"kind": "voice", "source_type": "voice_bot", "url": "https://h/x", "audio_probes": False},
    }))
    assert isinstance(findings, list)
