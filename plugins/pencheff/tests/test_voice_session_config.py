from pencheff.core.session import create_session


def test_voice_config_round_trips():
    cfg = {"kind": "voice", "source_type": "stt_endpoint", "url": "https://h/stt"}
    s = create_session(target_url="https://h/stt", depth="quick", voice_config=cfg)
    assert s.voice_config == cfg


def test_voice_config_defaults_none():
    s = create_session(target_url="x", depth="quick")
    assert s.voice_config is None
