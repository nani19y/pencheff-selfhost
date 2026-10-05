from __future__ import annotations
import pytest
from pydantic import ValidationError, TypeAdapter
from pencheff_api.schemas.targets import KindConfig
_adapter = TypeAdapter(KindConfig)
def _parse(d): return _adapter.validate_python(d)


def test_requires_url():
    ok = _parse({"kind": "voice", "source_type": "stt_endpoint", "url": "https://h/stt"})
    assert ok.source_type == "stt_endpoint"
    with pytest.raises(ValidationError):
        _parse({"kind": "voice", "source_type": "stt_endpoint"})


def test_all_source_types_accepted():
    for st in ("stt_endpoint", "voice_bot", "tts_endpoint", "voice_auth"):
        cfg = _parse({"kind": "voice", "source_type": st, "url": "https://h/x"})
        assert cfg.source_type == st


def test_defaults_and_extra_forbidden():
    cfg = _parse({"kind": "voice", "source_type": "voice_bot", "url": "https://h/x"})
    assert cfg.audio_format == "wav"
    assert cfg.audio_probes is False
    with pytest.raises(ValidationError):
        _parse({"kind": "voice", "source_type": "voice_bot", "url": "https://h/x", "bogus": 1})


def test_audio_probes_flag_round_trips():
    cfg = _parse({"kind": "voice", "source_type": "voice_auth", "url": "https://h/x", "audio_probes": True})
    assert cfg.audio_probes is True
