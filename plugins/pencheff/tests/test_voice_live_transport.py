from pencheff.modules.voice_scan.live_transport import build_live_transport


def test_builder_returns_three_callables():
    cfg = {"kind": "voice", "source_type": "stt_endpoint", "url": "https://h/stt"}
    http_get, http_post, submit_audio = build_live_transport(cfg)
    assert callable(http_get) and callable(http_post) and callable(submit_audio)


def test_audio_multipart_shape_from_template():
    from pencheff.modules.voice_scan.live_transport import _audio_multipart
    # default: bare 'audio' field, no extra form data
    assert _audio_multipart({}) == ("audio", {})
    # Sarvam-style: custom file field + required model/language form fields
    cfg = {"request_template": '{"audio_field":"file","form_fields":{"model":"saarika:v2.5","language_code":"en-IN"}}'}
    field, form = _audio_multipart(cfg)
    assert field == "file"
    assert form == {"model": "saarika:v2.5", "language_code": "en-IN"}
    # a non-shape template (legacy {"headers":...}) must not crash → defaults
    assert _audio_multipart({"request_template": '{"headers":{"x":"y"}}'}) == ("audio", {})


def test_extract_transcript():
    from pencheff.modules.voice_scan.live_transport import _extract_transcript
    body = {"request_id": "20260806_x", "transcript": "open the door", "language_code": "en-IN"}
    # response_path pulls the transcript, NOT the whole envelope (which has digits)
    assert _extract_transcript(body, "$.transcript") == "open the door"
    # empty transcript stays empty (so silence never looks like a hallucination)
    assert _extract_transcript({"transcript": ""}, "$.transcript") == ""
    # fallback to common keys when no path given
    assert _extract_transcript({"text": "hello there"}, None) == "hello there"
    # missing → None (caller keeps raw text)
    assert _extract_transcript({"nope": 1}, "$.transcript") is None
