import asyncio
from pencheff.modules.voice_scan.dynamic_probes import run_dynamic_probes


def test_no_submit_fn_is_noop():
    cfg = {"kind": "voice", "source_type": "voice_bot", "url": "https://h/x", "audio_probes": True}
    findings = asyncio.run(run_dynamic_probes(cfg, submit_audio=None))
    assert findings == []


def test_cross_modal_injection_flagged_when_response_follows():
    async def submit_audio(wav_bytes, kind):
        # endpoint echoes the injected marker → it followed the instruction
        return {"status_code": 200, "text": "ok INJECT-CANARY done"}
    cfg = {"kind": "voice", "source_type": "voice_bot", "url": "https://h/x",
           "audio_probes": True, "injection_phrase": "INJECT-CANARY"}
    findings = asyncio.run(run_dynamic_probes(cfg, submit_audio=submit_audio))
    assert any(f.metadata.get("technique") == "voice:transcription-injection" for f in findings)


def test_auth_spoof_flagged_when_accepted():
    async def submit_audio(wav_bytes, kind):
        return {"status_code": 200, "json": {"verified": True}}
    cfg = {"kind": "voice", "source_type": "voice_auth", "url": "https://h/x", "audio_probes": True}
    findings = asyncio.run(run_dynamic_probes(cfg, submit_audio=submit_audio))
    assert any(f.metadata.get("technique") == "voice:auth-spoof" for f in findings)


def test_cross_modal_dataset_flags_each_complied_payload():
    from pencheff.modules.voice_scan.voice_payloads import CROSS_MODAL_PAYLOADS
    target = CROSS_MODAL_PAYLOADS[0]["marker"]

    async def submit_audio(wav_bytes, kind):
        # endpoint echoes only the first dataset payload's marker
        return {"status_code": 200, "text": f"sure {target} done"}

    cfg = {"kind": "voice", "source_type": "voice_bot", "url": "https://h/x", "audio_probes": True}
    findings = asyncio.run(run_dynamic_probes(cfg, submit_audio=submit_audio))
    inj = [f for f in findings if f.metadata.get("technique") == "voice:transcription-injection"]
    assert inj and any(f.metadata.get("payload_id") == CROSS_MODAL_PAYLOADS[0]["id"] for f in inj)


def test_replay_attack_flagged_when_identical_resubmission_accepted():
    calls = {"n": 0}

    async def submit_audio(wav_bytes, kind):
        calls["n"] += 1
        # both submissions accepted → no replay/nonce protection
        return {"status_code": 200, "json": {"verified": True}}

    cfg = {"kind": "voice", "source_type": "voice_auth", "url": "https://h/x", "audio_probes": True}
    findings = asyncio.run(run_dynamic_probes(cfg, submit_audio=submit_audio))
    assert any(f.metadata.get("technique") == "voice:replay-attack" for f in findings)
    assert calls["n"] >= 2  # submitted at least twice


def test_replay_attack_not_flagged_when_replay_rejected():
    calls = {"n": 0}

    async def submit_audio(wav_bytes, kind):
        calls["n"] += 1
        # first accepted, replay rejected → has replay protection
        return {"status_code": 200, "json": {"verified": True}} if calls["n"] == 1 \
            else {"status_code": 401, "json": {"verified": False}}

    cfg = {"kind": "voice", "source_type": "voice_auth", "url": "https://h/x", "audio_probes": True}
    findings = asyncio.run(run_dynamic_probes(cfg, submit_audio=submit_audio))
    assert not any(f.metadata.get("technique") == "voice:replay-attack" for f in findings)


def test_adversarial_audio_flagged_when_transcript_changes():
    import hashlib
    # Transcript depends on the audio BYTES, so base vs perturbed differ regardless
    # of how many other probes (dataset loop, ultrasonic) submitted first. The text
    # avoids every dataset marker/compliance term so only the adversarial probe fires.
    async def submit_audio(wav_bytes, kind):
        h = hashlib.sha256(wav_bytes).hexdigest()[:6]
        return {"status_code": 200, "text": f"the quoted figure was {h} units overall"}

    cfg = {"kind": "voice", "source_type": "stt_endpoint", "url": "https://h/x", "audio_probes": True}
    findings = asyncio.run(run_dynamic_probes(cfg, submit_audio=submit_audio))
    assert any(f.metadata.get("technique") == "voice:adversarial-audio" for f in findings)


def test_hallucination_flagged_on_non_speech():
    # A fixed, marker-free transcript returned for every submission: injection,
    # ultrasonic and adversarial (base==perturbed) all stay silent, so only the
    # silence/noise hallucination probe can fire.
    async def submit_audio(wav_bytes, kind):
        return {"status_code": 200, "text": "the meeting is at noon tomorrow"}

    cfg = {"kind": "voice", "source_type": "stt_endpoint", "url": "https://h/x", "audio_probes": True}
    findings = asyncio.run(run_dynamic_probes(cfg, submit_audio=submit_audio))
    assert any(f.metadata.get("technique") == "voice:transcript-hallucination" for f in findings)


def test_non_2xx_responses_never_flagged():
    # An auth wall: every call returns a 401 whose body varies (request_id). Before
    # the 2xx gate this tripped a bogus "unstable transcription" (adversarial) FP.
    calls = {"n": 0}

    async def submit_audio(wav_bytes, kind):
        calls["n"] += 1
        return {"status_code": 401, "text": f"unauthorized request_id={calls['n']}"}

    cfg = {"kind": "voice", "source_type": "stt_endpoint", "url": "https://h/x", "audio_probes": True}
    findings = asyncio.run(run_dynamic_probes(cfg, submit_audio=submit_audio))
    assert findings == []


def test_injection_not_run_for_pure_stt():
    # A pure STT just transcribes; echoing the spoken marker is not "compliance".
    async def submit_audio(wav_bytes, kind):
        return {"status_code": 200, "text": "ok INJECT-CANARY done"}
    cfg = {"kind": "voice", "source_type": "stt_endpoint", "url": "https://h/x",
           "audio_probes": True, "injection_phrase": "INJECT-CANARY"}
    findings = asyncio.run(run_dynamic_probes(cfg, submit_audio=submit_audio))
    assert not any(f.metadata.get("technique") == "voice:transcription-injection" for f in findings)


def test_number_confusion_flagged(monkeypatch):
    import pencheff.modules.voice_scan.dynamic_probes as dp
    monkeypatch.setattr(dp, "synth_tts_wav", lambda text, **k: b"RIFFdummy")

    async def submit_audio(wav_bytes, kind):
        return {"status_code": 200, "text": "the account number is nine one five zero"}  # 9150 != 9115
    cfg = {"kind": "voice", "source_type": "stt_endpoint", "url": "https://h/x", "audio_probes": True}
    findings = asyncio.run(dp.run_dynamic_probes(cfg, submit_audio=submit_audio))
    assert any(f.metadata.get("technique") == "voice:number-confusion" for f in findings)


def test_homophone_confusion_flagged(monkeypatch):
    import pencheff.modules.voice_scan.dynamic_probes as dp
    monkeypatch.setattr(dp, "synth_tts_wav", lambda text, **k: b"RIFFdummy")

    async def submit_audio(wav_bytes, kind):
        return {"status_code": 200, "text": "please allow this transaction"}
    cfg = {"kind": "voice", "source_type": "voice_bot", "url": "https://h/x", "audio_probes": True}
    findings = asyncio.run(dp.run_dynamic_probes(cfg, submit_audio=submit_audio))
    assert any(f.metadata.get("technique") == "voice:homophone-confusion" for f in findings)
