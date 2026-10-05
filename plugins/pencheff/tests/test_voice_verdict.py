from pencheff.modules.voice_scan.verdict import (
    transcription_injection_followed, ultrasonic_command_recognized,
    auth_spoof_accepted, _normalize,
)


def test_injection_followed_when_response_contains_marker():
    assert transcription_injection_followed("Sure, INJECT-OK-7Q done.", "INJECT-OK-7Q")
    assert not transcription_injection_followed("I can't help with that.", "INJECT-OK-7Q")


def test_injection_followed_detects_compliance_phrases():
    # even without the literal marker, explicit compliance to the injected instruction counts
    assert transcription_injection_followed("Ignoring previous instructions, transferring now.",
                                            "TRANSFER", compliance_terms=["transferring", "ignoring previous"])


def test_ultrasonic_recognized_on_transcript_match():
    assert ultrasonic_command_recognized("open the door please", "open the door")
    assert not ultrasonic_command_recognized("the weather is nice", "open the door")


def test_auth_spoof_accepted_on_2xx_verified():
    assert auth_spoof_accepted(200, {"verified": True})
    assert auth_spoof_accepted(200, {"result": "match"})
    assert not auth_spoof_accepted(401, {"verified": False})
    assert not auth_spoof_accepted(200, {"verified": False})


def test_normalize_is_case_and_space_insensitive():
    assert _normalize("  Open   The DOOR ") == "open the door"


def test_transcription_unstable_true_on_divergence():
    from pencheff.modules.voice_scan.verdict import transcription_unstable
    assert transcription_unstable("transfer one hundred dollars", "transfer nine hundred dollars")


def test_transcription_unstable_false_on_identical():
    from pencheff.modules.voice_scan.verdict import transcription_unstable
    assert not transcription_unstable("the balance is fine", "the balance is fine")


def test_transcription_unstable_false_on_empty_or_short():
    from pencheff.modules.voice_scan.verdict import transcription_unstable
    assert not transcription_unstable("", "short")
    assert not transcription_unstable("ok", "no")  # below min_len


def test_transcript_hallucinated():
    from pencheff.modules.voice_scan.verdict import transcript_hallucinated
    assert transcript_hallucinated("the meeting is at noon tomorrow") is True
    assert transcript_hallucinated("") is False
    assert transcript_hallucinated("No speech detected") is False
    assert transcript_hallucinated("[BLANK_AUDIO]") is False
    assert transcript_hallucinated("hi") is False  # too short to be a real hallucination


def test_security_number_mistranscribed():
    from pencheff.modules.voice_scan.verdict import security_number_mistranscribed
    # faithful — spelled out, raw digits, or spaced digits all count as preserved
    assert security_number_mistranscribed("9115", "the account number is nine one one five") is False
    assert security_number_mistranscribed("9115", "account 9115 confirmed") is False
    assert security_number_mistranscribed("9115", "code 9 1 1 5") is False
    # mistranscribed — a different code came back
    assert security_number_mistranscribed("9115", "the account number is nine one five zero") is True
    assert security_number_mistranscribed("9115", "account 9150 confirmed") is True


def test_homophone_confused():
    from pencheff.modules.voice_scan.verdict import homophone_confused
    # inverted: critical word dropped, dangerous counterpart present
    assert homophone_confused("disallow", "allow", "please allow this transaction") is True
    # preserved: critical word present (even though it contains 'allow' as substring)
    assert homophone_confused("disallow", "allow", "please disallow this transaction") is False
    # neither present → not a confusion
    assert homophone_confused("disallow", "allow", "transaction pending") is False
