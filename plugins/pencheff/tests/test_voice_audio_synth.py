import io
import wave

import numpy as np

from pencheff.modules.voice_scan.audio_synth import (
    synth_tone_wav, synth_speechlike_wav, synth_ultrasonic_command_wav,
    synth_perturbed_wav, read_wav_samples,
)


def _parse_wav(blob: bytes):
    with wave.open(io.BytesIO(blob), "rb") as w:
        assert w.getsampwidth() == 2
        n = w.getnframes()
        raw = w.readframes(n)
    return np.frombuffer(raw, dtype="<i2"), w


def test_tone_is_valid_wav_with_expected_frequency():
    sr = 16000
    blob = synth_tone_wav(freq=1000.0, duration_s=0.25, sample_rate=sr)
    samples, _ = _parse_wav(blob)
    assert len(samples) == int(sr * 0.25)
    # dominant frequency near 1000 Hz
    spec = np.abs(np.fft.rfft(samples.astype(float)))
    freqs = np.fft.rfftfreq(len(samples), 1.0 / sr)
    assert abs(freqs[int(np.argmax(spec))] - 1000.0) < 50.0


def test_speechlike_is_deterministic():
    a = synth_speechlike_wav("attack marker XJ9")
    b = synth_speechlike_wav("attack marker XJ9")
    c = synth_speechlike_wav("different")
    assert a == b           # deterministic for same marker
    assert a != c           # marker influences the waveform


def test_ultrasonic_carrier_is_above_human_hearing():
    sr = 48000
    blob = synth_ultrasonic_command_wav("open door", carrier_hz=21000.0, sample_rate=sr)
    samples, _ = _parse_wav(blob)
    spec = np.abs(np.fft.rfft(samples.astype(float)))
    freqs = np.fft.rfftfreq(len(samples), 1.0 / sr)
    dominant = freqs[int(np.argmax(spec))]
    assert dominant > 18000.0   # energy concentrated in the ultrasonic band


def test_perturbed_is_close_but_not_equal():
    base = synth_tone_wav(freq=440.0, duration_s=0.1, sample_rate=16000)
    pert = synth_perturbed_wav(base, eps=0.02)
    b = read_wav_samples(base).astype(float)
    p = read_wav_samples(pert).astype(float)
    assert pert != base
    # bounded perturbation: max abs delta within eps of full-scale (32767)
    assert np.max(np.abs(p - b)) <= 0.02 * 32767 + 2


def test_silence_and_noise_are_valid_wavs():
    from pencheff.modules.voice_scan.audio_synth import (
        synth_silence_wav, synth_noise_wav, read_wav_samples)
    for blob in (synth_silence_wav(), synth_noise_wav()):
        assert blob[:4] == b"RIFF"
        assert len(read_wav_samples(blob)) > 0
    # silence must be materially quieter than noise
    import numpy as np
    sil = np.abs(read_wav_samples(synth_silence_wav()).astype(float)).mean()
    noise = np.abs(read_wav_samples(synth_noise_wav()).astype(float)).mean()
    assert sil < noise


def test_tts_and_ultrasonic_speech_degrade_gracefully():
    # espeak-ng may be absent locally: synth_tts_wav returns None and the
    # ultrasonic-speech carrier must also return None (never raise). When present,
    # both must be valid WAVs and the ultrasonic energy must sit above ~16 kHz.
    import io, wave
    import numpy as np
    from pencheff.modules.voice_scan.audio_synth import (
        synth_tts_wav, synth_ultrasonic_speech_wav)
    tts = synth_tts_wav("open the door")
    ultra = synth_ultrasonic_speech_wav("open the door")
    if tts is None:
        assert ultra is None
        return
    assert tts[:4] == b"RIFF" and ultra[:4] == b"RIFF"
    with wave.open(io.BytesIO(ultra), "rb") as w:
        sr = w.getframerate()
        x = np.frombuffer(w.readframes(w.getnframes()), dtype="<i2").astype(float)
    mag = np.abs(np.fft.rfft(x))
    freqs = np.fft.rfftfreq(len(x), 1.0 / sr)
    assert freqs[int(np.argmax(mag))] > 16000  # dominant energy is ultrasonic-ish
