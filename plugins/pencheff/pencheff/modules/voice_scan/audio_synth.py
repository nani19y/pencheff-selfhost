# pencheff/modules/voice_scan/audio_synth.py
"""Pure audio synthesis for voice-AI probing. stdlib `wave` + numpy only —
no TTS/librosa/torch. All functions are deterministic and unit-tested.
These craft test signals; they do NOT transmit anything (transport is separate)."""
from __future__ import annotations

import hashlib
import io
import logging
import shutil
import subprocess
import wave

import numpy as np

log = logging.getLogger("pencheff.modules.voice_scan.audio_synth")

_MAX_INT16 = 32767


def _pack_wav(samples: np.ndarray, sample_rate: int) -> bytes:
    """Encode a float [-1,1] (or int16) array as a 16-bit mono PCM WAV."""
    arr = np.asarray(samples)
    if arr.dtype != np.int16:
        arr = np.clip(arr, -1.0, 1.0)
        arr = (arr * _MAX_INT16).astype("<i2")
    buf = io.BytesIO()
    with wave.open(buf, "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(sample_rate)
        w.writeframes(arr.tobytes())
    return buf.getvalue()


def read_wav_samples(blob: bytes) -> np.ndarray:
    """Decode a 16-bit mono PCM WAV to an int16 numpy array."""
    with wave.open(io.BytesIO(blob), "rb") as w:
        raw = w.readframes(w.getnframes())
    return np.frombuffer(raw, dtype="<i2").copy()


def synth_tone_wav(freq: float = 1000.0, duration_s: float = 0.5,
                   sample_rate: int = 16000, amplitude: float = 0.6) -> bytes:
    n = int(sample_rate * duration_s)
    t = np.arange(n) / sample_rate
    sig = amplitude * np.sin(2 * np.pi * freq * t)
    return _pack_wav(sig, sample_rate)


def _marker_seed(marker: str) -> int:
    return int.from_bytes(hashlib.sha256(marker.encode("utf-8")).digest()[:4], "big")


def synth_speechlike_wav(marker: str, duration_s: float = 1.0,
                         sample_rate: int = 16000) -> bytes:
    """A deterministic, marker-dependent multi-tone 'carrier'. v1 is NOT real
    TTS (no spoken words) — it is a reproducible signal whose content depends on
    the marker, used for cross-modal/transport probing. The cross-modal verdict
    keys off the ENDPOINT RESPONSE, not on STT recovering this marker."""
    rng = np.random.default_rng(_marker_seed(marker))
    n = int(sample_rate * duration_s)
    t = np.arange(n) / sample_rate
    sig = np.zeros(n)
    # 3 formant-like tones seeded by the marker → deterministic but content-varying
    for f0 in rng.uniform(200, 3000, size=3):
        sig += 0.3 * np.sin(2 * np.pi * f0 * t)
    sig /= np.max(np.abs(sig)) or 1.0
    return _pack_wav(0.7 * sig, sample_rate)


def synth_silence_wav(duration_s: float = 1.0, sample_rate: int = 16000) -> bytes:
    """Near-silence (tiny dither, ~-66 dBFS): a valid non-empty PCM frame that a
    well-behaved STT should transcribe as empty. Substantial text back = the STT
    hallucinated words. Dithered (not all-zero) so strict encoders don't reject it."""
    n = int(sample_rate * duration_s)
    rng = np.random.default_rng(7)
    sig = rng.uniform(-1.0, 1.0, size=n) * 0.0005
    return _pack_wav(sig, sample_rate)


def synth_noise_wav(duration_s: float = 1.0, sample_rate: int = 16000,
                    amplitude: float = 0.3) -> bytes:
    """Full-band white noise — non-speech. A well-behaved STT returns no words;
    a transcript here is a hallucination (Whisper-class ghost-command vector)."""
    rng = np.random.default_rng(99)
    sig = rng.uniform(-1.0, 1.0, size=int(sample_rate * duration_s)) * amplitude
    return _pack_wav(sig, sample_rate)


def synth_tts_wav(text: str, *, speed: int = 150) -> bytes | None:
    """Render TEXT to intelligible SPEECH via espeak-ng (offline TTS). Returns
    16-bit PCM WAV bytes, or None when espeak-ng is unavailable — callers then
    fall back to the wordless carrier or skip. Text is piped via stdin so it can
    never be interpreted as a command-line flag (injection_phrase is untrusted)."""
    if not text or shutil.which("espeak-ng") is None:
        return None
    try:
        proc = subprocess.run(
            ["espeak-ng", "--stdout", "-s", str(int(speed))],
            input=text.encode("utf-8"), capture_output=True, timeout=20,
        )
    except (OSError, subprocess.SubprocessError) as e:  # noqa: BLE001
        log.warning("espeak-ng TTS failed: %s", e)
        return None
    wav = proc.stdout
    if not wav or wav[:4] != b"RIFF":
        return None
    # espeak-ng --stdout writes a STREAMING WAV whose header data-chunk size can be
    # a placeholder (it doesn't know the length up front), so downstream APIs misread
    # the duration as enormous ("exceeds 30 seconds"). Re-pack with an accurate header.
    try:
        with wave.open(io.BytesIO(wav), "rb") as w:
            sr = w.getframerate()
            frames = w.readframes(w.getnframes())
        samples = np.frombuffer(frames, dtype="<i2")
        if samples.size:
            return _pack_wav(samples, sr)
    except Exception as e:  # noqa: BLE001
        log.warning("espeak WAV re-pack failed, using raw: %s", e)
    return wav


def synth_ultrasonic_speech_wav(text: str, carrier_hz: float = 21000.0,
                                sample_rate: int = 48000) -> bytes | None:
    """DolphinAttack with REAL speech: AM-modulate the espeak speech envelope onto
    an ultrasonic (>20 kHz, inaudible) carrier. A voice front-end that demodulates
    (microphone/ADC nonlinearity) recovers the spoken words — so a transcript
    containing the command proves an inaudible command was decoded. None when
    espeak-ng is unavailable."""
    speech_wav = synth_tts_wav(text)
    if speech_wav is None:
        return None
    with wave.open(io.BytesIO(speech_wav), "rb") as w:
        sr_s = w.getframerate()
        speech = np.frombuffer(w.readframes(w.getnframes()), dtype="<i2").astype(np.float64)
    if speech.size == 0:
        return None
    speech /= np.max(np.abs(speech)) or 1.0
    # Resample speech up to the ultrasonic sample rate (linear interp is enough).
    n_out = int(len(speech) * sample_rate / sr_s)
    if n_out <= 0:
        return None
    xp = np.linspace(0.0, 1.0, num=len(speech), endpoint=False)
    x = np.linspace(0.0, 1.0, num=n_out, endpoint=False)
    speech_rs = np.interp(x, xp, speech)
    t = np.arange(n_out) / sample_rate
    baseband = 1.0 + 0.5 * speech_rs                    # AM index 0.5
    carrier = np.cos(2 * np.pi * carrier_hz * t)
    sig = baseband * carrier
    sig /= np.max(np.abs(sig)) or 1.0
    return _pack_wav(0.9 * sig, sample_rate)


def synth_ultrasonic_command_wav(payload: str, carrier_hz: float = 21000.0,
                                 duration_s: float = 1.0, sample_rate: int = 48000) -> bytes:
    """DolphinAttack-style: amplitude-modulate a baseband envelope (seeded by the
    payload) onto an ultrasonic carrier above human hearing. The energy sits at
    carrier_hz ± baseband (verified spectrally in tests)."""
    rng = np.random.default_rng(_marker_seed(payload))
    n = int(sample_rate * duration_s)
    t = np.arange(n) / sample_rate
    baseband = 0.5 * (1.0 + np.sin(2 * np.pi * rng.uniform(100, 400) * t))  # [0,1] env
    carrier = np.sin(2 * np.pi * carrier_hz * t)
    sig = baseband * carrier
    sig /= np.max(np.abs(sig)) or 1.0
    return _pack_wav(0.8 * sig, sample_rate)


def synth_perturbed_wav(base_wav: bytes, eps: float = 0.02) -> bytes:
    """Add a small, deterministic bounded perturbation (adversarial-lite). eps is
    a fraction of full-scale. Reads the base WAV's sample rate to round-trip."""
    with wave.open(io.BytesIO(base_wav), "rb") as w:
        sr = w.getframerate()
    samples = read_wav_samples(base_wav).astype(np.int64)
    rng = np.random.default_rng(1234)
    delta = (rng.uniform(-1.0, 1.0, size=len(samples)) * eps * _MAX_INT16).astype(np.int64)
    out = np.clip(samples + delta, -_MAX_INT16, _MAX_INT16).astype("<i2")
    return _pack_wav(out, sr)
