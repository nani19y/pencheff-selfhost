"""Native LSB extractor for PNG / BMP / WAV.

Source: standard LSB stego primer (any intro to stego).
"""

from __future__ import annotations

from pathlib import Path


def extract_lsb_image(path: str | Path, *, channels: str = "rgb", bits: int = 1) -> bytes:
    """Extract the LSB bitstream from each pixel channel and concatenate.

    Returns the raw byte string. Caller can feed it through ``auto_decode``.
    """
    try:
        from PIL import Image  # Pillow
    except ImportError as exc:
        raise RuntimeError("Pillow required for LSB image extraction") from exc

    img = Image.open(path).convert("RGBA")
    pixels = img.getdata()
    bitstream: list[int] = []
    channel_idx = {"r": 0, "g": 1, "b": 2, "a": 3}
    indices = [channel_idx[c] for c in channels.lower() if c in channel_idx]
    mask = (1 << bits) - 1
    for pixel in pixels:
        for ci in indices:
            bitstream.append(pixel[ci] & mask)

    out = bytearray()
    cur = 0
    nbits = 0
    for value in bitstream:
        cur = (cur << bits) | value
        nbits += bits
        while nbits >= 8:
            byte = (cur >> (nbits - 8)) & 0xFF
            out.append(byte)
            cur &= (1 << (nbits - 8)) - 1
            nbits -= 8
    return bytes(out)


def extract_lsb_wav(path: str | Path, *, bits: int = 1) -> bytes:
    """Extract the LSB bitstream from a WAV file's sample stream."""
    import wave

    with wave.open(str(path), "rb") as wav:
        frames = wav.readframes(wav.getnframes())
    samples = list(frames)  # bytes are already int8/16 packed; LSB applies per byte
    bitstream: list[int] = []
    mask = (1 << bits) - 1
    for s in samples:
        bitstream.append(s & mask)
    out = bytearray()
    cur = 0
    nbits = 0
    for value in bitstream:
        cur = (cur << bits) | value
        nbits += bits
        while nbits >= 8:
            out.append((cur >> (nbits - 8)) & 0xFF)
            cur &= (1 << (nbits - 8)) - 1
            nbits -= 8
    return bytes(out)
