# pencheff/modules/ml_scan/format_detect.py
"""Identify model file format by MAGIC BYTES (content), not extension.
Per JFrog CVE-2025-10155: extension-based routing is bypassable, so content wins.
Pure function — no I/O, no deserialization."""
from __future__ import annotations

import struct

_PICKLE_PROTO_OPCODES = {0x80}            # PROTO opcode (proto >= 2)
_PICKLE_PROTO0_FIRST = set(b"c(}]Kt.S\x8a")  # common proto-0/1 first opcodes


def _looks_like_safetensors(data: bytes) -> bool:
    if len(data) < 8:
        return False
    n = struct.unpack("<Q", data[:8])[0]
    # header length must be sane and point at a JSON object
    if not (0 < n <= len(data) - 8) or n > 100_000_000:
        return False
    head = data[8:8 + min(n, 64)].lstrip()
    if head[:1] != b"{":
        return False
    # Reject a pickle masquerading as safetensors: if trailing bytes remain
    # after the declared header and they begin with a pickle PROTO opcode
    # (\x80), treat it as a pickle so the opcode scanner runs on it.
    tail = 8 + n
    if tail < len(data) and data[tail] == 0x80:
        return False
    return True


def detect_format(data: bytes, name: str = "") -> str:
    """Return one of: safetensors, pytorch_zip, keras_zip, zip, pickle, hdf5,
    gguf, onnx, joblib, numpy, unknown. Content-first; extension only as a
    last-resort disambiguator."""
    if not data:
        return "unknown"
    # Zip-based containers (PyTorch .pt/.pth, .keras, generic zip)
    if data[:4] == b"PK\x03\x04":
        lname = name.lower()
        if lname.endswith(".keras"):
            return "keras_zip"
        # .pt/.pth and unknown zips → treat as pytorch_zip (we scan embedded pickles)
        return "pytorch_zip"
    if _looks_like_safetensors(data):
        return "safetensors"
    if data[:8] == b"\x89HDF\r\n\x1a\n":
        return "hdf5"
    if data[:4] == b"GGUF":
        return "gguf"
    if data[:6] == b"\x93NUMPY":
        return "numpy"
    # ONNX = protobuf; weak signal — only trust the extension here
    if name.lower().endswith(".onnx"):
        return "onnx"
    # Pickle: PROTO opcode (\x80) or a plausible proto-0 first opcode
    if data[0] in _PICKLE_PROTO_OPCODES:
        return "pickle"
    if data[0] in _PICKLE_PROTO0_FIRST:
        return "pickle"
    if name.lower().endswith((".joblib", ".pkl", ".pickle", ".bin")):
        # joblib files are zlib/pickle; default to pickle so opcode scan runs
        return "pickle"
    return "unknown"
