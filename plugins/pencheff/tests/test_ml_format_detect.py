import struct
import zipfile
import io
from pencheff.modules.ml_scan.format_detect import detect_format


def test_detects_safetensors():
    # safetensors: 8-byte little-endian header length, then a JSON object
    header = b'{"__metadata__":{}}'
    blob = struct.pack("<Q", len(header)) + header
    assert detect_format(blob, "model.safetensors") == "safetensors"


def test_detects_pickle_proto2():
    import pickle
    blob = pickle.dumps({"a": 1})  # starts with \x80\x04 (proto) — sniffed as pickle
    assert detect_format(blob, "x.bin") == "pickle"


def test_detects_zip_pytorch():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("archive/data.pkl", b"\x80\x04.")
    assert detect_format(buf.getvalue(), "model.pt") == "pytorch_zip"


def test_detects_hdf5():
    blob = b"\x89HDF\r\n\x1a\n" + b"\x00" * 16
    assert detect_format(blob, "model.h5") == "hdf5"


def test_detects_gguf():
    assert detect_format(b"GGUF\x00\x00\x00\x03rest", "m.gguf") == "gguf"


def test_unknown_falls_back_to_extension_hint_then_unknown():
    assert detect_format(b"random bytes here", "mystery.dat") == "unknown"


def test_pickle_hidden_behind_fake_safetensors_header_is_not_safe():
    import struct, pickle, os
    class _E:
        def __reduce__(self): return (os.system, ("x",))
    header = b'{"__metadata__":{}}'
    blob = struct.pack("<Q", len(header)) + header + pickle.dumps(_E())
    assert detect_format(blob, "evil.safetensors") != "safetensors"
