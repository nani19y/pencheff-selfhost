import asyncio
import os
import pickle
import struct

from pencheff.modules.ml_scan.fetcher import build_manifest


def test_local_path_reads_and_detects(tmp_path):
    p = tmp_path / "m.pkl"
    p.write_bytes(pickle.dumps({"w": [1, 2]}))
    cfg = {"kind": "ml_model", "source_type": "local_path", "local_path": str(p)}
    mf = asyncio.run(build_manifest(cfg))
    assert mf.source_type == "local_path"
    assert len(mf.artifacts) == 1
    assert mf.artifacts[0].fmt == "pickle"
    assert mf.artifacts[0].size > 0


def test_local_path_enforces_max_bytes(tmp_path):
    p = tmp_path / "big.bin"
    p.write_bytes(b"\x80\x04" + b"\x00" * 5000)
    cfg = {"kind": "ml_model", "source_type": "local_path", "local_path": str(p), "max_bytes": 1000}
    mf = asyncio.run(build_manifest(cfg))
    # bounded read: artifact data must not exceed max_bytes
    assert mf.artifacts[0].size <= 1000


def test_missing_local_path_records_error_non_fatal(tmp_path):
    cfg = {"kind": "ml_model", "source_type": "local_path", "local_path": str(tmp_path / "nope.pkl")}
    mf = asyncio.run(build_manifest(cfg))
    assert mf.artifacts == []
    assert mf.fetch_errors


def test_safetensors_detected_from_local(tmp_path):
    header = b'{"__metadata__":{}}'
    blob = struct.pack("<Q", len(header)) + header
    p = tmp_path / "m.safetensors"
    p.write_bytes(blob)
    cfg = {"kind": "ml_model", "source_type": "local_path", "local_path": str(p)}
    mf = asyncio.run(build_manifest(cfg))
    assert mf.artifacts[0].fmt == "safetensors"
