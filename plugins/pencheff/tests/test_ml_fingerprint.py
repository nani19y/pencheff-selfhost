from pencheff.modules.ml_scan.manifest import MlArtifact, MlManifest
from pencheff.modules.ml_scan.fingerprint import fingerprint


def test_keras_h5_matches_safe_mode_advisory():
    art = MlArtifact(name="m.h5", data=b"\x89HDF\r\n\x1a\n", fmt="hdf5", size=8)
    mf = MlManifest(source_type="file_url", origin="https://h/m.h5", artifacts=[art])
    out = fingerprint(mf)
    assert any(f.metadata.get("technique") == "ml:known-vuln" for f in out)


def test_safetensors_matches_nothing():
    import struct
    blob = struct.pack("<Q", 2) + b"{}"
    art = MlArtifact(name="m.safetensors", data=blob, fmt="safetensors", size=len(blob))
    mf = MlManifest(source_type="file_url", origin="x", artifacts=[art])
    assert fingerprint(mf) == []
