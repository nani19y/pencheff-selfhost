import io
import json
import struct
import zipfile

from pencheff.modules.ml_scan.manifest import MlArtifact, MlManifest
from pencheff.modules.ml_scan.analyzers import (
    analyze_pickle_rce, analyze_format_safety, analyze_keras_lambda,
    analyze_provenance, run_all_static,
)


def _mf(*arts, source_type="file_url", origin="https://h/m", **kw):
    return MlManifest(source_type=source_type, origin=origin, artifacts=list(arts), **kw)


def test_pickle_format_is_flagged_even_without_dangerous_opcode():
    import pickle
    art = MlArtifact(name="m.pkl", data=pickle.dumps({"w": [1]}), fmt="pickle", size=10)
    fs = analyze_format_safety(_mf(art))
    assert any(f.metadata["technique"] == "ml:unsafe-format" for f in fs)


def test_safetensors_is_safe_no_finding():
    header = b'{"__metadata__":{}}'
    blob = struct.pack("<Q", len(header)) + header
    art = MlArtifact(name="m.safetensors", data=blob, fmt="safetensors", size=len(blob))
    assert analyze_format_safety(_mf(art)) == []


def test_pickle_rce_finding_from_dangerous_opcode():
    import os, pickle
    class E:
        def __reduce__(self): return (os.system, ("x",))
    art = MlArtifact(name="m.pkl", data=pickle.dumps(E()), fmt="pickle", size=10)
    fs = analyze_pickle_rce(_mf(art))
    assert fs and fs[0].metadata["technique"] == "ml:pickle-rce"
    assert fs[0].cwe_id == "CWE-502"


def test_keras_lambda_detected_in_keras_zip():
    cfg = {"config": {"layers": [{"class_name": "Lambda", "config": {}}]}}
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("config.json", json.dumps(cfg))
    art = MlArtifact(name="m.keras", data=buf.getvalue(), fmt="keras_zip", size=10)
    fs = analyze_keras_lambda(_mf(art))
    assert fs and fs[0].metadata["technique"] == "ml:keras-lambda"


def test_h5_is_flagged_as_keras_risk():
    art = MlArtifact(name="m.h5", data=b"\x89HDF\r\n\x1a\n" + b"\x00" * 8, fmt="hdf5", size=16)
    fs = analyze_keras_lambda(_mf(art))
    assert fs and fs[0].metadata["technique"] == "ml:keras-lambda"


def test_provenance_flags_hf_without_safetensors():
    import pickle
    art = MlArtifact(name="pytorch_model.bin", data=pickle.dumps({"w": 1}), fmt="pickle", size=10)
    mf = _mf(art, source_type="huggingface", origin="owner/model", provider="huggingface", hf_repo="owner/model")
    fs = analyze_provenance(mf)
    assert any(f.metadata["technique"] == "ml:supply-chain" for f in fs)


def test_run_all_static_aggregates():
    import os, pickle
    class E:
        def __reduce__(self): return (os.system, ("x",))
    art = MlArtifact(name="m.pkl", data=pickle.dumps(E()), fmt="pickle", size=10)
    fs = run_all_static(_mf(art))
    techniques = {f.metadata["technique"] for f in fs}
    assert "ml:pickle-rce" in techniques
    assert "ml:unsafe-format" in techniques
