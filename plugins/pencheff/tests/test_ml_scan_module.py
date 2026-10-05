import asyncio
import os
import pickle

from pencheff.core.session import create_session
from pencheff.modules.ml_scan.manifest import MlArtifact, MlManifest
from pencheff.modules.ml_scan.module import MlStaticScanModule


def test_module_runs_static_on_injected_manifest(monkeypatch):
    class _E:
        def __reduce__(self): return (os.system, ("x",))
    art = MlArtifact(name="m.pkl", data=pickle.dumps(_E()), fmt="pickle", size=10)
    mf = MlManifest(source_type="file_url", origin="https://h/m.pkl", artifacts=[art])

    async def _fake_build(cfg): return mf
    monkeypatch.setattr("pencheff.modules.ml_scan.module.build_manifest", _fake_build)

    sess = create_session(target_url="https://h/m.pkl", depth="quick")
    findings = asyncio.run(MlStaticScanModule().run(sess, http=None, config={
        "ml_config": {"kind": "ml_model", "source_type": "file_url", "url": "https://h/m.pkl"},
    }))
    techniques = {f.metadata["technique"] for f in findings}
    assert "ml:pickle-rce" in techniques
    assert MlStaticScanModule().get_techniques()


def test_module_non_fatal_on_fetch_error(monkeypatch):
    mf = MlManifest(source_type="file_url", origin="x")
    mf.fetch_errors.append("boom")

    async def _fake_build(cfg): return mf
    monkeypatch.setattr("pencheff.modules.ml_scan.module.build_manifest", _fake_build)
    sess = create_session(target_url="x", depth="quick")
    findings = asyncio.run(MlStaticScanModule().run(sess, http=None, config={
        "ml_config": {"kind": "ml_model", "source_type": "file_url", "url": "x"},
    }))
    assert isinstance(findings, list)   # no artifacts → no crash
