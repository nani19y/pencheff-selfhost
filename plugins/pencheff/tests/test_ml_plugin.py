import asyncio
import os
import pickle

import pencheff.server as server


def test_scan_ml_model_tool_registers_findings(monkeypatch):
    class _E:
        def __reduce__(self): return (os.system, ("x",))
    from pencheff.modules.ml_scan.manifest import MlArtifact, MlManifest
    art = MlArtifact(name="m.pkl", data=pickle.dumps(_E()), fmt="pickle", size=10)
    mf = MlManifest(source_type="file_url", origin="https://h/m.pkl", artifacts=[art])

    async def _fake_build(cfg): return mf
    monkeypatch.setattr("pencheff.modules.ml_scan.module.build_manifest", _fake_build)

    # create_session auto-registers the session in the module-level store, so we
    # use the id it assigns (mirrors how core/session.create_session works).
    sess = server.create_session(target_url="https://h/m.pkl", depth="quick")
    fn = server.scan_ml_model.fn if hasattr(server.scan_ml_model, "fn") else server.scan_ml_model
    res = asyncio.run(fn(sess.id, {"kind": "ml_model", "source_type": "file_url", "url": "https://h/m.pkl"}))
    assert res["new_findings"] >= 1
    assert res["total_findings"] >= 1
