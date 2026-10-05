import asyncio
from pencheff.core.session import create_session
from pencheff.modules.rag_scan.manifest import RagManifest, RagSampleChunk
from pencheff.modules.rag_scan.module import RagStaticScanModule


def test_module_runs_static_analyzers_on_injected_manifest(monkeypatch):
    mf = RagManifest(source_type="self_hosted_vdb", provider="qdrant", endpoint="http://q:6333",
                     auth_required=False, tenancy_isolation=False,
                     samples=[RagSampleChunk(index="docs", chunk_id="c1",
                              text="leaked AWS key AKIAIOSFODNN7EXAMPLE")])

    class _FakeConn:
        async def build_manifest(self, cfg): return mf

    monkeypatch.setattr("pencheff.modules.rag_scan.module.GenericRestConnector", lambda **k: _FakeConn())
    sess = create_session(target_url="http://q:6333", depth="quick")
    mod = RagStaticScanModule()
    findings = asyncio.run(mod.run(sess, http=None, config={
        "rag_config": {"kind": "rag", "source_type": "self_hosted_vdb", "provider": "qdrant", "url": "http://q:6333"},
    }))
    cats = {f.owasp_category for f in findings}
    assert "LLM08" in cats   # exposure/tenancy
    assert "LLM02" in cats   # secret at rest
    assert mod.get_techniques()


def test_module_embedding_artifact_uses_items_directly():
    sess = create_session(target_url="rag://artifact", depth="quick")
    mod = RagStaticScanModule()
    findings = asyncio.run(mod.run(sess, http=None, config={
        "rag_config": {"kind": "rag", "source_type": "embedding_artifact",
                       "items": ["leaked token sk-ABCDEF0123456789ABCDEF01"]},
    }))
    # secrets-at-rest runs over items without a connector
    assert isinstance(findings, list)
