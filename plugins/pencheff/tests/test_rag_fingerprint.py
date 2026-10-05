from pencheff.modules.rag_scan.manifest import RagManifest, RagIndex
from pencheff.modules.rag_scan import fingerprint as fp


def _mf(**kw):
    base = dict(source_type="self_hosted_vdb", provider="weaviate", endpoint="http://w:8080")
    base.update(kw)
    return RagManifest(**base)


def test_flags_known_provider_advisory():
    # weaviate is a seeded provider — posture advisory fires on any detection
    findings = fp.fingerprint(_mf(provider="weaviate"))
    assert len(findings) >= 1
    assert all(hasattr(f, "title") for f in findings)


def test_benign_unknown_provider_no_findings():
    assert fp.fingerprint(_mf(provider="totally-unknown-vendor-xyz")) == []


def test_version_gate_does_not_flag_patched():
    # Advisory for qdrant has vulnerable_below="1.7.0"; version 9999.0.0 must NOT fire
    mf = _mf(provider="qdrant")
    mf.indexes = [RagIndex(name="i", metadata={"version": "9999.0.0"})]
    flagged_cves = [
        (f.metadata or {}).get("cve")
        for f in fp.fingerprint(mf)
        if (f.metadata or {}).get("cve") is not None
    ]
    # No CVE advisory should fire for a version way beyond the fix
    assert flagged_cves == []


def test_version_gate_flags_vulnerable_version():
    # qdrant advisory fires when detected version < vulnerable_below
    mf = _mf(provider="qdrant")
    mf.indexes = [RagIndex(name="i", metadata={"version": "1.6.0"})]
    cve_findings = [f for f in fp.fingerprint(mf) if (f.metadata or {}).get("cve")]
    assert len(cve_findings) >= 1


def test_chroma_posture_advisory_fires():
    findings = fp.fingerprint(_mf(provider="chroma"))
    assert len(findings) >= 1
    assert any("chroma" in f.title.lower() or "chromadb" in f.description.lower() for f in findings)


def test_milvus_posture_advisory_fires():
    findings = fp.fingerprint(_mf(provider="milvus"))
    assert len(findings) >= 1


def test_finding_fields_correct():
    findings = fp.fingerprint(_mf(provider="weaviate"))
    f = findings[0]
    assert f.category == "rag_known_vuln"
    assert f.owasp_category == "LLM08"
    assert (f.metadata or {}).get("technique") == "rag:known-vuln"
