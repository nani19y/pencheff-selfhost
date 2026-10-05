from pencheff.modules.rag_scan.manifest import RagManifest, RagIndex, RagSampleChunk
from pencheff.modules.rag_scan import static_analyzers as sa


def _mf(**kw):
    base = dict(source_type="managed_vdb", provider="qdrant", endpoint="https://q:6333")
    base.update(kw); return RagManifest(**base)


def test_exposure_flags_no_auth():
    f = sa.analyze_exposure(_mf(auth_required=False))
    assert len(f) >= 1 and f[0].cwe_id == "CWE-306"


def test_exposure_clean_when_auth_required():
    assert sa.analyze_exposure(_mf(auth_required=True)) == []


def test_tenancy_flags_missing_isolation():
    f = sa.analyze_tenancy(_mf(tenancy_isolation=False))
    assert len(f) >= 1 and f[0].owasp_category == "LLM08"


def test_tenancy_clean_when_isolated():
    assert sa.analyze_tenancy(_mf(tenancy_isolation=True)) == []


def test_secrets_at_rest_flags_secret_in_chunk():
    mf = _mf(samples=[RagSampleChunk(index="docs", chunk_id="c1",
             text="here is the AWS key AKIAIOSFODNN7EXAMPLE")])
    f = sa.analyze_secrets_at_rest(mf)
    assert len(f) >= 1 and f[0].owasp_category == "LLM02"


def test_secrets_at_rest_clean():
    mf = _mf(samples=[RagSampleChunk(index="docs", chunk_id="c1", text="the cat sat on the mat")])
    assert sa.analyze_secrets_at_rest(mf) == []


def test_invertibility_risk_flags_raw_export_known_encoder_no_auth():
    mf = _mf(raw_embedding_export=True, encoder_hint="text-embedding-ada-002", auth_required=False)
    f = sa.analyze_invertibility_risk(mf)
    assert len(f) >= 1 and f[0].owasp_category in ("LLM08", "LLM02")


def test_invertibility_risk_low_when_no_raw_export():
    assert sa.analyze_invertibility_risk(_mf(raw_embedding_export=False)) == []


def test_run_all_aggregates():
    cats = {f.owasp_category for f in sa.run_all_static(_mf(auth_required=False, tenancy_isolation=False))}
    assert "LLM08" in cats


def test_exposure_none_does_not_flag():
    # auth_required unknown (None) must NOT produce a finding (avoid false positives)
    assert sa.analyze_exposure(_mf(auth_required=None)) == []


def test_tenancy_none_does_not_flag():
    assert sa.analyze_tenancy(_mf(tenancy_isolation=None)) == []


def test_invertibility_severity_split_high_when_no_auth():
    high = sa.analyze_invertibility_risk(_mf(raw_embedding_export=True, auth_required=False))
    med = sa.analyze_invertibility_risk(_mf(raw_embedding_export=True, auth_required=True))
    assert high and med
    # the no-auth case must be at least as severe as the auth case
    sev_order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    def _rank(f):
        v = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
        return sev_order.get(str(v).lower(), 0)
    assert _rank(high[0]) >= _rank(med[0])


def test_baseline_hash_order_independent_and_change_sensitive():
    from pencheff.modules.rag_scan.manifest import RagIndex
    a = _mf(indexes=[RagIndex(name="x", dimensions=768), RagIndex(name="y", dimensions=1536)])
    b = _mf(indexes=[RagIndex(name="y", dimensions=1536), RagIndex(name="x", dimensions=768)])
    assert sa.baseline_hash(a) == sa.baseline_hash(b)
    c = _mf(indexes=[RagIndex(name="x", dimensions=999)])
    assert sa.baseline_hash(a) != sa.baseline_hash(c)
