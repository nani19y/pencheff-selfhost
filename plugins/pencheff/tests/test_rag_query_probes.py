import asyncio

from pencheff.modules.rag_scan import query_probes as qp


def test_extraction_prompts_nonempty_and_extraction_flavored():
    ps = qp.extraction_prompts()
    assert len(ps) >= 2
    joined = " ".join(ps).lower()
    assert "context" in joined or "documents" in joined or "repeat" in joined


def test_membership_canary_embeds_canary():
    q = qp.membership_canary("CANARY-XYZ-123")
    assert "CANARY-XYZ-123" in q


def test_response_leaks_canary():
    assert qp.response_leaks_canary("... the secret is CANARY-XYZ-123 ...", "CANARY-XYZ-123") is True
    assert qp.response_leaks_canary("nothing here", "CANARY-XYZ-123") is False


def test_response_indicates_extraction():
    chunks = ["Confidential: Project Aurora launches in Q3", "internal memo abc"]
    assert qp.response_indicates_extraction("Sure: Confidential: Project Aurora launches in Q3", chunks) is True
    assert qp.response_indicates_extraction("I can't help with that.", chunks) is False


def test_select_probes_gated():
    assert qp.select_probes(query_probes=False) == []
    assert len(qp.select_probes(query_probes=True)) >= 1


def test_run_query_probes_dedups_extraction_findings():
    chunk = "Confidential: Project Aurora launches in Q3 and will cost 5M dollars"

    class _MF:
        provider = "qdrant"
        endpoint = "http://q"
        samples = []

    async def fake_query_fn(prompt):
        # every prompt leaks the same chunk verbatim
        return [chunk]

    findings = asyncio.run(qp.run_query_probes(fake_query_fn, _MF(), {"query_probes": True}))
    extraction = [f for f in findings if (f.metadata or {}).get("technique") == "rag:datastore-extraction"]
    assert len(extraction) == 1  # deduped, not 5
