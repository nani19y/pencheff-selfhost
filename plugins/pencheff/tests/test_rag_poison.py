import asyncio

import httpx

from pencheff.modules.rag_scan import poison as po
from pencheff.modules.rag_scan.connectors import GenericRestConnector


def test_poison_doc_contains_anchor_and_marker():
    d = po.poison_doc("What is the refund policy?", "PWNED-MARKER-1")
    text = (d.get("text") or d.get("content") or str(d))
    assert "PWNED-MARKER-1" in text
    # retrieval anchor: references the canary question terms
    assert "refund" in text.lower()


def test_confirms_control_true_when_marker_in_answer():
    assert po.confirms_control("The refund policy is PWNED-MARKER-1", "PWNED-MARKER-1") is True
    assert po.confirms_control("The refund policy is 30 days", "PWNED-MARKER-1") is False


# ---------------------------------------------------------------------------
# MockTransport tests for upsert / delete
# ---------------------------------------------------------------------------

def test_connector_upsert_returns_doc_id():
    """upsert() POSTs to /upsert and extracts id from the response."""
    def handler(req: httpx.Request) -> httpx.Response:
        if req.method == "POST" and req.url.path == "/upsert":
            return httpx.Response(200, json={"id": "doc-42"})
        return httpx.Response(404)

    conn = GenericRestConnector(transport=httpx.MockTransport(handler))
    conn._cfg_url = "http://q:6333"
    conn._cfg_headers = {}
    doc_id = asyncio.run(conn.upsert({"text": "poisoned content", "marker": "X"}))
    assert doc_id == "doc-42"


def test_connector_delete_non_fatal_on_error():
    """delete() swallows transport errors without raising."""
    def handler(req: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=req)

    conn = GenericRestConnector(transport=httpx.MockTransport(handler))
    conn._cfg_url = "http://q:6333"
    conn._cfg_headers = {}
    # must not raise
    asyncio.run(conn.delete("doc-42"))


def test_hijack_doc_contains_marker():
    d = po.hijack_doc("HIJACK-MARK-1")
    text = d.get("text") or str(d)
    assert "HIJACK-MARK-1" in text


def test_unrelated_queries_are_offtopic_and_plural():
    qs = po.unrelated_queries()
    assert len(qs) >= 3 and all(isinstance(q, str) and q for q in qs)


def test_retrieval_hijack_flags_when_doc_dominates_unrelated_query():
    import asyncio
    deleted = []

    async def upsert_fn(doc):
        return "hijack-doc-1"

    async def delete_fn(doc_id):
        deleted.append(doc_id)

    async def query_fn(prompt):
        # the hijack doc is (wrongly) returned for every query; echo the
        # deterministic marker (label="test" → "HIJACK-MARK-TEST")
        return ["leading text HIJACK-MARK-TEST trailing text"]

    cfg = {"query_probes": True, "poison_injection_opt_in": True, "label": "test"}
    findings = asyncio.run(po.run_retrieval_hijack(upsert_fn, delete_fn, query_fn, cfg))
    assert any(f.metadata.get("technique") == "rag:retrieval-hijack" for f in findings)
    assert deleted == ["hijack-doc-1"]  # self-clean


def test_retrieval_hijack_clean_when_doc_not_retrieved():
    import asyncio
    deleted = []

    async def upsert_fn(doc):
        return "hijack-doc-2"

    async def delete_fn(doc_id):
        deleted.append(doc_id)

    async def query_fn(prompt):
        return ["unrelated legitimate content only"]

    cfg = {"query_probes": True, "poison_injection_opt_in": True, "label": "test"}
    findings = asyncio.run(po.run_retrieval_hijack(upsert_fn, delete_fn, query_fn, cfg))
    assert findings == []
    assert deleted == ["hijack-doc-2"]  # still self-cleans


def test_retrieval_hijack_gated_off():
    import asyncio
    async def fn(*a, **k):
        raise AssertionError("must not be called when gate off")
    out = asyncio.run(po.run_retrieval_hijack(fn, fn, fn, {"poison_injection_opt_in": False}))
    assert out == []
