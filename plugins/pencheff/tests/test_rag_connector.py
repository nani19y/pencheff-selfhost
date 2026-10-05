import asyncio
import httpx
from pencheff.modules.rag_scan.connectors import GenericRestConnector, _normalize_indexes


def test_normalize_indexes_maps_fields():
    raw = [{"name": "docs", "dimension": 768, "metric": "cosine"},
           {"name": "faq"}]
    idx = _normalize_indexes(raw)
    assert idx[0].name == "docs" and idx[0].dimensions == 768 and idx[0].metric == "cosine"
    assert idx[1].name == "faq" and idx[1].dimensions is None


def test_normalize_indexes_preserves_zero_counts():
    raw = [{"name": "empty", "dimension": 0, "vectorsCount": 0}]
    idx = _normalize_indexes(raw)
    assert idx[0].dimensions == 0 and idx[0].record_count == 0


def test_build_manifest_lists_indexes_and_sets_auth_required_false_when_open():
    # An open server: the no-auth probe returns 200 + a collections list
    def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"collections": [{"name": "docs", "dimension": 1536}]})
    conn = GenericRestConnector(transport=httpx.MockTransport(handler))
    mf = asyncio.run(conn.build_manifest({
        "source_type": "self_hosted_vdb", "provider": "qdrant", "url": "http://q:6333",
    }))
    assert mf.provider == "qdrant" and mf.endpoint == "http://q:6333"
    assert mf.auth_required is False      # reached data with no creds
    assert any(i.name == "docs" for i in mf.indexes)


def test_build_manifest_auth_required_true_when_401_without_creds():
    def handler(req: httpx.Request) -> httpx.Response:
        # 401 when no auth header present; 200 when present
        if "authorization" not in {k.lower() for k in req.headers}:
            return httpx.Response(401, json={"error": "unauthorized"})
        return httpx.Response(200, json={"collections": [{"name": "docs"}]})
    conn = GenericRestConnector(transport=httpx.MockTransport(handler))
    mf = asyncio.run(conn.build_manifest({
        "source_type": "managed_vdb", "provider": "weaviate", "url": "http://w:8080",
        "headers": {"Authorization": "Bearer k"},
    }))
    assert mf.auth_required is True


def test_build_manifest_non_fatal_on_error():
    def handler(req: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=req)
    conn = GenericRestConnector(transport=httpx.MockTransport(handler))
    mf = asyncio.run(conn.build_manifest({
        "source_type": "self_hosted_vdb", "provider": "chroma", "url": "http://c:8000",
    }))
    # degrades gracefully: returns a manifest (no crash), indexes empty
    assert mf.provider == "chroma" and mf.indexes == []


def test_query_returns_chunk_texts():
    """query() POSTs to /query and extracts text fields from the response."""
    def handler(req: httpx.Request) -> httpx.Response:
        if req.method == "POST" and req.url.path == "/query":
            return httpx.Response(200, json={"results": [
                {"text": "chunk one"},
                {"text": "chunk two"},
            ]})
        return httpx.Response(404)

    conn = GenericRestConnector(transport=httpx.MockTransport(handler))
    # Must call build_manifest first so _cfg_url is set
    asyncio.run(conn.build_manifest({
        "source_type": "self_hosted_vdb", "provider": "qdrant", "url": "http://q:6333",
    }))
    chunks = asyncio.run(conn.query("what is the policy?"))
    assert chunks == ["chunk one", "chunk two"]


def test_query_non_fatal_on_error():
    """query() returns [] without raising on transport error."""
    def handler(req: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=req)

    conn = GenericRestConnector(transport=httpx.MockTransport(handler))
    conn._cfg_url = "http://c:8000"  # set directly (no build_manifest)
    conn._cfg_headers = {}
    chunks = asyncio.run(conn.query("probe"))
    assert chunks == []
