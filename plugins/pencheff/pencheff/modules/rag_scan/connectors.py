# pencheff/modules/rag_scan/connectors.py
"""Vector-DB connector abstraction. A connector turns a RagConfig dict into a
normalized RagManifest. v1 ships a generic-REST connector (Task 4); more
vendor-specific connectors are additive."""
from __future__ import annotations

import logging
from typing import Any, Protocol

import httpx

from .manifest import RagIndex, RagManifest, RagSampleChunk

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Pure normalizers
# ---------------------------------------------------------------------------

def _first_present(item: dict, *keys: str) -> Any:
    """Return the first key whose value is not None (so integer 0 is preserved)."""
    for key in keys:
        val = item.get(key)
        if val is not None:
            return val
    return None


def _normalize_indexes(raw: list[dict]) -> list[RagIndex]:
    """Map a list-of-dicts (various vendor shapes) into RagIndex objects.

    Tolerated key variants:
      name          → name
      dimension / dimensions → dimensions
      metric        → metric
      vectorsCount / points_count / count → record_count
    Missing keys → None (never raises).
    """
    result: list[RagIndex] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        name = item.get("name") or item.get("id") or ""
        # dimension key variants (use first-present so 0 is preserved)
        dimensions = _first_present(item, "dimensions", "dimension", "vector_size")
        if dimensions is not None:
            try:
                dimensions = int(dimensions)
            except (TypeError, ValueError):
                dimensions = None
        metric = item.get("metric") or item.get("distance") or None
        # record count key variants (use first-present so 0 is preserved)
        record_count = _first_present(
            item, "vectorsCount", "points_count", "count", "vectors_count"
        )
        if record_count is not None:
            try:
                record_count = int(record_count)
            except (TypeError, ValueError):
                record_count = None
        namespaces = item.get("namespaces") or []
        metadata = {k: v for k, v in item.items()
                    if k not in {"name", "id", "dimension", "dimensions",
                                 "vector_size", "metric", "distance",
                                 "vectorsCount", "points_count", "count",
                                 "vectors_count", "namespaces"}}
        result.append(RagIndex(
            name=name,
            dimensions=dimensions,
            metric=metric,
            namespaces=namespaces,
            record_count=record_count,
            metadata=metadata,
        ))
    return result


def _normalize_samples(raw: list[dict], index_name: str = "") -> list[RagSampleChunk]:
    """Map a list-of-dicts into RagSampleChunk objects. Tolerates missing keys."""
    result: list[RagSampleChunk] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        chunk_id = str(item.get("id") or item.get("chunk_id") or "")
        text = item.get("text") or item.get("content") or item.get("document") or ""
        has_raw = bool(
            item.get("embedding") or item.get("vector") or item.get("values")
        )
        result.append(RagSampleChunk(
            index=index_name,
            chunk_id=chunk_id,
            text=str(text),
            has_raw_embedding=has_raw,
        ))
    return result


# ---------------------------------------------------------------------------
# Candidate list endpoints to probe (ordered by likelihood)
# ---------------------------------------------------------------------------
_LIST_PATHS = [
    "/collections",
    "/v1/collections",
    "/indexes",
    "/v1/indexes",
    "/api/v1/indexes",
    "/schema",          # Weaviate
    "/api/collections", # Chroma-style
]


def _extract_index_list(data: Any) -> list[dict]:
    """Best-effort extraction of an index/collection list from various response shapes."""
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in ("collections", "indexes", "indices", "result", "data", "schemas"):
            val = data.get(key)
            if isinstance(val, list):
                return val
            # Qdrant wraps in {"result": {"collections": [...]}}
            if isinstance(val, dict):
                for inner_key in ("collections", "indexes", "indices"):
                    inner = val.get(inner_key)
                    if isinstance(inner, list):
                        return inner
    return []


# ---------------------------------------------------------------------------
# Generic REST connector
# ---------------------------------------------------------------------------

class GenericRestConnector:
    """Best-effort generic-REST connector for any vector DB that speaks HTTP.

    auth_required detection:
      - Sends a no-auth GET to the list endpoint.
      - 2xx  → auth_required=False  (server is open)
      - 401/403 → auth_required=True
      - Network error → auth_required=None

    tenancy_isolation, raw_embedding_export, encoder_hint are left as None in
    v1 — the generic connector cannot reliably detect these without vendor-
    specific knowledge.  Vendor connectors will populate them; static analyzers
    will not fire on None values.

    samples are left as [] in v1 — a follow-up task can add sampling logic per
    vendor once we know the vector fetch endpoint shapes.
    """

    def __init__(self, *, transport: httpx.AsyncBaseTransport | None = None) -> None:
        self._transport = transport
        self._cfg_url: str = ""
        self._cfg_headers: dict = {}

    def _client(self, headers: dict | None = None) -> httpx.AsyncClient:
        kwargs: dict[str, Any] = {
            "headers": headers or {},
            "timeout": 10.0,
            "verify": False,
        }
        if self._transport is not None:
            kwargs["transport"] = self._transport
        return httpx.AsyncClient(**kwargs)

    async def build_manifest(self, cfg: dict[str, Any]) -> RagManifest:
        endpoint: str = cfg["url"].rstrip("/")
        provider: str | None = cfg.get("provider")
        source_type: str = cfg["source_type"]
        extra_headers: dict = cfg.get("headers") or {}

        # Store for use by query()
        self._cfg_url = endpoint
        self._cfg_headers = extra_headers

        auth_required: bool | None = None
        indexes: list[RagIndex] = []

        # --- Step 1: no-auth probe (always sans credentials) ---
        try:
            async with self._client(headers=None) as client:
                for path in _LIST_PATHS:
                    try:
                        resp = await client.get(endpoint + path)
                        if resp.status_code in (401, 403):
                            auth_required = True
                            break
                        if resp.status_code < 300:
                            auth_required = False
                            # try to parse indexes from this open response
                            try:
                                raw_list = _extract_index_list(resp.json())
                                indexes = _normalize_indexes(raw_list)
                            except Exception:
                                pass
                            break
                    except httpx.TransportError:
                        # this path failed; try next
                        continue
        except Exception as exc:
            log.debug("GenericRestConnector: no-auth probe failed: %s", exc)
            auth_required = None

        # --- Step 2: authenticated listing (if we have headers and didn't get data) ---
        if extra_headers and not indexes:
            try:
                async with self._client(headers=extra_headers) as client:
                    for path in _LIST_PATHS:
                        try:
                            resp = await client.get(endpoint + path)
                            if resp.status_code < 300:
                                try:
                                    raw_list = _extract_index_list(resp.json())
                                    indexes = _normalize_indexes(raw_list)
                                except Exception:
                                    pass
                                if indexes:
                                    break
                        except httpx.TransportError:
                            continue
            except Exception as exc:
                log.debug("GenericRestConnector: auth listing failed: %s", exc)

        return RagManifest(
            source_type=source_type,
            provider=provider,
            endpoint=endpoint,
            auth_required=auth_required,
            encoder_hint=None,          # v1: cannot detect generically
            tenancy_isolation=None,     # v1: cannot detect generically
            raw_embedding_export=None,  # v1: cannot detect generically
            indexes=indexes,
            samples=[],                 # v1: sampling deferred to vendor connectors
        )


    async def upsert(self, doc: dict[str, Any]) -> str:
        """Best-effort document upsert: POST /upsert (or /documents) and return a doc id.

        Non-fatal — raises on hard failure so the caller can skip the probe,
        but swallows transport errors and returns a best-guess id.
        """
        if not self._cfg_url:
            return ""
        _UPSERT_PATHS = ["/upsert", "/documents", "/v1/documents", "/v1/upsert"]
        try:
            async with self._client(headers=self._cfg_headers) as client:
                for path in _UPSERT_PATHS:
                    try:
                        resp = await client.post(self._cfg_url + path, json=doc)
                        if resp.status_code < 300:
                            try:
                                data = resp.json()
                                doc_id = (
                                    data.get("id") or data.get("doc_id") or
                                    data.get("document_id") or ""
                                )
                                return str(doc_id)
                            except Exception:
                                return ""
                    except httpx.TransportError:
                        continue
        except Exception as exc:
            log.debug("GenericRestConnector.upsert: failed (non-fatal): %s", exc)
        return ""

    async def delete(self, doc_id: str) -> None:
        """Best-effort document deletion: DELETE /documents/{doc_id} (or /upsert/{doc_id}).

        Non-fatal — swallows all errors; callers should treat this as best-effort cleanup.
        """
        if not self._cfg_url or not doc_id:
            return
        _DELETE_PATHS = [
            f"/documents/{doc_id}",
            f"/v1/documents/{doc_id}",
            f"/upsert/{doc_id}",
        ]
        try:
            async with self._client(headers=self._cfg_headers) as client:
                for path in _DELETE_PATHS:
                    try:
                        resp = await client.delete(self._cfg_url + path)
                        if resp.status_code < 300:
                            return
                    except httpx.TransportError:
                        continue
        except Exception as exc:
            log.debug("GenericRestConnector.delete: failed (best-effort, swallowed): %s", exc)

    async def query(self, text: str, top_k: int = 5) -> list[str]:
        """Best-effort semantic search: POST /query (or /search) and return chunk texts.

        Non-fatal — returns [] on any error so callers can always iterate safely.
        The generic connector does not know the embedding model, so it sends a
        raw-text query and hopes the endpoint accepts {"query": text, "top_k": top_k}.
        Vendor connectors can override with the correct request shape.
        """
        if not self._cfg_url:
            return []
        _QUERY_PATHS = ["/query", "/search", "/v1/query", "/v1/search"]
        payload = {"query": text, "top_k": top_k}
        try:
            async with self._client(headers=self._cfg_headers) as client:
                for path in _QUERY_PATHS:
                    try:
                        resp = await client.post(self._cfg_url + path, json=payload)
                        if resp.status_code < 300:
                            data = resp.json()
                            return _extract_chunk_texts(data)
                    except httpx.TransportError:
                        continue
        except Exception as exc:
            log.debug("GenericRestConnector.query: failed (non-fatal): %s", exc)
        return []


def _extract_chunk_texts(data: Any) -> list[str]:
    """Best-effort extraction of text strings from a query/search response."""
    texts: list[str] = []
    if isinstance(data, list):
        items = data
    elif isinstance(data, dict):
        for key in ("results", "matches", "hits", "documents", "data"):
            val = data.get(key)
            if isinstance(val, list):
                items = val
                break
        else:
            return texts
    else:
        return texts

    for item in items:
        if isinstance(item, str):
            texts.append(item)
        elif isinstance(item, dict):
            payload = item.get("payload")
            payload_text = payload.get("text", "") if isinstance(payload, dict) else ""
            text = (
                item.get("text") or item.get("content") or
                item.get("document") or payload_text or ""
            )
            if text:
                texts.append(str(text))
    return texts


# ---------------------------------------------------------------------------
# Protocol (kept for type-checking; GenericRestConnector satisfies it)
# ---------------------------------------------------------------------------

class VectorDbConnector(Protocol):
    async def build_manifest(self, cfg: dict[str, Any]) -> RagManifest: ...
    async def query(self, text: str, top_k: int = 5) -> list[str]: ...
    async def upsert(self, doc: dict[str, Any]) -> str: ...
    async def delete(self, doc_id: str) -> None: ...
