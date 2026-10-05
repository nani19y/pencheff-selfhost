# apps/api/tests/test_targets_rag_config.py
"""Validation tests for the RagConfig kind_config variant."""
from __future__ import annotations

import pytest
from pydantic import ValidationError, TypeAdapter

from pencheff_api.schemas.targets import KindConfig

_adapter = TypeAdapter(KindConfig)
def _parse(d): return _adapter.validate_python(d)


def test_managed_vdb_requires_provider_and_url():
    ok = _parse({"kind": "rag", "source_type": "managed_vdb",
                 "provider": "pinecone", "url": "https://idx.svc.pinecone.io", "index_name": "docs"})
    assert ok.provider == "pinecone"
    with pytest.raises(ValidationError):
        _parse({"kind": "rag", "source_type": "managed_vdb"})


def test_self_hosted_vdb_requires_provider_and_url():
    ok = _parse({"kind": "rag", "source_type": "self_hosted_vdb",
                 "provider": "pgvector", "url": "postgresql://h/db"})
    assert ok.provider == "pgvector"
    with pytest.raises(ValidationError):
        _parse({"kind": "rag", "source_type": "self_hosted_vdb", "provider": "pgvector"})


def test_rag_endpoint_requires_provider_llm():
    ok = _parse({"kind": "rag", "source_type": "rag_endpoint", "provider_llm": "openai-chat"})
    assert ok.provider_llm == "openai-chat"
    with pytest.raises(ValidationError):
        _parse({"kind": "rag", "source_type": "rag_endpoint"})


def test_embedding_artifact_requires_items():
    ok = _parse({"kind": "rag", "source_type": "embedding_artifact", "items": ["chunk1", "chunk2"]})
    assert ok.items == ["chunk1", "chunk2"]
    with pytest.raises(ValidationError):
        _parse({"kind": "rag", "source_type": "embedding_artifact"})


def test_poison_injection_requires_query_probes():
    with pytest.raises(ValidationError):
        _parse({"kind": "rag", "source_type": "managed_vdb", "provider": "qdrant",
                "url": "https://q", "poison_injection_opt_in": True})
    ok = _parse({"kind": "rag", "source_type": "managed_vdb", "provider": "qdrant",
                 "url": "https://q", "query_probes": True, "poison_injection_opt_in": True})
    assert ok.poison_injection_opt_in is True


def test_defaults_and_extra_forbidden():
    cfg = _parse({"kind": "rag", "source_type": "embedding_artifact", "items": ["x"]})
    assert cfg.query_probes is False and cfg.poison_injection_opt_in is False
    with pytest.raises(ValidationError):
        _parse({"kind": "rag", "source_type": "embedding_artifact", "items": ["x"], "bogus": 1})


def test_rag_accepts_optional_redteam_override():
    ok = _parse({"kind": "rag", "source_type": "rag_endpoint", "provider_llm": "openai-chat",
                 "redteam": {"categories": ["LLM02"], "plugins": ["rag"], "max_payloads": 20}})
    assert ok.redteam["categories"] == ["LLM02"]


def test_rag_redteam_defaults_none():
    ok = _parse({"kind": "rag", "source_type": "embedding_artifact", "items": ["x"]})
    assert ok.redteam is None
