"""Tests for MemoryKindConfig accepting structured memory items.

Plan M2 Task 3 — backward-compatible widening of MemoryKindConfig.items
to accept both bare strings (legacy) and structured {id?, text, namespace?,
source?} objects.
"""
from pydantic import ValidationError, TypeAdapter
import pytest
from pencheff_api.schemas.targets import KindConfig

_adapter = TypeAdapter(KindConfig)


def _parse(d):
    return _adapter.validate_python(d)


def test_memory_accepts_legacy_string_items():
    cfg = _parse({"kind": "memory", "items": ["note one", "note two"]})
    assert cfg.items == ["note one", "note two"]


def test_memory_accepts_structured_items():
    cfg = _parse({"kind": "memory", "items": [
        {"text": "note", "namespace": "tenant-a", "source": "tool"},
        {"id": "x2", "text": "note2"},
    ]})
    assert len(cfg.items) == 2


def test_memory_rejects_item_without_text():
    with pytest.raises(ValidationError):
        _parse({"kind": "memory", "items": [{"namespace": "a"}]})  # no text


def test_memory_empty_items_ok():
    cfg = _parse({"kind": "memory", "items": []})
    assert cfg.items == []


def test_memory_accepts_mem0_provider_source_metadata():
    cfg = _parse({
        "kind": "memory",
        "source_type": "mem0",
        "url": "https://api.mem0.ai",
        "org_id": "org_123",
        "project_id": "proj_456",
        "user_id": "user_789",
        "namespace": "support-prod",
        "items": [],
    })
    assert cfg.source_type == "mem0"
    assert cfg.url == "https://api.mem0.ai"
    assert cfg.user_id == "user_789"


def test_memory_provider_source_requires_url():
    with pytest.raises(ValidationError, match="requires url"):
        _parse({"kind": "memory", "source_type": "zep", "session_id": "s1"})


def test_memory_file_upload_requires_parsed_items():
    with pytest.raises(ValidationError, match="requires at least one parsed item"):
        _parse({"kind": "memory", "source_type": "file_upload", "file_name": "memory.jsonl"})


def test_memory_accepts_file_upload_items_and_file_metadata():
    cfg = _parse({
        "kind": "memory",
        "source_type": "file_upload",
        "file_name": "memory.jsonl",
        "file_format": "jsonl",
        "items": [{"id": "m1", "text": "Memory: user prefers short answers"}],
    })
    assert cfg.source_type == "file_upload"
    assert cfg.file_name == "memory.jsonl"
    assert cfg.file_format == "jsonl"
