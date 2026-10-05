# pencheff/modules/rag_scan/manifest.py
"""Normalized, source-agnostic view of a RAG / vector-DB target. Connectors
populate these; static analyzers consume ONLY these (pure + testable)."""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any


@dataclass
class RagIndex:
    name: str
    dimensions: int | None = None
    metric: str | None = None
    namespaces: list[str] = field(default_factory=list)
    record_count: int | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class RagSampleChunk:
    index: str
    chunk_id: str
    text: str = ""
    has_raw_embedding: bool = False


@dataclass
class RagManifest:
    source_type: str
    provider: str | None = None
    endpoint: str = ""
    auth_required: bool | None = None
    encoder_hint: str | None = None
    tenancy_isolation: bool | None = None
    raw_embedding_export: bool | None = None
    indexes: list[RagIndex] = field(default_factory=list)
    samples: list[RagSampleChunk] = field(default_factory=list)
