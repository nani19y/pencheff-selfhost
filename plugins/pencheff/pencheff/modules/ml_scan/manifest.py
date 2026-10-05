# pencheff/modules/ml_scan/manifest.py
"""Normalized, source-agnostic view of an ML model target. The fetcher populates
these; pure analyzers consume ONLY these (no network, no model loading)."""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any


@dataclass
class MlArtifact:
    """One file belonging to a model. `data` holds raw bytes (already size-bounded).
    NEVER deserialized — only byte/opcode/zip inspection."""
    name: str                       # logical filename, e.g. "pytorch_model.bin"
    data: bytes                     # raw bytes (bounded by max_bytes upstream)
    fmt: str = "unknown"            # set by format_detect
    size: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class MlManifest:
    source_type: str                # file_url | huggingface | local_path
    origin: str = ""                # url / hf_repo / path (for endpoint field)
    provider: str | None = None     # "huggingface" | None
    hf_repo: str | None = None
    artifacts: list[MlArtifact] = field(default_factory=list)
    fetch_errors: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
