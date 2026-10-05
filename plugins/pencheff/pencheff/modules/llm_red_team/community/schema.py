# SPDX-License-Identifier: AGPL-3.0-or-later
"""Per-probe metadata schema for the community corpus.

Two layers:

* ``ProbeMetadata`` — the provenance side. Every imported / synthesised
  probe carries one. Same audit-trail pattern as ``advisory_ai`` —
  ``source`` URL, upstream ``license``, ``attribution`` line, and the
  ``synthesizer_inputs`` list when AI-generated.

* ``ProbeRow`` — the on-disk JSONL row. One ``ProbeRow`` per line
  under ``community/probes/<owasp_category>.jsonl``. Designed so a
  diff between two corpus snapshots is line-noise-free.

The shapes are deliberately small. The bulk-import scripts under
``tools/`` produce ``ProbeRow`` records; the loader (``loader.py``)
fans them out into ``TestCase`` instances at scan time, with the
metadata copied onto a side-channel dict that ``engine.py`` already
ignores.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True)
class ProbeMetadata:
    """Audit-trail metadata for one probe.

    ``source`` points at the upstream repo / dataset URL the probe
    was imported from. ``license`` is the SPDX id (must be on the
    allowlist). ``attribution`` is the verbatim attribution line we
    show in DOCX exports + share-link renders. ``synthesizer_inputs``
    is populated *only* for AI-generated probes — empty for direct
    imports.
    """

    source: str                     # e.g. "https://github.com/JailbreakBench/JailbreakBench"
    license: str                    # SPDX id, e.g. "MIT", "Apache-2.0", "CC0-1.0"
    attribution: str                # e.g. "JailbreakBench © 2024 Chao et al."
    import_date: str                # ISO-8601
    synthesizer_inputs: list[str] = field(default_factory=list)  # input probe IDs
    synthesizer_model: str | None = None  # the LLM that generated this row, when any
    prompt_version: str | None = None     # Pencheff's synthesis prompt version


@dataclass
class ProbeRow:
    """On-disk JSONL row representing one community probe.

    Shape mirrors ``TestCase`` but adds ``meta``. Loader at scan time
    converts a ``ProbeRow`` into a ``TestCase`` (dropping ``meta``)
    and stores ``meta`` in a parallel dict keyed by probe id.
    """

    id: str                        # globally unique across the corpus
    category: str                  # "LLM01" .. "LLM10"
    technique: str
    title: str
    severity: str                  # "low" | "medium" | "high" | "critical" | "info"
    prompt: str
    success_indicators: list[str] = field(default_factory=list)
    refusal_patterns: list[str] = field(default_factory=list)
    success_embeddings: list[str] = field(default_factory=list)
    turns: list[str] = field(default_factory=list)
    system: str | None = None
    description: str = ""
    remediation: str = ""
    cwe: str | None = None
    meta: ProbeMetadata | None = None

    def to_jsonl(self) -> str:
        """One-line JSON for append-only storage. Sort keys so corpus
        snapshots diff cleanly."""
        d = asdict(self)
        return json.dumps(d, sort_keys=True, ensure_ascii=False)

    @classmethod
    def from_jsonl(cls, line: str) -> "ProbeRow":
        d = json.loads(line)
        meta = d.pop("meta", None)
        if meta is not None:
            meta = ProbeMetadata(**meta)
        return cls(meta=meta, **d)


def validate_probe(row: ProbeRow, allowlist: set[str]) -> tuple[bool, str]:
    """Return ``(ok, reason)``.

    Hard rejects:
    * No metadata
    * License not on the allowlist
    * Empty prompt
    * Category not LLM01..LLM10
    * No verdict signals (regex + embedding both empty)
    """
    if row.meta is None:
        return False, "missing metadata"
    if row.meta.license not in allowlist:
        return False, f"license {row.meta.license!r} not on allowlist"
    if not row.prompt.strip():
        return False, "empty prompt"
    if not row.category.startswith("LLM") or len(row.category) != 5:
        return False, f"invalid category {row.category!r}"
    if not row.success_indicators and not row.success_embeddings:
        return False, "no success signals (regex + embeddings both empty)"
    return True, ""


def asdict_safe(obj: Any) -> dict[str, Any]:
    """``dataclasses.asdict`` doesn't round-trip ``ProbeMetadata`` when it's
    nested inside ``meta``; this wrapper handles that explicitly so callers
    don't trip on the nested-dataclass quirk."""
    return asdict(obj)
