# SPDX-License-Identifier: AGPL-3.0-or-later
"""Load community probes from the on-disk corpus into ``TestCase`` rows.

The corpus shape is one JSONL per OWASP-LLM category at:

    plugins/pencheff/pencheff/modules/llm_red_team/community/probes/
        llm01_prompt_injection.jsonl
        llm02_info_disclosure.jsonl
        ...
        llm10_unbounded_consumption.jsonl

Each line is a serialised ``ProbeRow``. The loader:

1. Walks the directory.
2. Validates every row against the license allowlist read from
   ``tools/license-allowlist.txt`` (so a misconfigured probe corpus
   can't sneak in a non-permissive seed).
3. Drops invalid rows with a warning, keeps the rest.
4. Returns ``TestCase`` instances + a parallel ``meta`` dict for the
   reporter / share-link to surface attribution at render time.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Iterable

from pencheff.config import Severity
from ..engine import TestCase
from .schema import ProbeRow, validate_probe

log = logging.getLogger(__name__)

PROBES_DIR = Path(__file__).resolve().parent / "probes"

# License allowlist for community probes — kept narrow on purpose.
# Mirrors ``tools/license-allowlist.txt`` for the inputs we actually
# accept. CC-BY-SA appears here for *data* only; it's intentionally
# absent from the inputs side of the SPDX list because we don't want
# share-alike code in the engine.
DEFAULT_PROBE_LICENSE_ALLOWLIST: frozenset[str] = frozenset({
    "MIT",
    "Apache-2.0",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "ISC",
    "CC0-1.0",
    "0BSD",
    "Public Domain",
    "Unlicense",
    "CC-BY-4.0",
    "CC-BY-3.0",
})


def load_community_probes(
    *,
    probes_dir: Path = PROBES_DIR,
    allowlist: Iterable[str] = DEFAULT_PROBE_LICENSE_ALLOWLIST,
) -> tuple[list[TestCase], dict[str, dict]]:
    """Return ``(test_cases, metadata_by_probe_id)``.

    A missing or empty ``probes_dir`` returns an empty pair — the
    built-in YAML payloads under ``llm_red_team/payloads/`` continue
    to drive scans on a vanilla install. The community corpus is
    additive.
    """
    allow = set(allowlist)
    test_cases: list[TestCase] = []
    metadata: dict[str, dict] = {}

    if not probes_dir.is_dir():
        return test_cases, metadata

    for jsonl in sorted(probes_dir.glob("*.jsonl")):
        try:
            with jsonl.open("r", encoding="utf-8") as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    try:
                        row = ProbeRow.from_jsonl(line)
                    except Exception as exc:  # noqa: BLE001
                        log.warning(
                            "community probe %s:%d malformed: %s",
                            jsonl.name, line_num, exc,
                        )
                        continue
                    ok, reason = validate_probe(row, allow)
                    if not ok:
                        log.warning(
                            "community probe %s rejected (%s): %s",
                            row.id, reason, jsonl.name,
                        )
                        continue
                    test_cases.append(_to_test_case(row))
                    if row.meta is not None:
                        metadata[row.id] = {
                            "source": row.meta.source,
                            "license": row.meta.license,
                            "attribution": row.meta.attribution,
                            "import_date": row.meta.import_date,
                            "synthesizer_inputs": list(row.meta.synthesizer_inputs),
                            "synthesizer_model": row.meta.synthesizer_model,
                            "prompt_version": row.meta.prompt_version,
                        }
        except OSError as exc:
            log.warning("community probe load failed for %s: %s", jsonl, exc)
    return test_cases, metadata


def _to_test_case(row: ProbeRow) -> TestCase:
    severity = _severity(row.severity)
    extra_metadata = dict(getattr(row, "metadata", None) or {})
    return TestCase(
        id=row.id,
        category=row.category,
        technique=row.technique,
        title=row.title,
        severity=severity,
        prompt=row.prompt,
        turns=list(row.turns),
        system=row.system,
        success_indicators=list(row.success_indicators),
        refusal_patterns=list(row.refusal_patterns),
        success_embeddings=list(row.success_embeddings),
        description=row.description,
        remediation=row.remediation,
        cwe=row.cwe,
        metadata=extra_metadata,
    )


def _severity(value: str) -> Severity:
    try:
        return Severity(value.lower())
    except ValueError:
        return Severity.MEDIUM
