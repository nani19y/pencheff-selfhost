# SPDX-License-Identifier: AGPL-3.0-or-later
"""Runtime-traffic → OpenAPI synthesis (Phase 3.2).

Reads a slice of ``ProxyFlow`` rows from ``core/proxy.py`` and emits
an OpenAPI 3.1 document. Two layers:

* **Deterministic** — URL templating, methods, status codes, auth
  scheme detection, response-shape inference (a per-path ``200``
  body sampled across N requests is collapsed into a JSON Schema by
  shape-merging). Runs offline.
* **LLM-assisted** (optional) — operation summaries, parameter
  descriptions, tag selection. Off by default; opt-in via
  ``synthesize(..., chat=client._chat)``.

The synthesis result feeds the drift detector at
``services/api_drift.py``: diffing a synthesized spec against the
target's declared OpenAPI spec produces ``api_drift`` findings for
shadow APIs and out-of-spec endpoints.
"""
from __future__ import annotations

from .synth import (
    SynthesisResult,
    synthesize_openapi,
    summarize_endpoints,
)

__all__ = ["SynthesisResult", "synthesize_openapi", "summarize_endpoints"]
