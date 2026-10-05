# SPDX-License-Identifier: AGPL-3.0-or-later
"""API drift detector — compare a synthesised OpenAPI vs a declared one.

Phase 3.2 — sits on top of ``modules/api_discovery/synth.py``.
Diff produces three buckets:

* **Shadow endpoints** — paths the runtime exposes but the declared
  spec doesn't list. Severity: ``high`` (an endpoint reachable by
  clients but not in the security review's scope is the canonical
  blind spot).
* **Phantom endpoints** — paths the declared spec lists but no live
  traffic ever hit. Severity: ``low`` (could be unused, could be
  test-only, could be a legitimate new endpoint waiting on a client).
* **Method drift** — same path, different methods between specs.
  Severity: ``medium`` (often a copy-paste error in the spec, but
  occasionally a missing CSRF check).

Findings are emitted with category ``api_drift`` so the unified
findings stream + per-scan compliance rollup pick them up via the
existing ``CATEGORY_TO_OWASP`` map (``api_drift`` → OWASP A04
Insecure Design).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any


_DEFAULT_OWASP = "A04: Insecure Design"


@dataclass
class DriftFinding:
    severity: str
    title: str
    description: str
    path: str
    method: str | None
    drift_kind: str  # "shadow" | "phantom" | "method-drift"


def diff_specs(
    *,
    synthesized: dict[str, Any],
    declared: dict[str, Any] | None,
) -> list[DriftFinding]:
    """Produce ``DriftFinding`` rows for every divergence.

    ``declared`` may be ``None`` when the target hasn't attached an
    OpenAPI spec — in that case every synthesised endpoint becomes a
    ``shadow`` finding (the runtime surface is entirely undocumented).
    """
    out: list[DriftFinding] = []
    syn_paths = (synthesized or {}).get("paths", {}) or {}
    dec_paths = (declared or {}).get("paths", {}) or {} if declared else {}

    syn_keys = set(syn_paths.keys())
    dec_keys = set(dec_paths.keys())

    # Shadow endpoints — synthesized but not declared
    for path in sorted(syn_keys - dec_keys):
        methods = sorted(_methods(syn_paths[path]))
        for method in methods:
            out.append(DriftFinding(
                severity="high",
                title=f"Shadow endpoint: {method.upper()} {path}",
                description=(
                    "Captured live traffic exercised this endpoint, but "
                    "the declared OpenAPI spec for the target does not "
                    "list it. Shadow endpoints are the canonical blind "
                    "spot for security review — the AppSec checklist "
                    "doesn't cover paths it doesn't know about."
                ),
                path=path, method=method, drift_kind="shadow",
            ))

    # Phantom endpoints — declared but no traffic
    for path in sorted(dec_keys - syn_keys):
        methods = sorted(_methods(dec_paths[path]))
        for method in methods:
            out.append(DriftFinding(
                severity="low",
                title=f"Phantom endpoint: {method.upper()} {path}",
                description=(
                    "The declared OpenAPI spec advertises this endpoint "
                    "but no client traffic reached it during the "
                    "observation window. Likely unused / test-only / "
                    "deprecated; verify before hardening review."
                ),
                path=path, method=method, drift_kind="phantom",
            ))

    # Method drift — same path, different method set
    for path in sorted(syn_keys & dec_keys):
        syn_methods = _methods(syn_paths[path])
        dec_methods = _methods(dec_paths[path])
        for method in sorted(syn_methods - dec_methods):
            out.append(DriftFinding(
                severity="medium",
                title=f"Undocumented method: {method.upper()} {path}",
                description=(
                    f"Live traffic exercised {method.upper()} on this "
                    f"path, but the declared spec only covers "
                    f"{', '.join(sorted(dec_methods)) or '(none)'}. "
                    "Common causes: missing CSRF protection on a "
                    "state-changing verb, an unintended write path "
                    "left in production."
                ),
                path=path, method=method, drift_kind="method-drift",
            ))
        for method in sorted(dec_methods - syn_methods):
            out.append(DriftFinding(
                severity="low",
                title=f"Unobserved declared method: {method.upper()} {path}",
                description=(
                    f"The declared spec covers {method.upper()} on "
                    f"this path, but no traffic exercised it. Could "
                    "be deprecated, could be a feature waiting on a "
                    "client that never landed."
                ),
                path=path, method=method, drift_kind="phantom",
            ))

    return out


def to_finding_dicts(
    drifts: list[DriftFinding], *, target_id: str | None = None,
) -> list[dict[str, Any]]:
    """Render to the same dict shape used by ``RepoFinding`` / unified
    findings stream — caller bulk-inserts into the relevant table."""
    out: list[dict[str, Any]] = []
    for d in drifts:
        out.append({
            "scanner": "api_discovery",
            "rule_id": f"api-drift-{d.drift_kind}",
            "severity": d.severity,
            "title": d.title,
            "description": d.description,
            "category": "api_drift",
            "owasp_category": _DEFAULT_OWASP,
            "endpoint": d.path,
            "raw": {
                "drift_kind": d.drift_kind,
                "method": d.method,
                "target_id": target_id,
            },
        })
    return out


def _methods(path_obj: dict[str, Any]) -> set[str]:
    """Pluck the OpenAPI method names from a single path object."""
    valid = {"get", "post", "put", "delete", "options", "head", "patch", "trace"}
    return {k.lower() for k in (path_obj or {}).keys() if k.lower() in valid}
