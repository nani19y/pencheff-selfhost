"""CVE correlation workflow.

For each input finding, checks the offline ``cve_correlation.yaml`` overlay
first, then falls back to ``core.cve_feed.lookup`` for live NVD/CIRCL data.
Returns enriched findings with linked CVE IDs and patch versions.
"""

from __future__ import annotations

import re
from typing import Any

from pencheff.core.orchestrator.policies import load_policies


async def run(findings: list[dict[str, Any]] | None = None, **_: Any) -> dict[str, Any]:
    findings = findings or []
    pol = load_policies()
    overlay = pol.cve_correlation.get("products", {})

    enriched: list[dict[str, Any]] = []
    for finding in findings:
        banner = (
            finding.get("banner")
            or finding.get("server")
            or finding.get("evidence", "")
            or finding.get("description", "")
        )
        cves = _match_overlay(banner, overlay)
        if not cves:
            cves = await _live_lookup(finding)
        enriched.append({**finding, "linked_cves": cves})
    return {"workflow": "cve_intel", "findings": enriched}


def _match_overlay(banner: str, overlay: dict[str, Any]) -> list[dict[str, str]]:
    matches: list[dict[str, str]] = []
    for product, entry in overlay.items():
        for matcher in entry.get("matches", []):
            pattern = matcher.get("banner_regex")
            if not pattern:
                continue
            if re.search(pattern, banner or "", flags=re.IGNORECASE):
                versions = entry.get("versions", {})
                for ver_range, payload in versions.items():
                    for cve in payload.get("cves", []):
                        matches.append(
                            {
                                "id": cve["id"],
                                "severity": cve.get("severity", ""),
                                "summary": cve.get("summary", ""),
                                "source": cve.get("source", ""),
                                "product": product,
                                "version_range": ver_range,
                            }
                        )
    return matches


async def _live_lookup(finding: dict[str, Any]) -> list[dict[str, str]]:
    """Fall back to the existing live CVE feed."""
    try:
        from pencheff.core import cve_feed  # type: ignore[import-not-found]
    except Exception:  # noqa: BLE001
        return []
    cpe = finding.get("cpe") or finding.get("product")
    if not cpe:
        return []
    try:
        results = await cve_feed.lookup(cpe)  # type: ignore[attr-defined]
    except Exception:  # noqa: BLE001
        return []
    return [
        {"id": r.get("id", ""), "severity": r.get("severity", ""),
         "summary": r.get("summary", ""), "source": r.get("source", "nvd")}
        for r in (results or [])
    ]
