"""Enrich existing findings with EPSS + KEV signals so reports can risk-rank.

Pencheff findings carry ``references`` as free-text URLs; this module extracts
CVE IDs from references + titles, queries the local CveFeed cache, and adds
``epss``, ``epss_percentile``, and ``kev`` keys to ``Finding.to_dict`` payloads
via a wrapper function ``enrich_findings``.
"""

from __future__ import annotations

import re
from typing import Any

from pencheff.core.cve_feed import CveFeed, get_feed
from pencheff.core.findings import Finding

CVE_REGEX = re.compile(r"CVE-\d{4}-\d{4,7}")


def _extract_cves(finding: Finding) -> list[str]:
    text = " ".join([
        finding.title or "",
        finding.description or "",
        " ".join(finding.references or []),
    ])
    seen: dict[str, None] = {}
    for m in CVE_REGEX.findall(text):
        seen.setdefault(m, None)
    return list(seen.keys())


def enrich_findings_dict(
    findings: list[Finding], feed: CveFeed | None = None
) -> list[dict[str, Any]]:
    """Serialize findings with added EPSS/KEV fields + risk score."""
    feed = feed or get_feed()
    out: list[dict[str, Any]] = []
    for f in findings:
        d = f.to_dict()
        cves = _extract_cves(f)
        enriched = [feed.enrich(c) for c in cves]
        epss_scores = [e.epss for e in enriched if e.epss is not None]
        kev_flags = [e for e in enriched if e.kev]
        d["cves"] = cves
        d["epss"] = max(epss_scores) if epss_scores else None
        d["kev"] = bool(kev_flags)
        d["kev_entries"] = [
            {"cve": e.cve, "short_desc": e.kev_short_desc, "due_date": e.kev_due_date}
            for e in kev_flags
        ]
        # risk = cvss × (1 + epss) × (2 if kev else 1)
        multiplier = 1.0
        if epss_scores:
            multiplier *= 1.0 + max(epss_scores)
        if kev_flags:
            multiplier *= 2.0
        d["risk_score"] = round(f.cvss_score * multiplier, 2)
        out.append(d)
    return out
