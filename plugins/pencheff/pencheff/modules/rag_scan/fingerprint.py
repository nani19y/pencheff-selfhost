# pencheff/modules/rag_scan/fingerprint.py
"""Match a RagManifest against pinned vector-DB exposure-posture advisories
and CVEs. Version-gated and refreshable (advisories.yaml)."""
from __future__ import annotations

import re
from importlib.resources import files

import yaml

from pencheff.config import Severity
from pencheff.core.findings import Finding

from .manifest import RagManifest

_SEV = {
    "critical": Severity.CRITICAL, "high": Severity.HIGH,
    "medium": Severity.MEDIUM, "low": Severity.LOW, "info": Severity.INFO,
}
_VER_RE = re.compile(r"(\d+)\.(\d+)\.(\d+)")
_cache: list[dict] | None = None


def _load() -> list[dict]:
    global _cache
    if _cache is None:
        text = (
            files("pencheff.modules.rag_scan")
            .joinpath("advisories.yaml")
            .read_text("utf-8")
        )
        _cache = yaml.safe_load(text) or []
    return _cache


def _parse_ver(s: str | None) -> tuple[int, int, int] | None:
    if not s:
        return None
    m = _VER_RE.search(s)
    return (int(m[1]), int(m[2]), int(m[3])) if m else None


def _detect_version(mf: RagManifest) -> str | None:
    """Return first version string found across index metadata."""
    for idx in mf.indexes:
        v = (idx.metadata or {}).get("version")
        if v:
            return str(v)
    return None


def fingerprint(mf: RagManifest) -> list[Finding]:
    """Match *mf* against the advisory list and return a Finding per match."""
    provider = mf.provider or ""
    out: list[Finding] = []
    for adv in _load():
        pat = adv["provider_match"]
        if not re.search(pat, provider):
            continue
        below = adv.get("vulnerable_below")
        if below:
            detected_str = _detect_version(mf)
            detected = _parse_ver(detected_str)
            want = _parse_ver(below)
            # Only flag when we detected a version AND it is below the fix.
            if detected is None or want is None or detected >= want:
                continue
        out.append(Finding(
            title=adv["title"],
            severity=_SEV.get(adv.get("severity", "medium"), Severity.MEDIUM),
            category="rag_known_vuln",
            owasp_category="LLM08",
            description=adv["description"],
            remediation=adv["remediation"],
            endpoint=mf.endpoint or "",
            cwe_id=adv.get("cwe"),
            references=[adv["reference"]] if adv.get("reference") else [],
            metadata={
                "technique": "rag:known-vuln",
                "cve": adv.get("cve"),
                "cvss": adv.get("cvss"),
                "provider": provider,
            },
        ))
    return out
