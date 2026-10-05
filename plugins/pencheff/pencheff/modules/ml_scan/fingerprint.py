# pencheff/modules/ml_scan/fingerprint.py
"""Match an MlManifest's artifact formats against pinned ML known-vuln advisories
(refreshable advisories.yaml). Pure; no I/O beyond reading the bundled yaml."""
from __future__ import annotations

import re
from importlib.resources import files

import yaml

from pencheff.config import Severity
from pencheff.core.findings import Finding

from .manifest import MlManifest

_SEV = {
    "critical": Severity.CRITICAL, "high": Severity.HIGH,
    "medium": Severity.MEDIUM, "low": Severity.LOW, "info": Severity.INFO,
}
_cache: list[dict] | None = None


def _load() -> list[dict]:
    global _cache
    if _cache is None:
        text = files("pencheff.modules.ml_scan").joinpath("advisories.yaml").read_text("utf-8")
        _cache = yaml.safe_load(text) or []
    return _cache


def fingerprint(mf: MlManifest) -> list[Finding]:
    fmts = {a.fmt for a in mf.artifacts}
    out: list[Finding] = []
    for adv in _load():
        pat = adv.get("format_match")
        if not pat or not any(re.search(pat, f) for f in fmts):
            continue
        out.append(Finding(
            title=adv["title"],
            severity=_SEV.get(adv.get("severity", "medium"), Severity.MEDIUM),
            category="ml_known_vuln",
            owasp_category="LLM03",
            cwe_id=adv.get("cwe"),
            description=adv["description"],
            remediation=adv["remediation"],
            endpoint=mf.origin or "",
            references=[adv["reference"]] if adv.get("reference") else [],
            metadata={"technique": "ml:known-vuln", "cve": adv.get("cve"), "cvss": adv.get("cvss")},
        ))
    return out
