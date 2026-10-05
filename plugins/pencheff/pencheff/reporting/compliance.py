"""Compliance framework mapping for findings."""

from __future__ import annotations

from pencheff.config import HIPAA_MAP, ISO27001_MAP, NIST_MAP, OWASP_TOP_10, PCI_DSS_MAP, SOC2_MAP


def get_owasp_coverage(findings_categories: list[str]) -> dict[str, bool]:
    """Check which OWASP Top 10 categories are covered by findings."""
    category_to_owasp = {
        "injection": "A03",
        "xss": "A03",
        "auth": "A07",
        "authz": "A01",
        "crypto": "A02",
        "misconfiguration": "A05",
        "ssrf": "A10",
        "file_handling": "A01",
        "cloud": "A05",
        "logic": "A04",
    }

    covered = set()
    for cat in findings_categories:
        owasp = category_to_owasp.get(cat)
        if owasp:
            covered.add(owasp)

    return {
        f"{code}: {name}": code in covered
        for code, name in OWASP_TOP_10.items()
    }


_FRAMEWORK_MAPS = {
    "owasp": None,          # handled separately
    "pci-dss": PCI_DSS_MAP,
    "nist": NIST_MAP,
    "soc2": SOC2_MAP,
    "iso27001": ISO27001_MAP,
    "hipaa": HIPAA_MAP,
}

_FRAMEWORK_LABELS = {
    "owasp": "OWASP Top 10",
    "pci-dss": "PCI-DSS",
    "nist": "NIST 800-53",
    "soc2": "SOC 2",
    "iso27001": "ISO 27001:2022",
    "hipaa": "HIPAA",
}


def get_compliance_summary(
    findings: list,
    frameworks: list[str] | None = None,
) -> dict[str, dict]:
    """Generate compliance summary across requested frameworks.

    frameworks: list of framework keys (owasp, pci-dss, nist, soc2, iso27001, hipaa).
    Defaults to all six if not specified.
    """
    frameworks = [f.lower() for f in (frameworks or list(_FRAMEWORK_MAPS.keys()))]
    result: dict[str, dict] = {}

    # Initialise buckets
    for fw in frameworks:
        label = _FRAMEWORK_LABELS.get(fw, fw)
        result[label] = {}

    for f in findings:
        for fw in frameworks:
            label = _FRAMEWORK_LABELS.get(fw, fw)
            if fw == "owasp":
                key = f"{f.owasp_category}: {f.owasp_name}"
                result[label].setdefault(key, []).append(f.title)
            else:
                fw_map = _FRAMEWORK_MAPS.get(fw, {})
                for ctrl in fw_map.get(f.category, []):
                    result[label].setdefault(ctrl, []).append(f.title)

    return result
