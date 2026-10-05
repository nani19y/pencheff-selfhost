"""Map collected packages → CVEs via the local CveFeed/OSV cache.

Works hand-in-hand with ``authenticated_host_scan.collect_packages``: given a
PackageSnapshot and a host identifier, it emits Findings for every vulnerable
package with severity + CVSS + EPSS + KEV enrichment.
"""

from __future__ import annotations

from pencheff.config import Severity
from pencheff.core.cve_feed import get_feed
from pencheff.core.findings import Evidence, Finding
from pencheff.modules.network.authenticated_host_scan import PackageSnapshot


_OS_ECOSYSTEM = {
    "ubuntu": "Ubuntu",
    "debian": "Debian",
    "alpine": "Alpine",
    "rhel": "RedHat",
    "red hat": "RedHat",
    "rocky": "Rocky",
    "centos": "RedHat",
    "amazon": "AmazonLinux",
    "windows": "Windows",
}


async def scan_snapshot(host: str, snap: PackageSnapshot) -> list[Finding]:
    feed = get_feed()
    ecosystem = _pick_ecosystem(snap.os_name)
    findings: list[Finding] = []
    for name, ver in snap.packages:
        if not name or not ver:
            continue
        try:
            vulns = await feed.osv_query(ecosystem, name, ver)
        except Exception:  # noqa: BLE001
            continue
        for v in vulns:
            findings.append(_f(host, name, ver, v, ecosystem))
    return findings


def _pick_ecosystem(os_name: str) -> str:
    low = (os_name or "").lower()
    for key, eco in _OS_ECOSYSTEM.items():
        if key in low:
            return eco
    return "Debian"


def _f(host: str, name: str, ver: str, v, ecosystem: str) -> Finding:
    sev = {
        "critical": Severity.CRITICAL, "high": Severity.HIGH,
        "medium": Severity.MEDIUM, "low": Severity.LOW, "info": Severity.INFO,
    }.get((v.severity or "medium").lower(), Severity.MEDIUM)
    fixed = ", ".join(v.fixed_versions) or "no fixed version published"
    kev = bool(v.cve_info and v.cve_info.kev)
    return Finding(
        title=f"Missing patch on {host}: {name} {ver} — {v.id}",
        severity=sev,
        category="components",
        owasp_category="A06",
        description=(
            f"{ecosystem} package '{name}' {ver} on {host} is vulnerable to {v.id}: {v.summary}"
            + (" [CISA KEV — actively exploited]" if kev else "")
        ),
        remediation=(
            f"Upgrade {name} to {fixed} using the platform package manager. Reboot if a kernel/library upgrade requires it."
        ),
        endpoint=host,
        parameter=f"{ecosystem}:{name}@{ver}",
        cvss_score=v.cvss_score,
        cvss_vector=v.cvss_vector,
        references=v.references,
        evidence=[Evidence(
            request_method="SSH/WINRM", request_url=host,
            response_status=200, description=f"Installed: {name} {ver}",
        )],
    )
