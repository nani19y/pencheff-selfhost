"""Host-level CVE scanning using Pencheff service probes + network templates.

When a service banner is available, we derive a CPE and query OSV / the local
CVE feed for known vulns. This targeted workflow integrates cleanly with
pencheff's unified ``Finding`` model.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import re
from typing import Any

from pencheff.config import Severity
from pencheff.core.cve_feed import get_feed
from pencheff.core.findings import Evidence, Finding
from pencheff.core.netmap import parse_ports, scan_targets


def scan(host: str, ports: str = "top-1000") -> list[Finding]:
    """Run Pencheff service detection, then map banners to CVEs."""
    findings: list[Finding] = []
    services = _pencheff_services(host, ports)
    feed = get_feed()
    for svc in services:
        pkg, ver = _package_version_from_banner(svc["service"], svc["banner"])
        if not pkg or not ver:
            findings.append(_open_port_finding(host, svc))
            continue
        # Try PyPI/npm/debian/alpine/rpm — host-level maps loosely to several
        for ecosystem in ("Alpine", "Debian", "Ubuntu", "RedHat", "Rocky"):
            try:
                vulns = _sync_osv(feed, ecosystem, pkg, ver)
            except Exception:  # noqa: BLE001
                continue
            if vulns:
                for v in vulns:
                    findings.append(_vuln_finding(host, svc, pkg, ver, v))
                break
        findings.append(_open_port_finding(host, svc, service_detected=pkg))
    return findings


def _pencheff_services(host: str, ports: str) -> list[dict[str, str]]:
    """Run the first-party mapper into [{port, proto, service, banner}]."""
    try:
        result = _run_scan_targets_sync(host, ports)
    except Exception:
        return []
    out: list[dict[str, str]] = []
    for row in result.open:
        out.append({
            "port": str(row.port),
            "proto": row.protocol,
            "service": row.service,
            "banner": " ".join(filter(None, [row.version or "", row.banner])).strip(),
        })
    return out


def _run_scan_targets_sync(host: str, ports: str):
    async def _run():
        return await scan_targets(
            [host],
            parse_ports(ports),
            timeout=1.5,
            concurrency=100,
            banners=True,
            version_detection=True,
            script_scan=False,
        )

    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(_run())

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
        return ex.submit(lambda: asyncio.run(_run())).result(timeout=180)


def _package_version_from_banner(service: str, banner: str) -> tuple[str, str]:
    # e.g. "OpenSSH 7.2p2 Ubuntu-4ubuntu2.10" or "Apache httpd 2.4.29"
    m = re.search(r"([A-Za-z][A-Za-z_\-.]+?)[\s/]+(\d+\.\d+(?:\.\d+)*(?:[a-z]\d*)?)", banner)
    if m:
        return m.group(1).lower(), m.group(2)
    return service.lower(), ""


def _sync_osv(feed, ecosystem: str, pkg: str, ver: str):
    import asyncio
    return asyncio.get_event_loop().run_until_complete(
        feed.osv_query(ecosystem, pkg, ver)
    ) if not asyncio.get_event_loop().is_running() else _sync_gather_osv(feed, ecosystem, pkg, ver)


def _sync_gather_osv(feed, ecosystem: str, pkg: str, ver: str):
    import asyncio
    # Best-effort when inside an already-running loop — spin a fresh loop on a thread
    import concurrent.futures
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
        future = ex.submit(
            lambda: asyncio.run(feed.osv_query(ecosystem, pkg, ver))
        )
        try:
            return future.result(timeout=15)
        except Exception:  # noqa: BLE001
            return []


def _open_port_finding(
    host: str, svc: dict[str, str], service_detected: str | None = None
) -> Finding:
    return Finding(
        title=f"Open port {svc['port']}/{svc['proto']} — {svc['service']} on {host}",
        severity=Severity.INFO,
        category="misconfiguration",
        owasp_category="A05",
        description=(
            f"Service '{svc['service']}' listening on {host}:{svc['port']}/{svc['proto']}"
            + (f" (identified as {service_detected})" if service_detected else "")
            + (f". Banner: {svc['banner']}" if svc["banner"] else "")
        ),
        remediation=(
            "Confirm this port is intentionally exposed; restrict via firewall/security group to "
            "the minimum required source networks; ensure the service is kept patched."
        ),
        endpoint=f"{host}:{svc['port']}",
        evidence=[Evidence(
            request_method="TCP", request_url=f"{host}:{svc['port']}",
            response_status=0, description=svc["banner"][:300],
        )],
    )

def _vuln_finding(host: str, svc: dict[str, str], pkg: str, ver: str, v: Any) -> Finding:
    sev = {
        "critical": Severity.CRITICAL, "high": Severity.HIGH,
        "medium": Severity.MEDIUM, "low": Severity.LOW, "info": Severity.INFO,
    }.get((v.severity or "medium").lower(), Severity.MEDIUM)
    kev = v.cve_info and v.cve_info.kev
    return Finding(
        title=f"{pkg} {ver} on {host}:{svc['port']} — {v.id}",
        severity=sev,
        category="components",
        owasp_category="A06",
        description=(
            f"The service '{pkg}' version '{ver}' running on {host}:{svc['port']} is "
            f"vulnerable to {v.id}: {v.summary}"
            + (" [CISA KEV — actively exploited]" if kev else "")
        ),
        remediation=(
            f"Upgrade {pkg} to {', '.join(v.fixed_versions) or 'a patched release'} and restart "
            f"the service. Segment the host behind a firewall if the upgrade cannot be "
            f"performed immediately."
        ),
        endpoint=f"{host}:{svc['port']}",
        parameter=f"{pkg}@{ver}",
        cvss_score=v.cvss_score,
        cvss_vector=v.cvss_vector,
        references=v.references,
        evidence=[Evidence(
            request_method="PENCHEFF-MAP", request_url=f"{host}:{svc['port']}",
            response_status=0, description=svc["banner"][:300],
        )],
    )
