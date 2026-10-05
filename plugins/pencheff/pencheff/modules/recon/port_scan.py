"""TCP/UDP port scanning via the shared netmap engine."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from pencheff.config import Severity
from pencheff.core.findings import Finding
from pencheff.core.http_client import PencheffHTTPClient
from pencheff.core.netmap import KNOWN_SERVICES, apply_timing_profile, parse_ports, parse_udp_ports, scan_targets
from pencheff.core.session import PentestSession
from pencheff.modules.base import BaseTestModule

# High-risk ports that shouldn't be exposed
HIGH_RISK_PORTS = {
    23: "Telnet (unencrypted remote access)",
    135: "MSRPC (Windows exploitation vector)",
    139: "NetBIOS (information leakage)",
    445: "SMB (ransomware / lateral movement)",
    1433: "MSSQL (database direct access)",
    1521: "Oracle DB (database direct access)",
    3306: "MySQL (database direct access)",
    3389: "RDP (remote desktop brute force)",
    5432: "PostgreSQL (database direct access)",
    5900: "VNC (remote access)",
    6379: "Redis (unauthenticated by default)",
    9200: "Elasticsearch (unauthenticated by default)",
    11211: "Memcached (DDoS amplification)",
    27017: "MongoDB (unauthenticated by default)",
}


class PortScanModule(BaseTestModule):
    name = "port_scan"
    category = "recon"
    owasp_categories = ["A05"]
    description = "TCP connect port scanning"

    def get_techniques(self) -> list[str]:
        return ["tcp_connect", "service_detection"]

    async def run(
        self,
        session: PentestSession,
        http: PencheffHTTPClient,
        targets: list[str] | None = None,
        config: dict[str, Any] | None = None,
    ) -> list[Finding]:
        config = config or {}
        port_range = config.get("port_range", "top-1000")
        host = urlparse(session.target.base_url).hostname
        if not host:
            return []

        timing = int(config.get("timing", 3))
        timeout, concurrency, delay = apply_timing_profile(
            timing,
            float(config.get("timeout", 1.5)),
            int(config.get("concurrency", 100)),
        )
        result = await scan_targets(
            [host],
            parse_ports(port_range),
            timeout=timeout,
            concurrency=concurrency,
            banners=True,
            version_detection=bool(config.get("version_detection", True)),
            script_scan=bool(config.get("script_scan", True)),
            os_detection=bool(config.get("os_detection", True)),
            traceroute=bool(config.get("traceroute", False)),
            udp_ports=parse_udp_ports(config.get("udp_ports", "top")) if config.get("udp_scan", False) else None,
            delay=delay,
        )
        open_ports = [
            {
                "port": r.port,
                "protocol": r.protocol,
                "state": r.state,
                "service": r.service,
                "banner": r.banner,
                "version": r.version,
                "scripts": r.scripts or {},
            }
            for r in result.open
        ]
        session.discovered.open_ports = open_ports

        findings = []

        # Generate findings for high-risk exposed ports
        for port_info in open_ports:
            port = port_info["port"]
            if port in HIGH_RISK_PORTS:
                findings.append(Finding(
                    title=f"High-Risk Port Exposed: {port} ({port_info['service']})",
                    severity=Severity.HIGH if port in (6379, 27017, 11211, 9200) else Severity.MEDIUM,
                    category="misconfiguration",
                    owasp_category="A05",
                    description=f"Port {port} ({HIGH_RISK_PORTS[port]}) is exposed to the network. "
                                "This service should not be directly accessible from the internet.",
                    remediation=f"Restrict access to port {port} using firewall rules. "
                                "Only allow connections from trusted IP ranges.",
                    endpoint=f"{host}:{port}",
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
                    cvss_score=6.5,
                    cwe_id="CWE-284",
                ))

        return findings
