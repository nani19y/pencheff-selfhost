"""Subdomain enumeration via certificate transparency and DNS brute force."""

from __future__ import annotations

import asyncio
import socket
from typing import Any
from urllib.parse import urlparse

from pencheff.config import Severity
from pencheff.core.findings import Finding
from pencheff.core.http_client import PencheffHTTPClient
from pencheff.core.session import PentestSession
from pencheff.modules.base import BaseTestModule


def _normalize_hostname(host: str) -> str:
    """Collapse repeated leading subdomain labels (e.g. ``www.www.x``).

    The brute-force loop and the cert-transparency feed can both
    produce duplicates like ``www.www.example.com`` when the input
    target is already ``www.example.com`` and the prefix list adds
    another ``www`` on top. Normalise so they coalesce in the
    ``discovered`` set rather than each becoming its own scan target.
    """
    host = host.strip().lower().rstrip(".")
    parts = host.split(".")
    while len(parts) >= 4 and parts[0] == parts[1]:
        parts = parts[1:]
    return ".".join(parts)


def _apex_domain(host: str) -> str:
    """Strip a single leading ``www.`` so the brute-force loop builds
    ``api.example.com`` rather than ``api.www.example.com`` when the
    target was registered as ``www.example.com``.
    """
    host = host.strip().lower().rstrip(".")
    if host.startswith("www.") and host.count(".") >= 2:
        return host[4:]
    return host

# Common subdomain prefixes for brute force
COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "smtp", "pop", "ns1", "ns2", "dns", "mx",
    "api", "dev", "staging", "test", "beta", "admin", "portal",
    "app", "web", "blog", "shop", "store", "cdn", "static", "media",
    "img", "images", "assets", "docs", "wiki", "git", "svn",
    "jenkins", "ci", "cd", "deploy", "monitor", "grafana", "kibana",
    "elastic", "db", "database", "mysql", "postgres", "redis", "mongo",
    "vpn", "remote", "gateway", "proxy", "lb", "load", "internal",
    "intranet", "extranet", "sso", "auth", "login", "oauth",
    "status", "health", "dashboard", "console", "panel",
    "backup", "bak", "old", "new", "v2", "v3", "legacy",
    "sandbox", "demo", "qa", "uat", "preprod", "pre-prod",
    "s3", "aws", "cloud", "azure", "gcp",
]


class SubdomainModule(BaseTestModule):
    name = "subdomain_enum"
    category = "recon"
    owasp_categories = ["A05"]
    description = "Subdomain enumeration via cert transparency and DNS brute force"

    def get_techniques(self) -> list[str]:
        return ["cert_transparency", "dns_brute"]

    async def run(
        self,
        session: PentestSession,
        http: PencheffHTTPClient,
        targets: list[str] | None = None,
        config: dict[str, Any] | None = None,
    ) -> list[Finding]:
        raw_domain = urlparse(session.target.base_url).hostname
        if not raw_domain:
            return []
        # Use the apex (without leading "www.") as the brute-force base
        # so we don't produce ``www.www.example.com``; cert-transparency
        # queries get the apex too so we capture every sibling subdomain.
        domain = _apex_domain(raw_domain)

        findings = []
        discovered = set()

        # Method 1: Certificate Transparency via crt.sh
        try:
            resp = await http.get(
                f"https://crt.sh/?q=%.{domain}&output=json",
                module="subdomain_enum",
                inject_creds=False,
            )
            if resp.status_code == 200:
                entries = resp.json()
                for entry in entries:
                    name = entry.get("name_value", "")
                    for sub in name.split("\n"):
                        sub = _normalize_hostname(sub)
                        if (
                            sub
                            and sub.endswith(domain)
                            and sub != domain
                            and "*" not in sub
                        ):
                            discovered.add(sub)
        except Exception:
            pass

        # Method 2: DNS brute force with common prefixes
        async def check_subdomain(prefix: str) -> str | None:
            fqdn = _normalize_hostname(f"{prefix}.{domain}")
            try:
                loop = asyncio.get_event_loop()
                await loop.getaddrinfo(fqdn, None)
                return fqdn
            except socket.gaierror:
                return None

        tasks = [check_subdomain(prefix) for prefix in COMMON_SUBDOMAINS]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, str):
                discovered.add(r)

        session.discovered.subdomains = sorted(discovered)

        # Check for potential subdomain takeover indicators
        for sub in list(discovered)[:20]:  # check top 20
            try:
                resp = await http.get(
                    f"https://{sub}",
                    module="subdomain_enum",
                    inject_creds=False,
                    follow_redirects=False,
                )
                # Common takeover indicators
                takeover_signs = [
                    "There isn't a GitHub Pages site here",
                    "NoSuchBucket",
                    "No such app",
                    "Heroku | No such app",
                    "NXDOMAIN",
                    "The request could not be satisfied",
                    "Repository not found",
                ]
                for sign in takeover_signs:
                    if sign.lower() in resp.text.lower():
                        findings.append(Finding(
                            title=f"Potential Subdomain Takeover: {sub}",
                            severity=Severity.HIGH,
                            category="misconfiguration",
                            owasp_category="A05",
                            description=f"Subdomain {sub} shows signs of being vulnerable to takeover. "
                                        f"Indicator: '{sign}'",
                            remediation="Remove the dangling DNS record or reclaim the external service.",
                            endpoint=sub,
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N",
                            cvss_score=7.2,
                            cwe_id="CWE-284",
                        ))
                        break
            except Exception:
                continue

        return findings
