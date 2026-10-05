"""Subdomain takeover detection module."""

from __future__ import annotations

from typing import Any

from pencheff.config import Severity
from pencheff.core.findings import Evidence, Finding
from pencheff.core.http_client import PencheffHTTPClient
from pencheff.core.session import PentestSession
from pencheff.modules.base import BaseTestModule

# Service fingerprints: CNAME patterns and unclaimed response signatures
TAKEOVER_FINGERPRINTS = {
    "github_pages": {
        "cnames": ["github.io", "github.com"],
        "signatures": ["there isn't a github pages site here", "for root urls (like"],
        "status_codes": [404],
    },
    "heroku": {
        "cnames": ["herokuapp.com", "herokussl.com"],
        "signatures": ["no such app", "there is no app configured at that hostname"],
        "status_codes": [404],
    },
    "aws_s3": {
        "cnames": ["s3.amazonaws.com", "s3-website", ".s3."],
        "signatures": ["nosuchbucket", "the specified bucket does not exist"],
        "status_codes": [404],
    },
    "azure": {
        "cnames": ["azurewebsites.net", "cloudapp.azure.com", "azure-api.net", "azurefd.net", "blob.core.windows.net", "trafficmanager.net"],
        "signatures": ["404 web site not found", "azure web app - error 404"],
        "status_codes": [404],
    },
    "shopify": {
        "cnames": ["myshopify.com"],
        "signatures": ["sorry, this shop is currently unavailable", "only one step left"],
        "status_codes": [404],
    },
    "fastly": {
        "cnames": ["fastly.net", "global.ssl.fastly.net"],
        "signatures": ["fastly error: unknown domain"],
        "status_codes": [500],
    },
    "pantheon": {
        "cnames": ["pantheonsite.io"],
        "signatures": ["404 error unknown site", "the gods are wise"],
        "status_codes": [404],
    },
    "tumblr": {
        "cnames": ["tumblr.com"],
        "signatures": ["whatever you were looking for doesn't currently exist at this address", "there's nothing here"],
        "status_codes": [404],
    },
    "wordpress": {
        "cnames": ["wordpress.com"],
        "signatures": ["do you want to register"],
        "status_codes": [404],
    },
    "ghost": {
        "cnames": ["ghost.io"],
        "signatures": ["the thing you were looking for is no longer here"],
        "status_codes": [404],
    },
    "surge": {
        "cnames": ["surge.sh"],
        "signatures": ["project not found"],
        "status_codes": [404],
    },
    "bitbucket": {
        "cnames": ["bitbucket.io"],
        "signatures": ["repository not found"],
        "status_codes": [404],
    },
    "netlify": {
        "cnames": ["netlify.app", "netlify.com"],
        "signatures": ["not found - request id"],
        "status_codes": [404],
    },
    "fly_io": {
        "cnames": ["fly.dev"],
        "signatures": ["404 not found"],
        "status_codes": [404],
    },
    "vercel": {
        "cnames": ["vercel.app", "now.sh"],
        "signatures": ["the deployment could not be found", "deployment_not_found"],
        "status_codes": [404],
    },
    "cargo_collective": {
        "cnames": ["cargocollective.com"],
        "signatures": ["404 not found"],
        "status_codes": [404],
    },
    "readme_io": {
        "cnames": ["readme.io"],
        "signatures": ["project doesnt exist"],
        "status_codes": [404],
    },
    "zendesk": {
        "cnames": ["zendesk.com"],
        "signatures": ["help center closed"],
        "status_codes": [404],
    },
    "unbounce": {
        "cnames": ["unbouncepages.com"],
        "signatures": ["the requested url was not found on this server"],
        "status_codes": [404],
    },
    "teamwork": {
        "cnames": ["teamwork.com"],
        "signatures": ["oops - we didn't find your site"],
        "status_codes": [404],
    },
}


class SubdomainTakeoverModule(BaseTestModule):
    """Detect subdomain takeover vulnerabilities via dangling DNS records."""

    name = "subdomain_takeover"
    category = "subdomain_takeover"
    owasp_categories = ["A05"]
    description = "Subdomain takeover detection via dangling CNAME records"

    def get_techniques(self) -> list[str]:
        return [
            "dangling_cname_detection",
            "service_fingerprinting",
            "ns_delegation_check",
        ]

    async def run(
        self,
        session: PentestSession,
        http: PencheffHTTPClient,
        targets: list[str] | None = None,
        config: dict[str, Any] | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []

        # Get subdomains to test
        subdomains = targets or session.discovered.subdomains
        if not subdomains:
            return findings

        # Resolve CNAME records for each subdomain
        try:
            import dns.resolver
            has_dns = True
        except ImportError:
            has_dns = False

        for subdomain in subdomains[:50]:
            # Ensure it's a full domain (not just a subdomain fragment)
            if "." not in subdomain:
                subdomain = f"{subdomain}.{session.target.base_url.split('//')[1].split('/')[0]}"

            # Step 1: Resolve CNAME
            cname_target = None
            if has_dns:
                try:
                    answers = dns.resolver.resolve(subdomain, "CNAME")
                    for rdata in answers:
                        cname_target = str(rdata.target).rstrip(".")
                        session.discovered.cname_records.append({
                            "subdomain": subdomain,
                            "cname": cname_target,
                        })
                except Exception:
                    pass

            # Step 2: Check for takeover signatures via HTTP
            for scheme in ("https", "http"):
                url = f"{scheme}://{subdomain}"
                try:
                    resp = await http.get(url, module="subdomain_takeover")
                    body_lower = resp.text.lower()

                    for service, fingerprint in TAKEOVER_FINGERPRINTS.items():
                        # Check if CNAME matches service
                        cname_match = False
                        if cname_target:
                            cname_match = any(c in cname_target.lower() for c in fingerprint["cnames"])

                        # Check response signatures
                        sig_match = any(sig in body_lower for sig in fingerprint["signatures"])
                        status_match = resp.status_code in fingerprint.get("status_codes", [])

                        if sig_match and (cname_match or status_match):
                            findings.append(Finding(
                                title=f"Subdomain Takeover: {subdomain} ({service})",
                                severity=Severity.HIGH,
                                category="subdomain_takeover",
                                owasp_category="A05",
                                description=(
                                    f"The subdomain '{subdomain}' appears vulnerable to takeover. "
                                    f"It points to {service} (CNAME: {cname_target or 'N/A'}) but the "
                                    f"service is unclaimed. An attacker can register the service and "
                                    f"serve malicious content on this subdomain, enabling phishing, "
                                    f"cookie theft, and CSP bypass."
                                ),
                                remediation=(
                                    f"Remove the dangling DNS record for {subdomain}, or reclaim the "
                                    f"service on {service}. Audit all DNS records regularly."
                                ),
                                endpoint=url,
                                evidence=[Evidence(
                                    request_method="GET",
                                    request_url=url,
                                    response_status=resp.status_code,
                                    response_body_snippet=resp.text[:300],
                                    description=f"CNAME: {cname_target}, Service: {service}, Signature matched",
                                )],
                                cwe_id="CWE-284",
                                cvss_score=7.5,
                                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
                            ))
                            break
                    break  # Only need one scheme to succeed
                except Exception:
                    continue

        return findings
