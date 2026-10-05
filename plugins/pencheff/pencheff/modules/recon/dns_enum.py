"""DNS enumeration module — discover DNS records for the target domain."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from datetime import datetime, timezone

from pencheff.config import Severity
from pencheff.core.findings import Evidence, Finding, SuppressReason
from pencheff.core.http_client import PencheffHTTPClient
from pencheff.core.session import PentestSession
from pencheff.core.tool_runner import run_tool, tool_available
from pencheff.modules.base import BaseTestModule


def _email_dns_finding_pre_suppressed(**kwargs) -> Finding:
    """Build an email-DNS finding pre-suppressed as out-of-scope.

    SPF / DMARC / DKIM checks fire whenever the target's domain has no
    matching TXT record — but for a web-application pentest those
    records are not in scope. We still record the finding (so the user
    can toggle "Show false positives" and see it) but flag it
    suppressed so it doesn't pollute the active list or burn an agent
    turn during verification.
    """
    f = Finding(**kwargs)
    f.suppressed = True
    f.suppress_reason = SuppressReason.OUT_OF_SCOPE
    f.suppress_notes = (
        "Auto-suppressed: email DNS records (SPF/DMARC/DKIM) are not "
        "part of the web-application attack surface. Toggle off if "
        "your engagement explicitly covers email security."
    )
    f.suppressed_at = datetime.now(timezone.utc)
    return f


class DnsEnumModule(BaseTestModule):
    name = "dns_enum"
    category = "recon"
    owasp_categories = ["A05"]
    description = "DNS record enumeration"

    def get_techniques(self) -> list[str]:
        return ["a_record", "aaaa_record", "mx_record", "ns_record", "txt_record", "cname_record", "soa_record"]

    async def run(
        self,
        session: PentestSession,
        http: PencheffHTTPClient,
        targets: list[str] | None = None,
        config: dict[str, Any] | None = None,
    ) -> list[Finding]:
        domain = urlparse(session.target.base_url).hostname
        if not domain:
            return []

        findings = []
        records: dict[str, list[str]] = {}

        record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]

        for rtype in record_types:
            try:
                if tool_available("dig"):
                    result = await run_tool(["dig", "+short", rtype, domain])
                    if result.success and result.stdout.strip():
                        records[rtype] = result.stdout.strip().split("\n")
                else:
                    # Fallback to dnspython
                    import dns.resolver
                    try:
                        answers = dns.resolver.resolve(domain, rtype)
                        records[rtype] = [str(r) for r in answers]
                    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
                        pass
            except Exception:
                continue

        # Check for zone transfer vulnerability
        ns_records = records.get("NS", [])
        for ns in ns_records:
            ns = ns.strip().rstrip(".")
            if tool_available("dig"):
                result = await run_tool(["dig", "AXFR", domain, f"@{ns}"], timeout=10)
                if result.success and "XFR size" in result.stdout:
                    findings.append(Finding(
                        title="DNS Zone Transfer Allowed",
                        severity=Severity.HIGH,
                        category="misconfiguration",
                        owasp_category="A05",
                        description=f"DNS zone transfer (AXFR) is allowed on nameserver {ns}. "
                                    "This exposes all DNS records to anyone.",
                        remediation="Restrict zone transfers to authorized secondary nameservers only.",
                        endpoint=domain,
                        parameter=ns,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                        cvss_score=5.3,
                        cwe_id="CWE-200",
                        evidence=[Evidence(
                            request_method="DNS",
                            request_url=f"AXFR {domain} @{ns}",
                            response_body_snippet=result.stdout[:500],
                            description="Zone transfer succeeded",
                        )],
                    ))

        # Check for SPF/DMARC in TXT records
        txt_records = records.get("TXT", [])
        has_spf = any("v=spf1" in r for r in txt_records)
        has_dmarc = False

        if tool_available("dig"):
            dmarc_result = await run_tool(["dig", "+short", "TXT", f"_dmarc.{domain}"])
            if dmarc_result.success and "v=DMARC1" in dmarc_result.stdout:
                has_dmarc = True

        if not has_spf:
            findings.append(_email_dns_finding_pre_suppressed(
                title="Missing SPF Record",
                severity=Severity.LOW,
                category="misconfiguration",
                owasp_category="A05",
                description="No SPF record found. The domain may be vulnerable to email spoofing.",
                remediation="Add an SPF TXT record to specify authorized mail servers.",
                endpoint=domain,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
                cvss_score=4.3,
                cwe_id="CWE-290",
            ))

        if not has_dmarc:
            findings.append(_email_dns_finding_pre_suppressed(
                title="Missing DMARC Record",
                severity=Severity.LOW,
                category="misconfiguration",
                owasp_category="A05",
                description="No DMARC record found. Email spoofing protection is incomplete.",
                remediation="Add a DMARC TXT record at _dmarc.domain with at least p=none for monitoring.",
                endpoint=domain,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
                cvss_score=4.3,
                cwe_id="CWE-290",
            ))

        # Store DNS info in session
        session.discovered.tech_stack["dns"] = [
            f"{rtype}: {', '.join(vals)}" for rtype, vals in records.items()
        ]

        return findings
