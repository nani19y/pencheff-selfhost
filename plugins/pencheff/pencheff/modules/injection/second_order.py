"""Second-order injection detection module."""

from __future__ import annotations

from typing import Any

from pencheff.config import Severity
from pencheff.core.findings import Evidence, Finding
from pencheff.core.http_client import PencheffHTTPClient
from pencheff.core.payload_loader import load_payloads
from pencheff.core.session import PentestSession
from pencheff.modules.base import BaseTestModule

# Canary payloads that produce distinctive output when processed
SECOND_ORDER_PAYLOADS = {
    "sqli": [
        "' || (SELECT 'PENCHEFF_SQLI_CANARY') || '",
        "1; SELECT 'PENCHEFF_SQLI_CANARY'--",
    ],
    "xss": [
        '<img src=x onerror="PENCHEFF_XSS_CANARY">',
        "PENCHEFF_XSS_CANARY<script>1</script>",
    ],
    "ssti": [
        "{{PENCHEFF_SSTI_CANARY}}",
        "${PENCHEFF_SSTI_CANARY}",
        "<%= PENCHEFF_SSTI_CANARY %>",
    ],
}

CANARY_MARKERS = ["PENCHEFF_SQLI_CANARY", "PENCHEFF_XSS_CANARY", "PENCHEFF_SSTI_CANARY"]


class SecondOrderInjectionModule(BaseTestModule):
    """Detect second-order (stored) injection vulnerabilities using canary payloads."""

    name = "second_order_injection"
    category = "injection"
    owasp_categories = ["A03"]
    description = "Second-order injection: stored SQLi/XSS/SSTI via inject-then-trigger"

    def get_techniques(self) -> list[str]:
        return ["stored_sqli", "stored_xss", "stored_ssti"]

    async def run(
        self,
        session: PentestSession,
        http: PencheffHTTPClient,
        targets: list[str] | None = None,
        config: dict[str, Any] | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []
        endpoints = self._get_target_endpoints(session, targets)

        # Phase 1: Inject canary payloads into writable endpoints
        write_endpoints = [
            ep for ep in endpoints
            if ep.get("method", "GET") in ("POST", "PUT", "PATCH")
        ]
        injected_urls: list[str] = []

        for ep in self._cap_endpoints(write_endpoints, 10):
            url = ep["url"]
            method = ep.get("method", "POST")

            for attack_type, payloads in SECOND_ORDER_PAYLOADS.items():
                for payload in payloads:
                    try:
                        # Try injecting via common field names
                        for field in ["name", "comment", "message", "title", "description", "bio", "note"]:
                            resp = await http.request(
                                method, url,
                                json_data={field: payload},
                                module="second_order_injection",
                            )
                            if resp.status_code in (200, 201, 302):
                                injected_urls.append(url)
                                break
                    except Exception:
                        continue

        if not injected_urls:
            return findings

        # Phase 2: Crawl readable endpoints to look for triggered canaries
        read_endpoints = [ep for ep in endpoints if ep.get("method", "GET") == "GET"]

        for ep in self._cap_endpoints(read_endpoints, 30):
            url = ep["url"]
            try:
                resp = await http.get(url, module="second_order_injection")
                body = resp.text

                for marker in CANARY_MARKERS:
                    if marker in body:
                        attack_type = "Unknown"
                        if "SQLI" in marker:
                            attack_type = "SQL Injection"
                        elif "XSS" in marker:
                            attack_type = "Cross-Site Scripting"
                        elif "SSTI" in marker:
                            attack_type = "Server-Side Template Injection"

                        findings.append(Finding(
                            title=f"Second-Order {attack_type}: {url}",
                            severity=Severity.CRITICAL if "SQLI" in marker else Severity.HIGH,
                            category="injection",
                            owasp_category="A03",
                            description=(
                                f"A second-order {attack_type.lower()} vulnerability was detected. "
                                f"A canary payload injected via a write endpoint was triggered "
                                f"when the data was rendered at '{url}'. This means stored user "
                                f"input is processed unsafely in a different context."
                            ),
                            remediation=(
                                f"Sanitize stored data when it is output, not just when it is input. "
                                f"Use parameterized queries for SQL, context-aware output encoding for "
                                f"XSS, and safe template rendering for SSTI."
                            ),
                            endpoint=url,
                            evidence=[Evidence(
                                request_method="GET",
                                request_url=url,
                                response_status=resp.status_code,
                                response_body_snippet=body[max(0, body.index(marker)-50):body.index(marker)+100][:300],
                                description=f"Canary marker '{marker}' found in response",
                            )],
                            cwe_id="CWE-89" if "SQLI" in marker else "CWE-79",
                            cvss_score=9.8 if "SQLI" in marker else 8.1,
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" if "SQLI" in marker else "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N",
                        ))
            except Exception:
                continue

        return findings
