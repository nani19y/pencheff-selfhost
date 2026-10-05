"""API parameter fuzzing and boundary testing."""

from __future__ import annotations

import json
from typing import Any

from pencheff.config import Severity
from pencheff.core.findings import Evidence, Finding
from pencheff.core.http_client import PencheffHTTPClient
from pencheff.core.session import PentestSession
from pencheff.modules.base import BaseTestModule

# Fuzz values keyed by transport. Long strings stay reasonable on GET so
# we don't trigger HTTP 414 (URI Too Long) and waste a probe slot on a
# request that never reaches the application.
_LONG_GET = "A" * 256        # safe for almost every server's URL limit
_LONG_POST = "A" * 4096      # exercises body-length handling without DoS

FUZZ_VALUES_BASE = [
    ("empty_string", ""),
    ("null", "null"),
    ("zero", "0"),
    ("negative", "-1"),
    ("large_number", "99999999999999999"),
    ("special_chars", "!@#$%^&*()"),
    ("html_tag", "<script>alert(1)</script>"),
    ("sql_quote", "' OR 1=1--"),
    ("json_object", '{"__proto__":{"admin":true}}'),
    ("array", "[]"),
    ("boolean", "true"),
    ("newline", "test\r\nHeader: injected"),
    ("unicode", "\\u0000\\uffff"),
]

FUZZ_VALUES_GET = FUZZ_VALUES_BASE + [("long_string", _LONG_GET)]
FUZZ_VALUES_POST = FUZZ_VALUES_BASE + [("long_string", _LONG_POST)]

# Status codes that mean "I rejected your input shape; further variants
# will be rejected the same way." Stop fuzzing this endpoint when seen.
_ABORT_STATUSES = {413, 414, 429, 431}

# Hard cap on probes per endpoint so a chatty fuzz value list multiplied
# by many parameters can never explode into thousands of requests.
_MAX_PROBES_PER_ENDPOINT = 60


class APIFuzzerModule(BaseTestModule):
    name = "api_fuzzer"
    category = "api"
    owasp_categories = ["A03", "A04"]
    description = "API parameter fuzzing and boundary testing"

    def get_techniques(self) -> list[str]:
        return ["parameter_fuzzing", "mass_assignment", "type_confusion"]

    async def run(
        self,
        session: PentestSession,
        http: PencheffHTTPClient,
        targets: list[str] | None = None,
        config: dict[str, Any] | None = None,
    ) -> list[Finding]:
        findings = []
        endpoints = self._get_target_endpoints(session, targets)

        # Focus on API endpoints
        api_endpoints = [
            ep for ep in endpoints
            if any(kw in ep["url"].lower() for kw in ["/api/", "/v1/", "/v2/", "/graphql"])
        ]
        if not api_endpoints:
            api_endpoints = endpoints

        for ep in self._cap_endpoints(api_endpoints, 15):
            url = ep["url"]
            params = ep.get("params", [])
            method = ep.get("method", "GET")
            is_body_method = method in ("POST", "PUT", "PATCH")
            fuzz_set = FUZZ_VALUES_POST if is_body_method else FUZZ_VALUES_GET

            # Get baseline
            try:
                baseline = await http.request(method, url, module="api_fuzzer")
                baseline_status = baseline.status_code
            except Exception:
                continue

            # If the endpoint already rejects the unauthenticated request
            # shape, fuzzing it produces zero signal. Skip — saves dozens
            # of requests per locked-down route (admin / login pages).
            if baseline_status in _ABORT_STATUSES:
                continue

            probes_used = 0
            abort_endpoint = False

            # Fuzz each parameter
            for param in params:
                if abort_endpoint:
                    break
                for fuzz_name, fuzz_value in fuzz_set:
                    if probes_used >= _MAX_PROBES_PER_ENDPOINT:
                        abort_endpoint = True
                        break
                    try:
                        if is_body_method:
                            resp = await http.post(
                                url,
                                json_data={param: fuzz_value},
                                module="api_fuzzer",
                            )
                        else:
                            resp = await http.get(
                                url, params={param: fuzz_value}, module="api_fuzzer",
                            )
                        probes_used += 1

                        # Hard stop on rejection signals so we don't keep
                        # flooding a server that's already saying no
                        # (414 URI Too Long, 413 Payload Too Large,
                        #  429 Too Many Requests, 431 Header Fields Too Large).
                        if resp.status_code in _ABORT_STATUSES:
                            abort_endpoint = True
                            break

                        # Check for interesting responses
                        if resp.status_code == 500:
                            findings.append(Finding(
                                title=f"Server Error on Fuzz Input ({fuzz_name})",
                                severity=Severity.MEDIUM,
                                category="injection",
                                owasp_category="A03",
                                description=f"Parameter '{param}' with fuzz value '{fuzz_name}' caused a 500 error. "
                                            "Improper input handling may lead to exploitation.",
                                remediation="Validate and sanitize all input. Handle edge cases gracefully.",
                                endpoint=url,
                                parameter=param,
                                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:L",
                                cvss_score=5.3,
                                cwe_id="CWE-20",
                                evidence=[Evidence(
                                    request_method=method,
                                    request_url=url,
                                    request_body=f"{param}={fuzz_value[:100]}",
                                    response_status=500,
                                    response_body_snippet=resp.text[:300],
                                    description=f"Fuzz type: {fuzz_name}",
                                )],
                            ))
                    except Exception:
                        continue

            # Test mass assignment
            if method in ("POST", "PUT", "PATCH"):
                mass_assign_fields = {
                    "role": "admin", "isAdmin": True, "admin": True,
                    "verified": True, "active": True, "credits": 99999,
                    "price": 0, "discount": 100,
                }
                try:
                    body = {param: "test" for param in params}
                    body.update(mass_assign_fields)
                    resp = await http.post(url, json_data=body, module="api_fuzzer")

                    if resp.status_code in (200, 201):
                        try:
                            resp_data = resp.json()
                            for field in mass_assign_fields:
                                if field in str(resp_data):
                                    findings.append(Finding(
                                        title="Potential Mass Assignment Vulnerability",
                                        severity=Severity.HIGH,
                                        category="authz",
                                        owasp_category="A04",
                                        description=f"Server accepted extra field '{field}' in request. "
                                                    "May allow privilege escalation or data manipulation.",
                                        remediation="Use allowlists for accepted parameters. "
                                                    "Never bind request body directly to data models.",
                                        endpoint=url,
                                        parameter=field,
                                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:N",
                                        cvss_score=7.1,
                                        cwe_id="CWE-915",
                                    ))
                                    break
                        except Exception:
                            pass
                except Exception:
                    pass

        return findings
