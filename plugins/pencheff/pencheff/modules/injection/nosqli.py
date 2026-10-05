"""NoSQL injection testing — MongoDB operator injection, JSON injection."""

from __future__ import annotations

import json
from typing import Any

from pencheff.config import Severity
from pencheff.core.findings import Evidence, Finding
from pencheff.core.http_client import PencheffHTTPClient
from pencheff.core.session import PentestSession
from pencheff.modules.injection import param_names
from pencheff.modules.base import BaseTestModule

NOSQL_PAYLOADS = [
    {"$gt": ""},
    {"$ne": ""},
    {"$regex": ".*"},
    {"$exists": True},
]

NOSQL_STRING_PAYLOADS = [
    "' || '1'=='1",
    "'; return true; var x='",
    "{\"$gt\": \"\"}",
    "{\"$ne\": \"\"}",
    "true, $where: '1 == 1'",
    "[$ne]=1",
]


class NoSQLiModule(BaseTestModule):
    name = "nosqli"
    category = "injection"
    owasp_categories = ["A03"]
    description = "NoSQL injection testing"

    def get_techniques(self) -> list[str]:
        return ["operator_injection", "json_injection", "js_injection"]

    async def run(
        self,
        session: PentestSession,
        http: PencheffHTTPClient,
        targets: list[str] | None = None,
        config: dict[str, Any] | None = None,
    ) -> list[Finding]:
        findings = []
        endpoints = self._get_target_endpoints(session, targets)

        for ep in self._cap_endpoints(endpoints, 20):
            url = ep["url"]
            params = param_names(ep.get("params", []))
            method = ep.get("method", "GET")

            # Get baseline response
            try:
                baseline = await http.get(url, module="nosqli")
                baseline_len = len(baseline.text)
                baseline_status = baseline.status_code
            except Exception:
                continue

            for param in params:
                # Test operator injection via JSON body
                if method in ("POST", "PUT", "PATCH"):
                    for payload in NOSQL_PAYLOADS:
                        try:
                            body = json.dumps({param: payload})
                            resp = await http.post(
                                url, body=body,
                                headers={"Content-Type": "application/json"},
                                module="nosqli",
                            )
                            if resp.status_code != baseline_status or abs(len(resp.text) - baseline_len) > 100:
                                findings.append(Finding(
                                    title="NoSQL Injection (Operator Injection)",
                                    severity=Severity.HIGH,
                                    category="injection",
                                    owasp_category="A03",
                                    description=f"NoSQL operator injection in parameter '{param}'. "
                                                f"Payload {json.dumps(payload)} produced different response.",
                                    remediation="Validate and sanitize all input. Use parameterized queries. "
                                                "Reject objects/operators in user input fields.",
                                    endpoint=url,
                                    parameter=param,
                                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                                    cvss_score=9.1,
                                    cwe_id="CWE-943",
                                    evidence=[Evidence(
                                        request_method="POST",
                                        request_url=url,
                                        request_body=body,
                                        response_status=resp.status_code,
                                        response_body_snippet=resp.text[:300],
                                        description="Response differs with NoSQL operator payload",
                                    )],
                                ))
                                break
                        except Exception:
                            continue

                # Test string payloads via query params
                for payload in NOSQL_STRING_PAYLOADS:
                    try:
                        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
                        parsed = urlparse(url)
                        qs = parse_qs(parsed.query, keep_blank_values=True)
                        qs[param] = [payload]
                        test_url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))
                        resp = await http.get(test_url, module="nosqli")

                        if resp.status_code != baseline_status or abs(len(resp.text) - baseline_len) > 100:
                            findings.append(Finding(
                                title="NoSQL Injection (String Payload)",
                                severity=Severity.HIGH,
                                category="injection",
                                owasp_category="A03",
                                description=f"Potential NoSQL injection in parameter '{param}' via string payload.",
                                remediation="Sanitize input. Reject special characters and MongoDB operators.",
                                endpoint=url,
                                parameter=param,
                                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                                cvss_score=9.1,
                                cwe_id="CWE-943",
                                evidence=[Evidence(
                                    request_method="GET",
                                    request_url=test_url,
                                    response_status=resp.status_code,
                                    description=f"Payload: {payload}",
                                )],
                            ))
                            break
                    except Exception:
                        continue

        return findings
