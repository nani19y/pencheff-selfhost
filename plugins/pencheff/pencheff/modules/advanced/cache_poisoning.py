"""Web cache poisoning and cache deception module."""

from __future__ import annotations

import hashlib
import time
from typing import Any

from pencheff.config import Severity
from pencheff.core.findings import Evidence, Finding
from pencheff.core.http_client import PencheffHTTPClient
from pencheff.core.session import PentestSession
from pencheff.modules.base import BaseTestModule

# Headers commonly unkeyed by caches but reflected in responses
UNKEYED_HEADERS = [
    ("X-Forwarded-Host", "pencheff-canary.example.com"),
    ("X-Original-URL", "/pencheff-canary"),
    ("X-Rewrite-URL", "/pencheff-canary"),
    ("X-Forwarded-Scheme", "nothttps"),
    ("X-Forwarded-Proto", "nothttps"),
    ("X-Host", "pencheff-canary.example.com"),
    ("X-Forwarded-Server", "pencheff-canary.example.com"),
    ("X-HTTP-Method-Override", "POST"),
    ("X-Original-Host", "pencheff-canary.example.com"),
    ("X-Forwarded-For", "127.0.0.1"),
]

# Static file extensions that caches commonly store
CACHEABLE_EXTENSIONS = [
    ".css", ".js", ".png", ".jpg", ".gif", ".ico", ".svg", ".woff", ".woff2",
]


class CachePoisoningModule(BaseTestModule):
    """Detect web cache poisoning and cache deception vulnerabilities."""

    name = "cache_poisoning"
    category = "cache_poisoning"
    owasp_categories = ["A05"]
    description = "Web cache poisoning via unkeyed headers and cache deception"

    def get_techniques(self) -> list[str]:
        return [
            "unkeyed_header_poisoning",
            "cache_deception",
            "parameter_cloaking",
            "fat_get_poisoning",
        ]

    async def run(
        self,
        session: PentestSession,
        http: PencheffHTTPClient,
        targets: list[str] | None = None,
        config: dict[str, Any] | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []
        base_url = session.target.base_url
        endpoints = self._get_target_endpoints(session, targets)

        # Phase 1: Test unkeyed header injection
        header_findings = await self._test_unkeyed_headers(http, base_url, session)
        findings.extend(header_findings)

        # Phase 2: Test cache deception
        deception_findings = await self._test_cache_deception(http, endpoints, session)
        findings.extend(deception_findings)

        # Phase 3: Test fat GET / parameter cloaking
        fat_get_findings = await self._test_fat_get(http, base_url, session)
        findings.extend(fat_get_findings)

        return findings

    async def _test_unkeyed_headers(
        self, http: PencheffHTTPClient, base_url: str, session: PentestSession,
    ) -> list[Finding]:
        """Test if unkeyed headers are reflected in cached responses."""
        findings: list[Finding] = []
        canary = hashlib.md5(str(time.time()).encode()).hexdigest()[:8]

        for header_name, header_value in UNKEYED_HEADERS:
            # Use a cache-buster to get a fresh response
            buster = hashlib.md5(f"{header_name}{time.time()}".encode()).hexdigest()[:6]
            test_url = f"{base_url}/?cb={buster}"

            try:
                # Send request with unkeyed header
                resp1 = await http.get(
                    test_url,
                    headers={header_name: f"{canary}.example.com"},
                    module="cache_poisoning",
                )

                # Check if canary is reflected in response
                if canary in resp1.text:
                    # Verify caching: request again without the header
                    resp2 = await http.get(test_url, module="cache_poisoning")

                    if canary in resp2.text:
                        # Poisoned response was cached!
                        findings.append(Finding(
                            title=f"Web Cache Poisoning via {header_name}",
                            severity=Severity.HIGH,
                            category="cache_poisoning",
                            owasp_category="A05",
                            description=(
                                f"The header '{header_name}' is reflected in the response but not "
                                f"included in the cache key. An attacker can poison the cache to "
                                f"serve malicious content (XSS, redirects) to all users."
                            ),
                            remediation=(
                                f"Include '{header_name}' in the cache key via Vary header, or "
                                f"stop reflecting this header in responses. Review CDN/cache configuration."
                            ),
                            endpoint=test_url,
                            parameter=header_name,
                            evidence=[
                                Evidence(
                                    request_method="GET",
                                    request_url=test_url,
                                    request_headers={header_name: f"{canary}.example.com"},
                                    response_status=resp1.status_code,
                                    response_body_snippet=resp1.text[:300],
                                    description=f"Canary '{canary}' reflected via {header_name}",
                                ),
                                Evidence(
                                    request_method="GET",
                                    request_url=test_url,
                                    response_status=resp2.status_code,
                                    response_body_snippet=resp2.text[:300],
                                    description="Poisoned response served from cache",
                                ),
                            ],
                            cwe_id="CWE-525",
                            cvss_score=7.5,
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
                        ))
                    else:
                        # Header is reflected but not cached — still noteworthy
                        findings.append(Finding(
                            title=f"Unkeyed Header Reflected: {header_name}",
                            severity=Severity.LOW,
                            category="cache_poisoning",
                            owasp_category="A05",
                            description=(
                                f"The header '{header_name}' value is reflected in the response. "
                                f"While not currently cached, this could become exploitable if "
                                f"caching configuration changes."
                            ),
                            remediation=f"Stop reflecting '{header_name}' in responses, or include it in the Vary header.",
                            endpoint=test_url,
                            parameter=header_name,
                            evidence=[Evidence(
                                request_method="GET",
                                request_url=test_url,
                                request_headers={header_name: f"{canary}.example.com"},
                                response_status=resp1.status_code,
                                description=f"Canary reflected but not cached",
                            )],
                            cwe_id="CWE-525",
                            cvss_score=3.7,
                        ))
            except Exception:
                continue

        return findings

    async def _test_cache_deception(
        self, http: PencheffHTTPClient,
        endpoints: list[dict[str, Any]],
        session: PentestSession,
    ) -> list[Finding]:
        """Test web cache deception: trick cache into storing authenticated responses."""
        findings: list[Finding] = []

        # Test authenticated endpoints with static extension suffixes
        for ep in endpoints[:10]:
            url = ep["url"]
            for ext in CACHEABLE_EXTENSIONS[:3]:
                deception_url = f"{url}/nonexistent{ext}"
                try:
                    resp = await http.get(deception_url, module="cache_poisoning")

                    # If the response contains the same content as the original page
                    # (ignoring 404), the server is ignoring the path suffix
                    if resp.status_code == 200:
                        original = await http.get(url, module="cache_poisoning")
                        if original.status_code == 200 and len(resp.text) > 100:
                            # Check for similarity
                            if abs(len(resp.text) - len(original.text)) < len(original.text) * 0.2:
                                cache_headers = {
                                    k.lower(): v for k, v in resp.headers.items()
                                    if "cache" in k.lower() or k.lower() in ("age", "x-cache", "cf-cache-status")
                                }
                                if cache_headers:
                                    findings.append(Finding(
                                        title="Web Cache Deception Vulnerability",
                                        severity=Severity.HIGH,
                                        category="cache_poisoning",
                                        owasp_category="A05",
                                        description=(
                                            f"The server returns the same content for '{url}' and "
                                            f"'{deception_url}', and the response appears to be cached. "
                                            f"An attacker can trick a victim into visiting the deception URL, "
                                            f"causing their authenticated response to be cached publicly."
                                        ),
                                        remediation=(
                                            "Configure the cache to only store responses based on content-type, "
                                            "not URL extension. Return 404 for invalid path suffixes."
                                        ),
                                        endpoint=deception_url,
                                        evidence=[Evidence(
                                            request_method="GET",
                                            request_url=deception_url,
                                            response_status=resp.status_code,
                                            response_headers=cache_headers,
                                            description="Authenticated content served with cache headers",
                                        )],
                                        cwe_id="CWE-525",
                                        cvss_score=7.5,
                                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
                                    ))
                                    return findings  # One finding is sufficient
                except Exception:
                    continue

        return findings

    async def _test_fat_get(
        self, http: PencheffHTTPClient, base_url: str, session: PentestSession,
    ) -> list[Finding]:
        """Test fat GET requests (GET with body) for parameter cloaking."""
        findings: list[Finding] = []

        try:
            # Send a GET request with a body — some frameworks process it
            resp = await http.request(
                "GET", base_url,
                body="admin=true&role=admin",
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                module="cache_poisoning",
            )

            # Compare with normal GET
            normal = await http.get(base_url, module="cache_poisoning")

            if resp.text != normal.text and resp.status_code == 200:
                findings.append(Finding(
                    title="Fat GET Request Processed",
                    severity=Severity.MEDIUM,
                    category="cache_poisoning",
                    owasp_category="A05",
                    description=(
                        "The server processes body parameters in GET requests. Combined with "
                        "caching (where GET body is not part of cache key), this enables "
                        "parameter cloaking attacks for cache poisoning."
                    ),
                    remediation="Ignore request body for GET requests. Configure cache to reject GET requests with bodies.",
                    endpoint=base_url,
                    evidence=[Evidence(
                        request_method="GET",
                        request_url=base_url,
                        request_body="admin=true&role=admin",
                        response_status=resp.status_code,
                        description="GET with body produced different response",
                    )],
                    cwe_id="CWE-444",
                    cvss_score=5.3,
                ))
        except Exception:
            pass

        return findings
