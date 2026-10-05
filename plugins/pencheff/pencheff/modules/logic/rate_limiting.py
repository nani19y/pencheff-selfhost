"""Rate limiting and brute force resistance testing."""

from __future__ import annotations

import asyncio
import time
from typing import Any

from pencheff.config import Severity
from pencheff.core.findings import Evidence, Finding
from pencheff.core.http_client import PencheffHTTPClient
from pencheff.core.session import PentestSession
from pencheff.modules.base import BaseTestModule


class RateLimitModule(BaseTestModule):
    name = "rate_limiting"
    category = "logic"
    owasp_categories = ["A04"]
    description = "Rate limiting and abuse prevention testing"

    def get_techniques(self) -> list[str]:
        return ["rapid_requests", "rate_limit_headers"]

    async def run(
        self,
        session: PentestSession,
        http: PencheffHTTPClient,
        targets: list[str] | None = None,
        config: dict[str, Any] | None = None,
    ) -> list[Finding]:
        findings = []
        base_url = session.target.base_url
        endpoints = self._get_target_endpoints(session, targets)

        # Test sensitive endpoints
        sensitive = [ep for ep in endpoints if any(
            kw in ep["url"].lower()
            for kw in ["login", "register", "password", "token", "api", "payment", "checkout"]
        )]
        if not sensitive:
            sensitive = [{"url": base_url, "method": "GET", "params": []}]

        from pencheff.core.spa_detector import is_real_endpoint
        for ep in sensitive[:5]:
            url = ep["url"]

            # Confirm the endpoint really exists before flooding it.
            # On a SPA every "sensitive path" candidate (/login,
            # /register, /api/*, etc.) returns the index.html catchall
            # and would otherwise yield a "no rate limiting" finding
            # against a phantom endpoint.
            try:
                preflight = await http.get(url, module="rate_limiting")
            except Exception:
                continue
            if not is_real_endpoint(preflight, session):
                continue

            # Send rapid requests
            statuses = []
            start = time.monotonic()
            for _ in range(30):
                try:
                    resp = await http.get(url, module="rate_limiting")
                    statuses.append(resp.status_code)
                except Exception:
                    statuses.append(0)
            elapsed = time.monotonic() - start

            rate_limited = 429 in statuses
            has_rate_headers = False

            # Check last response for rate limit headers
            try:
                resp = await http.get(url, module="rate_limiting")
                rate_headers = ["x-ratelimit-limit", "x-ratelimit-remaining",
                                "x-rate-limit-limit", "retry-after", "ratelimit-limit"]
                for h in rate_headers:
                    if h in {k.lower() for k in resp.headers}:
                        has_rate_headers = True
                        break
            except Exception:
                pass

            if not rate_limited and not has_rate_headers:
                findings.append(Finding(
                    title=f"No Rate Limiting on Sensitive Endpoint",
                    severity=Severity.MEDIUM,
                    category="logic",
                    owasp_category="A04",
                    description=f"30 rapid requests to {url} completed in {elapsed:.1f}s "
                                "with no rate limiting (no 429 responses, no rate limit headers). "
                                "Vulnerable to brute force and abuse.",
                    remediation="Implement rate limiting. Return 429 with Retry-After header. "
                                "Use progressive delays for repeated failed attempts.",
                    endpoint=url,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:L",
                    cvss_score=5.3,
                    cwe_id="CWE-770",
                    evidence=[Evidence(
                        request_method="GET",
                        request_url=url,
                        description=f"30 requests in {elapsed:.1f}s, statuses: {set(statuses)}",
                    )],
                ))

        return findings
