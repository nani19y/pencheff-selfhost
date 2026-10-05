"""Race condition testing via concurrent requests."""

from __future__ import annotations

import asyncio
from typing import Any

from pencheff.config import Severity
from pencheff.core.findings import Evidence, Finding
from pencheff.core.http_client import PencheffHTTPClient
from pencheff.core.session import PentestSession
from pencheff.modules.base import BaseTestModule


class RaceConditionModule(BaseTestModule):
    name = "race_condition"
    category = "logic"
    owasp_categories = ["A04"]
    description = "Race condition testing via concurrent requests"

    def get_techniques(self) -> list[str]:
        return ["concurrent_requests", "double_spending"]

    async def run(
        self,
        session: PentestSession,
        http: PencheffHTTPClient,
        targets: list[str] | None = None,
        config: dict[str, Any] | None = None,
    ) -> list[Finding]:
        findings = []
        endpoints = self._get_target_endpoints(session, targets)

        # Focus on state-changing endpoints
        state_changing = [
            ep for ep in endpoints
            if ep.get("method", "GET") in ("POST", "PUT", "PATCH")
            and any(kw in ep["url"].lower() for kw in [
                "transfer", "payment", "coupon", "redeem", "vote",
                "like", "follow", "apply", "submit", "create", "order",
            ])
        ]

        for ep in state_changing[:5]:
            url = ep["url"]
            params = ep.get("params", [])
            body = {p: "test" for p in params}

            # Send 10 concurrent identical requests
            async def send_one():
                try:
                    return await http.post(
                        url, json_data=body, module="race_condition",
                    )
                except Exception:
                    return None

            results = await asyncio.gather(*[send_one() for _ in range(10)])
            valid_results = [r for r in results if r is not None]

            if not valid_results:
                continue

            # Check for inconsistent responses (some succeed, some fail differently)
            success_count = sum(1 for r in valid_results if r.status_code in (200, 201))
            status_set = set(r.status_code for r in valid_results)

            if success_count > 1 and len(status_set) > 1:
                findings.append(Finding(
                    title="Potential Race Condition",
                    severity=Severity.MEDIUM,
                    category="logic",
                    owasp_category="A04",
                    description=f"10 concurrent requests to {url} produced mixed results: "
                                f"{success_count} successes, statuses: {status_set}. "
                                "May indicate a TOCTOU race condition allowing double-spending or duplicate actions.",
                    remediation="Use database-level locks, optimistic concurrency control, or idempotency keys "
                                "for state-changing operations.",
                    endpoint=url,
                    cvss_vector="CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:N",
                    cvss_score=5.3,
                    cwe_id="CWE-362",
                    evidence=[Evidence(
                        request_method="POST",
                        request_url=url,
                        description=f"10 concurrent requests: {success_count} successes, statuses: {status_set}",
                    )],
                ))

        return findings
