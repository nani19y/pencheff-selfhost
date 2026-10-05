"""Multi-step workflow bypass testing."""

from __future__ import annotations

from typing import Any

from pencheff.config import Severity
from pencheff.core.findings import Evidence, Finding
from pencheff.core.http_client import PencheffHTTPClient
from pencheff.core.session import PentestSession
from pencheff.modules.base import BaseTestModule


class WorkflowBypassModule(BaseTestModule):
    name = "workflow_bypass"
    category = "logic"
    owasp_categories = ["A04"]
    description = "Multi-step workflow bypass testing"

    def get_techniques(self) -> list[str]:
        return ["step_skipping", "parameter_manipulation"]

    async def run(
        self,
        session: PentestSession,
        http: PencheffHTTPClient,
        targets: list[str] | None = None,
        config: dict[str, Any] | None = None,
    ) -> list[Finding]:
        findings = []
        endpoints = self._get_target_endpoints(session, targets)

        # Look for multi-step processes (step/page/phase in URL or params)
        step_endpoints = []
        for ep in endpoints:
            url_lower = ep["url"].lower()
            params_lower = [p.lower() for p in ep.get("params", [])]
            if any(kw in url_lower or kw in " ".join(params_lower) for kw in [
                "step", "page", "phase", "stage", "wizard", "checkout",
                "confirm", "verify", "complete", "finalize",
            ]):
                step_endpoints.append(ep)

        # Try accessing final step directly
        final_keywords = ["confirm", "complete", "finalize", "finish", "submit", "checkout/complete"]
        for ep in step_endpoints[:10]:
            url = ep["url"]
            # Check if this looks like a final step
            if any(kw in url.lower() for kw in final_keywords):
                try:
                    resp = await http.get(url, module="workflow_bypass")
                    if resp.status_code == 200 and len(resp.text) > 100:
                        findings.append(Finding(
                            title="Workflow Step Bypass",
                            severity=Severity.MEDIUM,
                            category="logic",
                            owasp_category="A04",
                            description=f"Final workflow step at {url} is accessible directly "
                                        "without completing prior steps. May allow skipping validation.",
                            remediation="Enforce server-side state tracking for multi-step workflows. "
                                        "Verify each step was completed before allowing the next.",
                            endpoint=url,
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N",
                            cvss_score=4.3,
                            cwe_id="CWE-841",
                            evidence=[Evidence(
                                request_method="GET",
                                request_url=url,
                                response_status=resp.status_code,
                                description="Final step accessible without completing prior steps",
                            )],
                        ))
                except Exception:
                    continue

        # Test parameter manipulation (price, quantity, discount)
        manipulate_params = {
            "price": ["0", "0.01", "-1"],
            "amount": ["0", "-100", "999999"],
            "quantity": ["0", "-1", "999999"],
            "discount": ["100", "999", "-1"],
            "total": ["0", "0.01"],
        }

        for ep in endpoints[:20]:
            for param in ep.get("params", []):
                if param.lower() in manipulate_params:
                    for value in manipulate_params[param.lower()]:
                        try:
                            resp = await http.post(
                                ep["url"],
                                json_data={param: value},
                                module="workflow_bypass",
                            )
                            if resp.status_code in (200, 201):
                                findings.append(Finding(
                                    title=f"Parameter Manipulation Accepted: {param}={value}",
                                    severity=Severity.HIGH,
                                    category="logic",
                                    owasp_category="A04",
                                    description=f"Server accepted manipulated value '{value}' for parameter '{param}'. "
                                                "May allow price tampering, negative quantities, or similar abuse.",
                                    remediation="Validate business logic server-side. Never trust client-supplied "
                                                "pricing, quantities, or discounts.",
                                    endpoint=ep["url"],
                                    parameter=param,
                                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N",
                                    cvss_score=6.5,
                                    cwe_id="CWE-472",
                                ))
                                break
                        except Exception:
                            continue

        return findings
