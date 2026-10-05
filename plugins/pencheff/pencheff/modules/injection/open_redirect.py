"""Open redirect detection module."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlencode

from pencheff.config import Severity
from pencheff.core.findings import Evidence, Finding
from pencheff.core.http_client import PencheffHTTPClient
from pencheff.core.payload_loader import load_payloads
from pencheff.core.session import PentestSession
from pencheff.modules.base import BaseTestModule
from pencheff.modules.injection import param_names

REDIRECT_PARAMS = [
    "redirect", "url", "next", "return", "returnTo", "redirect_uri",
    "continue", "dest", "destination", "go", "out", "rurl", "target",
    "view", "redir", "redirect_url", "return_url", "checkout_url",
    "image_url", "goto", "return_path", "returnUrl", "path",
    "redirect_to", "login_url", "callback",
]

REDIRECT_PAYLOADS = [
    "https://attacker.example.com",
    "//attacker.example.com",
    "https://attacker.example.com@legitimate.com",
    "/\\attacker.example.com",
    "///attacker.example.com",
    "https:attacker.example.com",
    "\\\\attacker.example.com",
    "https://legitimate.com.attacker.example.com",
    "%0d%0aLocation:%20https://attacker.example.com",
    "https://attacker.example.com%23.legitimate.com",
    "https://attacker.example.com%00.legitimate.com",
    "//attacker.example.com/%2f..",
]


class OpenRedirectModule(BaseTestModule):
    """Detect open redirect vulnerabilities."""

    name = "open_redirect"
    category = "open_redirect"
    owasp_categories = ["A01"]
    description = "Open redirect detection with bypass techniques"

    def get_techniques(self) -> list[str]:
        return ["redirect_param_injection", "bypass_techniques", "chaining_detection"]

    async def run(
        self,
        session: PentestSession,
        http: PencheffHTTPClient,
        targets: list[str] | None = None,
        config: dict[str, Any] | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []
        endpoints = self._get_target_endpoints(session, targets)
        extra_payloads = load_payloads("open_redirect.txt")
        all_payloads = REDIRECT_PAYLOADS + [p for p in extra_payloads if p not in REDIRECT_PAYLOADS]
        base_host = session.target.base_url.split("//")[1].split("/")[0] if "//" in session.target.base_url else ""

        for ep in self._cap_endpoints(endpoints, 20):
            url = ep["url"]
            params = param_names(ep.get("params", []))

            # Test known redirect parameters
            test_params = [p for p in params if p.lower() in REDIRECT_PARAMS]
            if not test_params:
                test_params = REDIRECT_PARAMS[:8]

            for param_name in test_params:
                for payload in all_payloads[:8]:
                    # Replace legitimate.com with actual host
                    test_payload = payload.replace("legitimate.com", base_host)

                    try:
                        resp = await http.request(
                            "GET", url,
                            params={param_name: test_payload},
                            follow_redirects=False,
                            module="open_redirect",
                        )

                        # Check for redirect to attacker domain
                        location = resp.headers.get("location", "")
                        if resp.status_code in (301, 302, 303, 307, 308):
                            if "attacker.example.com" in location:
                                findings.append(Finding(
                                    title=f"Open Redirect: {url} [{param_name}]",
                                    severity=Severity.MEDIUM,
                                    category="open_redirect",
                                    owasp_category="A01",
                                    description=(
                                        f"Open redirect via parameter '{param_name}'. The server "
                                        f"redirects to attacker-controlled URL: '{location[:100]}'. "
                                        f"This can be chained with OAuth redirect_uri bypass for "
                                        f"token theft, or used for phishing attacks."
                                    ),
                                    remediation=(
                                        "Validate redirect targets against a whitelist of allowed domains. "
                                        "Use relative URLs for redirects. Never redirect to user-supplied URLs "
                                        "without validation."
                                    ),
                                    endpoint=url,
                                    parameter=param_name,
                                    evidence=[Evidence(
                                        request_method="GET",
                                        request_url=f"{url}?{param_name}={test_payload}",
                                        response_status=resp.status_code,
                                        response_headers={"Location": location},
                                        description=f"Redirected to attacker URL via payload: {test_payload[:60]}",
                                    )],
                                    cwe_id="CWE-601",
                                    cvss_score=6.1,
                                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                                ))
                                break  # Found for this param, move to next
                    except Exception:
                        continue

        return findings
