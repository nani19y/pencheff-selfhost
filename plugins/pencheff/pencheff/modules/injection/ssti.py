"""Server-Side Template Injection (SSTI) testing."""

from __future__ import annotations

from typing import Any

from pencheff.config import Severity
from pencheff.core.findings import Evidence, Finding
from pencheff.core.http_client import PencheffHTTPClient
from pencheff.core.session import PentestSession
from pencheff.modules.injection import param_names
from pencheff.modules.base import BaseTestModule

# Polyglot probes and expected outputs
SSTI_PROBES = [
    ("{{7*7}}", "49", "Jinja2/Twig"),
    ("${7*7}", "49", "Freemarker/Velocity/Mako"),
    ("#{7*7}", "49", "Ruby ERB/Java EL"),
    ("<%= 7*7 %>", "49", "ERB/EJS"),
    ("{{7*'7'}}", "7777777", "Jinja2 (string multiplication)"),
    ("${7*7}", "49", "Spring EL"),
    ("@(1+2)", "3", "Razor"),
    ("[[${7*7}]]", "49", "Thymeleaf"),
]


class SSTIModule(BaseTestModule):
    name = "ssti"
    category = "injection"
    owasp_categories = ["A03"]
    description = "Server-Side Template Injection testing"

    def get_techniques(self) -> list[str]:
        return ["polyglot_probe", "engine_fingerprint"]

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

            for param in params:
                for payload, expected, engine in SSTI_PROBES:
                    try:
                        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
                        parsed = urlparse(url)
                        qs = parse_qs(parsed.query, keep_blank_values=True)

                        if method == "GET":
                            qs[param] = [payload]
                            test_url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))
                            resp = await http.get(test_url, module="ssti")
                        else:
                            body_params = {p: qs.get(p, [""])[0] for p in qs}
                            body_params[param] = payload
                            resp = await http.post(
                                url, body=urlencode(body_params),
                                headers={"Content-Type": "application/x-www-form-urlencoded"},
                                module="ssti",
                            )

                        if expected in resp.text and payload not in resp.text:
                            findings.append(Finding(
                                title=f"Server-Side Template Injection ({engine})",
                                severity=Severity.CRITICAL,
                                category="injection",
                                owasp_category="A03",
                                description=f"SSTI detected in parameter '{param}'. Template engine: {engine}. "
                                            f"Payload '{payload}' was evaluated to '{expected}'.",
                                remediation="Never pass user input into template expressions. "
                                            "Use sandboxed template rendering. Separate logic from templates.",
                                endpoint=url,
                                parameter=param,
                                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                cvss_score=9.8,
                                cwe_id="CWE-1336",
                                evidence=[Evidence(
                                    request_method=method,
                                    request_url=url,
                                    request_body=f"{param}={payload}",
                                    response_body_snippet=resp.text[:300],
                                    description=f"Payload evaluated: {payload} → {expected}",
                                )],
                            ))
                            break  # found for this param, move on
                    except Exception:
                        continue

        return findings
