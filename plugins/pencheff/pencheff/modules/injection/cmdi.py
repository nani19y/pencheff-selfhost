"""OS command injection testing."""

from __future__ import annotations

import re
from typing import Any

from pencheff.config import Severity
from pencheff.core.findings import Evidence, Finding
from pencheff.core.http_client import PencheffHTTPClient
from pencheff.core.session import PentestSession
from pencheff.modules.injection import param_names
from pencheff.modules.base import BaseTestModule

# Payloads that produce detectable output without causing harm
CMDI_PAYLOADS = [
    # Concatenation operators
    ("; echo pencheff_cmdi_test", "pencheff_cmdi_test"),
    ("| echo pencheff_cmdi_test", "pencheff_cmdi_test"),
    ("|| echo pencheff_cmdi_test", "pencheff_cmdi_test"),
    ("& echo pencheff_cmdi_test", "pencheff_cmdi_test"),
    ("&& echo pencheff_cmdi_test", "pencheff_cmdi_test"),
    ("`echo pencheff_cmdi_test`", "pencheff_cmdi_test"),
    ("$(echo pencheff_cmdi_test)", "pencheff_cmdi_test"),
    # Newline injection
    ("%0aecho pencheff_cmdi_test", "pencheff_cmdi_test"),
    # Windows variants
    ("& echo pencheff_cmdi_test &", "pencheff_cmdi_test"),
    ("| type nul && echo pencheff_cmdi_test", "pencheff_cmdi_test"),
]

# Time-based payloads
TIME_PAYLOADS = [
    ("; sleep 3", 3),
    ("| sleep 3", 3),
    ("|| sleep 3", 3),
    ("$(sleep 3)", 3),
    ("`sleep 3`", 3),
    ("; ping -c 3 127.0.0.1", 3),
]


class CommandInjectionModule(BaseTestModule):
    name = "cmdi"
    category = "injection"
    owasp_categories = ["A03"]
    description = "OS command injection testing"

    def get_techniques(self) -> list[str]:
        return ["output_based", "time_based", "blind"]

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
                # Output-based detection
                finding = await self._test_output_based(http, url, param, method)
                if finding:
                    findings.append(finding)
                    continue

                # Time-based detection
                finding = await self._test_time_based(http, url, param, method)
                if finding:
                    findings.append(finding)

        return findings

    async def _inject(self, http, url, param, payload, method):
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
        parsed = urlparse(url)
        qs = parse_qs(parsed.query, keep_blank_values=True)

        if method == "GET":
            qs[param] = [payload]
            test_url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))
            return await http.get(test_url, module="cmdi")
        else:
            body_params = {p: qs.get(p, ["test"])[0] for p in qs}
            body_params[param] = payload
            return await http.post(
                urlunparse(parsed._replace(query="")),
                body=urlencode(body_params),
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                module="cmdi",
            )

    async def _test_output_based(self, http, url, param, method) -> Finding | None:
        for payload, marker in CMDI_PAYLOADS:
            try:
                resp = await self._inject(http, url, param, payload, method)
                if marker in resp.text:
                    return Finding(
                        title="OS Command Injection",
                        severity=Severity.CRITICAL,
                        category="injection",
                        owasp_category="A03",
                        description=f"Command injection in parameter '{param}'. "
                                    f"Payload '{payload}' produced marker '{marker}' in response.",
                        remediation="Never pass user input to system commands. Use language-native APIs instead. "
                                    "If unavoidable, use strict allowlisting and escaping.",
                        endpoint=url,
                        parameter=param,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        cvss_score=9.8,
                        cwe_id="CWE-78",
                        evidence=[Evidence(
                            request_method=method,
                            request_url=url,
                            request_body=f"{param}={payload}",
                            response_body_snippet=resp.text[:300],
                            description=f"Marker '{marker}' found in response",
                        )],
                    )
            except Exception:
                continue
        return None

    async def _test_time_based(self, http, url, param, method) -> Finding | None:
        import time
        # Baseline
        try:
            start = time.monotonic()
            await self._inject(http, url, param, "test", method)
            baseline = time.monotonic() - start
        except Exception:
            return None

        for payload, delay in TIME_PAYLOADS[:3]:
            try:
                start = time.monotonic()
                await self._inject(http, url, param, payload, method)
                elapsed = time.monotonic() - start

                if elapsed - baseline > delay * 0.8:
                    return Finding(
                        title="OS Command Injection (Time-Based)",
                        severity=Severity.CRITICAL,
                        category="injection",
                        owasp_category="A03",
                        description=f"Time-based command injection in parameter '{param}'. "
                                    f"Payload '{payload}' caused {elapsed:.1f}s delay vs {baseline:.1f}s baseline.",
                        remediation="Never pass user input to system commands.",
                        endpoint=url,
                        parameter=param,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        cvss_score=9.8,
                        cwe_id="CWE-78",
                        evidence=[Evidence(
                            request_method=method,
                            request_url=url,
                            request_body=f"{param}={payload}",
                            description=f"Time delay: {elapsed:.1f}s vs baseline {baseline:.1f}s",
                        )],
                    )
            except Exception:
                continue
        return None
