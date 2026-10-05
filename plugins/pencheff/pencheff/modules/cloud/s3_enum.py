"""S3 bucket enumeration and permission testing."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

from pencheff.config import Severity
from pencheff.core.findings import Evidence, Finding
from pencheff.core.http_client import PencheffHTTPClient
from pencheff.core.session import PentestSession
from pencheff.modules.base import BaseTestModule


class S3EnumModule(BaseTestModule):
    name = "s3_enum"
    category = "cloud"
    owasp_categories = ["A05"]
    description = "S3 bucket enumeration and permission testing"

    def get_techniques(self) -> list[str]:
        return ["bucket_discovery", "permission_check", "listing_check"]

    async def run(
        self,
        session: PentestSession,
        http: PencheffHTTPClient,
        targets: list[str] | None = None,
        config: dict[str, Any] | None = None,
    ) -> list[Finding]:
        findings = []
        base_url = session.target.base_url
        domain = urlparse(base_url).hostname

        # Look for S3 references in discovered content. Track bucket
        # provenance: candidates derived from the company-name prefix
        # are likely owned by the target organisation; those scraped
        # from response bodies may belong to anyone the page links to
        # (third-party widgets, OSS demos, social embeds, …) and AWS
        # bucket names are globally unique, so misattributing a
        # foreign bucket to the target produces a confidently-wrong
        # HIGH finding.
        prefix_buckets: set[str] = set()
        body_scrape_buckets: set[str] = set()
        domain_parts = domain.split(".")
        company_name = domain_parts[0] if domain_parts else domain

        # Common bucket naming patterns
        suffixes = ["", "-assets", "-static", "-media", "-uploads", "-backup",
                     "-data", "-logs", "-dev", "-staging", "-prod", "-public"]
        for suffix in suffixes:
            prefix_buckets.add(f"{company_name}{suffix}")

        # Also scan response bodies for S3 URLs
        try:
            resp = await http.get(base_url, module="s3_enum")
            s3_patterns = [
                r'https?://([a-zA-Z0-9.-]+)\.s3[.-]',
                r's3://([a-zA-Z0-9.-]+)',
                r'https?://s3[.-][a-zA-Z0-9-]+\.amazonaws\.com/([a-zA-Z0-9.-]+)',
            ]
            for pattern in s3_patterns:
                for match in re.findall(pattern, resp.text):
                    if match not in prefix_buckets:
                        body_scrape_buckets.add(match)
        except Exception:
            pass

        # Cap each list separately so a noisy page can't squeeze the
        # higher-confidence prefix candidates out of the test budget.
        candidates: list[tuple[str, str]] = (
            [(b, "prefix") for b in list(prefix_buckets)[:20]] +
            [(b, "body") for b in list(body_scrape_buckets)[:20]]
        )

        # Test each bucket
        for bucket, source in candidates:
            try:
                list_resp = await http.get(
                    f"https://{bucket}.s3.amazonaws.com/",
                    module="s3_enum",
                    inject_creds=False,
                )
                if list_resp.status_code == 200 and "<ListBucketResult" in list_resp.text:
                    if source == "prefix":
                        # Bucket name follows the target's company-prefix
                        # pattern — high confidence the org owns it.
                        findings.append(Finding(
                            title=f"S3 Bucket Publicly Listable: {bucket}",
                            severity=Severity.HIGH,
                            category="cloud",
                            owasp_category="A05",
                            description=(
                                f"S3 bucket '{bucket}' allows public listing. "
                                "All objects in the bucket can be enumerated by anyone."
                            ),
                            remediation="Disable public listing. Update bucket policy to deny s3:ListBucket for public.",
                            endpoint=f"https://{bucket}.s3.amazonaws.com/",
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                            cvss_score=7.5,
                            cwe_id="CWE-284",
                            evidence=[Evidence(
                                request_method="GET",
                                request_url=f"https://{bucket}.s3.amazonaws.com/",
                                response_status=list_resp.status_code,
                                response_body_snippet=list_resp.text[:300],
                                description="Bucket listing returned ListBucketResult XML",
                            )],
                        ))
                    else:
                        # Bucket name was scraped out of the page body.
                        # AWS bucket names are globally unique, so we
                        # cannot assume the target owns it — the page
                        # may simply reference a third-party bucket.
                        # Emit at INFO so it surfaces for review without
                        # implying the target is responsible.
                        findings.append(Finding(
                            title=f"Third-party Publicly Listable S3 Bucket Referenced: {bucket}",
                            severity=Severity.INFO,
                            category="info_disclosure",
                            owasp_category="A05",
                            description=(
                                f"A page on the target referenced the S3 bucket "
                                f"'{bucket}', which is publicly listable. The bucket "
                                "name does not match the target's company-name prefix, "
                                "so it most likely belongs to a third party (CDN, "
                                "embedded widget, OSS demo, social embed, …). Verify "
                                "ownership before treating this as actionable; if it "
                                "is yours, lock it down — if it isn't, consider "
                                "removing the reference to avoid linking your users "
                                "into someone else's misconfigured storage."
                            ),
                            remediation=(
                                "Verify whether your organisation owns this bucket. "
                                "If yes, disable public listing. If no, remove the "
                                "reference from your pages."
                            ),
                            endpoint=f"https://{bucket}.s3.amazonaws.com/",
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                            cvss_score=5.3,
                            cwe_id="CWE-284",
                            evidence=[Evidence(
                                request_method="GET",
                                request_url=f"https://{bucket}.s3.amazonaws.com/",
                                response_status=list_resp.status_code,
                                response_body_snippet=list_resp.text[:300],
                                description="Bucket name discovered in response body; ownership not verified.",
                            )],
                        ))
                elif list_resp.status_code == 403:
                    # Bucket exists but not listable — try reading a common file
                    pass
            except Exception:
                continue

        return findings
