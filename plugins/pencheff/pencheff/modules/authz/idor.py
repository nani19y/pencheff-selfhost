"""Insecure Direct Object Reference (IDOR) testing."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

from pencheff.config import Severity
from pencheff.core.findings import Evidence, Finding
from pencheff.core.http_client import PencheffHTTPClient
from pencheff.core.session import PentestSession
from pencheff.modules.base import BaseTestModule

ID_PATTERNS = [
    r'/(\d+)(?:/|$|\?)',           # numeric IDs in path
    r'[?&]id=(\d+)',               # id query param
    r'[?&]user_id=(\d+)',          # user_id
    r'[?&]account_id=(\d+)',       # account_id
    r'[?&]order_id=(\d+)',         # order_id
    r'/users/(\d+)',               # RESTful user ID
    r'/accounts/(\d+)',            # RESTful account
    r'/orders/(\d+)',              # RESTful order
    r'/profiles/(\d+)',            # RESTful profile
]


class IDORModule(BaseTestModule):
    name = "idor"
    category = "authz"
    owasp_categories = ["A01"]
    description = "Insecure Direct Object Reference testing"

    def get_techniques(self) -> list[str]:
        return ["numeric_id_manipulation", "uuid_enumeration", "cross_user_access"]

    async def run(
        self,
        session: PentestSession,
        http: PencheffHTTPClient,
        targets: list[str] | None = None,
        config: dict[str, Any] | None = None,
    ) -> list[Finding]:
        findings = []
        endpoints = self._get_target_endpoints(session, targets)

        for ep in self._cap_endpoints(endpoints, 30):
            url = ep["url"]

            # Find numeric IDs in the URL
            for pattern in ID_PATTERNS:
                matches = re.findall(pattern, url)
                for original_id in matches:
                    # Try adjacent IDs
                    original_int = int(original_id)
                    test_ids = [
                        str(original_int + 1),
                        str(original_int - 1),
                        str(original_int + 100),
                        "0",
                        "1",
                    ]

                    # Get baseline (authorized response)
                    try:
                        baseline = await http.get(url, module="idor")
                        if baseline.status_code not in (200, 201):
                            continue
                    except Exception:
                        continue

                    for test_id in test_ids:
                        test_url = url.replace(original_id, test_id, 1)
                        if test_url == url:
                            continue

                        try:
                            resp = await http.get(test_url, module="idor")

                            # If we get a 200 with different content, potential IDOR
                            if (resp.status_code == 200 and
                                len(resp.text) > 50 and
                                resp.text != baseline.text):
                                findings.append(Finding(
                                    title=f"Potential IDOR: Accessed Object ID {test_id}",
                                    severity=Severity.HIGH,
                                    category="authz",
                                    owasp_category="A01",
                                    description=f"Changing object ID from {original_id} to {test_id} "
                                                f"returned a valid response with different data. "
                                                "This may allow accessing other users' data.",
                                    remediation="Implement proper authorization checks. Verify that the "
                                                "authenticated user owns or has permission to access the requested resource.",
                                    endpoint=test_url,
                                    parameter=f"id={test_id}",
                                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
                                    cvss_score=6.5,
                                    cwe_id="CWE-639",
                                    evidence=[Evidence(
                                        request_method="GET",
                                        request_url=test_url,
                                        response_status=resp.status_code,
                                        response_body_snippet=resp.text[:200],
                                        description=f"Original ID {original_id} → test ID {test_id}: "
                                                    f"200 OK with {len(resp.text)} bytes",
                                    )],
                                ))
                                break  # one finding per endpoint
                        except Exception:
                            continue

        # Cross-user testing if multiple credential sets available
        cred_sets = session.credentials.get_all()
        if len(cred_sets) >= 2:
            cred_names = list(cred_sets.keys())
            # Get endpoints accessible by user A
            http_a = PencheffHTTPClient(session, credential_set=cred_names[0])
            http_b = PencheffHTTPClient(session, credential_set=cred_names[1])

            try:
                for ep in self._cap_endpoints(endpoints, 10):
                    url = ep["url"]
                    try:
                        resp_a = await http_a.get(url, module="idor")
                        if resp_a.status_code != 200:
                            continue

                        resp_b = await http_b.get(url, module="idor")
                        if resp_b.status_code == 200 and resp_b.text == resp_a.text:
                            findings.append(Finding(
                                title="Cross-User Data Access (IDOR)",
                                severity=Severity.HIGH,
                                category="authz",
                                owasp_category="A01",
                                description=f"User B can access User A's resource at {url}. "
                                            "Identical response suggests missing authorization.",
                                remediation="Implement per-resource ownership checks.",
                                endpoint=url,
                                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N",
                                cvss_score=7.1,
                                cwe_id="CWE-639",
                            ))
                    except Exception:
                        continue
            finally:
                await http_a.close()
                await http_b.close()

        return findings
