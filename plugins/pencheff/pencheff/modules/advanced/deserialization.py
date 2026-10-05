"""Insecure deserialization detection module."""

from __future__ import annotations

import base64
import re
from typing import Any

from pencheff.config import Severity
from pencheff.core.findings import Evidence, Finding
from pencheff.core.http_client import PencheffHTTPClient
from pencheff.core.payload_loader import load_payloads
from pencheff.core.session import PentestSession
from pencheff.modules.base import BaseTestModule

# Known deserialization endpoints
JAVA_DESER_ENDPOINTS = [
    "/invoker/readonly",
    "/invoker/JMXInvokerServlet",
    "/jmx-console/",
    "/web-console/",
    "/status",
    "/seam/resource/",
]

# Magic bytes for serialized objects
SERIALIZATION_SIGNATURES = {
    "java": b"\xac\xed\x00\x05",
    "java_base64": "rO0AB",
    "php": re.compile(r'[OaCsbi]:\d+[:;{]'),
    "python_pickle": [b"\x80\x04\x95", b"\x80\x03", b"\x80\x02"],
    "dotnet_viewstate": re.compile(r'__VIEWSTATE'),
    "ruby_marshal": b"\x04\x08",
    "yaml_constructor": re.compile(r'!!python/|!!ruby/|!!java/'),
}


class DeserializationModule(BaseTestModule):
    """Detect insecure deserialization vulnerabilities across multiple frameworks."""

    name = "deserialization"
    category = "deserialization"
    owasp_categories = ["A08"]
    description = "Insecure deserialization detection (Java, Python, PHP, .NET, Ruby, YAML)"

    def get_techniques(self) -> list[str]:
        return [
            "java_deserialization",
            "python_pickle",
            "php_unserialize",
            "dotnet_viewstate",
            "yaml_deserialization",
            "serialized_object_detection",
        ]

    async def run(
        self,
        session: PentestSession,
        http: PencheffHTTPClient,
        targets: list[str] | None = None,
        config: dict[str, Any] | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []
        base_url = session.target.base_url
        endpoints = self._get_target_endpoints(session, targets)

        # Phase 1: Scan for serialized objects in responses, cookies, parameters
        scan_findings = await self._scan_for_serialized_objects(
            http, endpoints, session
        )
        findings.extend(scan_findings)

        # Phase 2: Check known Java deserialization endpoints
        java_findings = await self._check_java_endpoints(http, base_url, session)
        findings.extend(java_findings)

        # Phase 3: Test YAML deserialization
        yaml_findings = await self._test_yaml_deser(http, endpoints, session)
        findings.extend(yaml_findings)

        # Phase 4: Test ViewState (.NET)
        viewstate_findings = await self._test_viewstate(http, endpoints, session)
        findings.extend(viewstate_findings)

        return findings

    async def _scan_for_serialized_objects(
        self, http: PencheffHTTPClient,
        endpoints: list[dict[str, Any]],
        session: PentestSession,
    ) -> list[Finding]:
        """Scan responses and cookies for serialized object patterns."""
        findings: list[Finding] = []

        for ep in endpoints[:20]:
            url = ep["url"]
            try:
                resp = await http.get(url, module="deserialization")
            except Exception:
                continue

            body = resp.text
            cookies = resp.headers.get("set-cookie", "")

            # Check for Java serialized objects (base64)
            if SERIALIZATION_SIGNATURES["java_base64"] in body or SERIALIZATION_SIGNATURES["java_base64"] in cookies:
                findings.append(Finding(
                    title="Java Serialized Object Detected",
                    severity=Severity.HIGH,
                    category="deserialization",
                    owasp_category="A08",
                    description=(
                        "A Java serialized object (base64-encoded, prefix 'rO0AB') was detected "
                        "in the response or cookies. If user-controlled, this may allow Remote "
                        "Code Execution via deserialization gadget chains."
                    ),
                    remediation=(
                        "Avoid deserializing untrusted data. Use allowlists for permitted classes. "
                        "Replace Java serialization with safer formats like JSON. "
                        "Implement integrity checks (HMAC) on serialized data."
                    ),
                    endpoint=url,
                    evidence=[Evidence(
                        request_method="GET",
                        request_url=url,
                        response_status=resp.status_code,
                        response_body_snippet=body[:300],
                        description="Java serialized object signature detected",
                    )],
                    cwe_id="CWE-502",
                    cvss_score=9.8,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                ))

            # Check for PHP serialized objects
            php_pattern = SERIALIZATION_SIGNATURES["php"]
            if php_pattern.search(body) or php_pattern.search(cookies):
                findings.append(Finding(
                    title="PHP Serialized Object Detected",
                    severity=Severity.HIGH,
                    category="deserialization",
                    owasp_category="A08",
                    description=(
                        "A PHP serialized object pattern was detected in the response or cookies. "
                        "If user-controllable, this could allow object injection leading to RCE, "
                        "file manipulation, or authentication bypass via magic methods (__wakeup, __destruct)."
                    ),
                    remediation=(
                        "Use json_encode/json_decode instead of serialize/unserialize. "
                        "If serialization is required, implement integrity verification (HMAC). "
                        "Audit all classes for dangerous magic methods."
                    ),
                    endpoint=url,
                    evidence=[Evidence(
                        request_method="GET",
                        request_url=url,
                        response_status=resp.status_code,
                        description="PHP serialized object pattern detected",
                    )],
                    cwe_id="CWE-502",
                    cvss_score=8.1,
                    cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
                ))

            # Check cookies for base64-encoded serialized data
            for cookie_header in resp.headers.get_list("set-cookie") if hasattr(resp.headers, "get_list") else [cookies]:
                cookie_value = cookie_header.split("=", 1)[-1].split(";")[0] if "=" in cookie_header else ""
                if cookie_value:
                    try:
                        decoded = base64.b64decode(cookie_value)
                        if decoded[:4] == SERIALIZATION_SIGNATURES["java"]:
                            findings.append(Finding(
                                title="Java Serialized Object in Cookie",
                                severity=Severity.CRITICAL,
                                category="deserialization",
                                owasp_category="A08",
                                description="A Java serialized object was found in a cookie. User-controlled cookies with serialized data are a direct RCE vector.",
                                remediation="Never deserialize user-controlled cookies. Use signed, encrypted session tokens instead.",
                                endpoint=url,
                                cwe_id="CWE-502",
                                cvss_score=9.8,
                                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                            ))
                    except Exception:
                        pass

        return findings

    async def _check_java_endpoints(
        self, http: PencheffHTTPClient, base_url: str, session: PentestSession,
    ) -> list[Finding]:
        """Check for known Java deserialization endpoints."""
        findings: list[Finding] = []

        from pencheff.core.spa_detector import is_real_endpoint

        for endpoint in JAVA_DESER_ENDPOINTS:
            url = f"{base_url}{endpoint}"
            try:
                resp = await http.get(url, module="deserialization")
                if resp.status_code not in (200, 301, 302, 500):
                    continue
                # Suppress SPA-fallback hits: a SPA serves index.html with
                # 200 for any unknown path and would otherwise fire one of
                # these CRITICAL/HIGH findings per probed endpoint.
                if not is_real_endpoint(resp, session):
                    continue
                findings.append(Finding(
                    title=f"Java Deserialization Endpoint Accessible: {endpoint}",
                    severity=Severity.HIGH,
                    category="deserialization",
                    owasp_category="A08",
                    description=(
                        f"The Java deserialization endpoint {endpoint} is accessible "
                        f"(HTTP {resp.status_code}). These endpoints are commonly exploited "
                        f"with tools like ysoserial for Remote Code Execution."
                    ),
                    remediation=(
                        f"Restrict access to {endpoint}. Remove or disable the JMX/invoker "
                        "servlet if not needed. Apply deserialization filters."
                    ),
                    endpoint=url,
                    evidence=[Evidence(
                        request_method="GET",
                        request_url=url,
                        response_status=resp.status_code,
                        response_body_snippet=resp.text[:200],
                        description=f"Endpoint returned HTTP {resp.status_code}",
                    )],
                    cwe_id="CWE-502",
                    cvss_score=9.8,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                ))
            except Exception:
                continue

        return findings

    async def _test_yaml_deser(
        self, http: PencheffHTTPClient,
        endpoints: list[dict[str, Any]],
        session: PentestSession,
    ) -> list[Finding]:
        """Test for YAML deserialization vulnerabilities."""
        findings: list[Finding] = []
        yaml_payloads = load_payloads("deserialization.txt")
        yaml_specific = [p for p in yaml_payloads if "!!" in p] if yaml_payloads else [
            "!!python/object/apply:time.sleep [3]",
            "!!python/object/new:subprocess.check_output [['id']]",
            '!!ruby/object:Gem::Installer\ni: x',
        ]

        for ep in endpoints[:10]:
            url = ep["url"]
            method = ep.get("method", "POST")
            if method not in ("POST", "PUT", "PATCH"):
                continue

            for payload in yaml_specific[:5]:
                try:
                    resp = await http.request(
                        method, url,
                        headers={"Content-Type": "application/x-yaml"},
                        body=payload,
                        module="deserialization",
                    )
                    if resp.status_code == 500 or "error" in resp.text.lower():
                        findings.append(Finding(
                            title="YAML Deserialization Endpoint Detected",
                            severity=Severity.HIGH,
                            category="deserialization",
                            owasp_category="A08",
                            description=(
                                "The endpoint processes YAML input and may be vulnerable to "
                                "constructor injection attacks. YAML deserialization can lead "
                                "to Remote Code Execution in Python (PyYAML), Ruby, and Java."
                            ),
                            remediation="Use yaml.safe_load() instead of yaml.load(). Disable YAML constructors.",
                            endpoint=url,
                            evidence=[Evidence(
                                request_method=method,
                                request_url=url,
                                request_body=payload,
                                response_status=resp.status_code,
                                response_body_snippet=resp.text[:300],
                                description="YAML payload triggered server error",
                            )],
                            cwe_id="CWE-502",
                            cvss_score=9.8,
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        ))
                        break
                except Exception:
                    continue

        return findings

    async def _test_viewstate(
        self, http: PencheffHTTPClient,
        endpoints: list[dict[str, Any]],
        session: PentestSession,
    ) -> list[Finding]:
        """Check for .NET ViewState deserialization issues."""
        findings: list[Finding] = []

        for ep in endpoints[:15]:
            url = ep["url"]
            try:
                resp = await http.get(url, module="deserialization")
            except Exception:
                continue

            if "__VIEWSTATE" in resp.text:
                # Check if ViewState MAC is disabled
                if '__VIEWSTATEGENERATOR' in resp.text and '__EVENTVALIDATION' not in resp.text:
                    findings.append(Finding(
                        title=".NET ViewState Without Event Validation",
                        severity=Severity.HIGH,
                        category="deserialization",
                        owasp_category="A08",
                        description=(
                            "The page uses ASP.NET ViewState without Event Validation. "
                            "If ViewState MAC validation is also disabled, this allows "
                            "deserialization attacks leading to Remote Code Execution."
                        ),
                        remediation="Enable ViewState MAC validation and Event Validation in web.config.",
                        endpoint=url,
                        evidence=[Evidence(
                            request_method="GET",
                            request_url=url,
                            response_status=resp.status_code,
                            description="ViewState found without Event Validation",
                        )],
                        cwe_id="CWE-502",
                        cvss_score=8.1,
                        cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    ))

        return findings
