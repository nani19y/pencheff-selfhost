"""Mass assignment / object injection module."""

from __future__ import annotations

import json
from typing import Any

from pencheff.config import Severity
from pencheff.core.findings import Evidence, Finding
from pencheff.core.http_client import PencheffHTTPClient
from pencheff.core.session import PentestSession
from pencheff.modules.base import BaseTestModule

# Privileged properties to inject
PRIVILEGE_PROPERTIES = [
    {"role": "admin"},
    {"admin": True},
    {"is_admin": True},
    {"isAdmin": True},
    {"is_staff": True},
    {"is_superuser": True},
    {"permissions": ["admin", "write", "delete"]},
    {"privilege": "administrator"},
    {"user_type": "admin"},
    {"account_type": "premium"},
    {"verified": True},
    {"email_verified": True},
    {"active": True},
    {"approved": True},
    {"balance": 999999},
    {"price": 0},
    {"discount": 100},
    {"role_id": 1},
    {"group_id": 1},
]

# Framework-specific dangerous properties
FRAMEWORK_PROPERTIES = {
    "rails": [{"_destroy": True}, {"type": "Admin"}],
    "django": [{"is_staff": True}, {"is_superuser": True}, {"is_active": True}],
    "nodejs": [{"__proto__": {"admin": True}}, {"constructor": {"prototype": {"admin": True}}}],
    "laravel": [{"is_admin": 1}, {"role": "admin"}, {"guard_name": "admin"}],
}


class MassAssignmentModule(BaseTestModule):
    """Detect mass assignment / object injection vulnerabilities."""

    name = "mass_assignment"
    category = "mass_assignment"
    owasp_categories = ["A01"]
    description = "Mass assignment: privilege escalation via unprotected object properties"

    def get_techniques(self) -> list[str]:
        return [
            "privilege_property_injection",
            "framework_specific_injection",
            "registration_abuse",
            "profile_update_abuse",
        ]

    async def run(
        self,
        session: PentestSession,
        http: PencheffHTTPClient,
        targets: list[str] | None = None,
        config: dict[str, Any] | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []
        endpoints = self._get_target_endpoints(session, targets)

        # Focus on write endpoints (POST, PUT, PATCH)
        write_endpoints = [
            ep for ep in endpoints
            if ep.get("method", "GET") in ("POST", "PUT", "PATCH")
        ]

        for ep in self._cap_endpoints(write_endpoints, 15):
            url = ep["url"]
            method = ep.get("method", "POST")

            # Determine if this is a registration, profile, or update endpoint
            url_lower = url.lower()
            is_registration = any(kw in url_lower for kw in ["register", "signup", "sign-up", "create"])
            is_profile = any(kw in url_lower for kw in ["profile", "account", "settings", "user"])
            is_api = any(kw in url_lower for kw in ["/api/", "/v1/", "/v2/"])

            if not (is_registration or is_profile or is_api):
                continue

            # Test generic privilege properties
            ep_findings = await self._test_properties(
                http, url, method, PRIVILEGE_PROPERTIES, session
            )
            findings.extend(ep_findings)

            # Test framework-specific properties based on tech stack
            tech_stack = session.discovered.tech_stack
            frameworks = set()
            for category, techs in tech_stack.items():
                for tech in techs:
                    tech_lower = tech.lower()
                    if "rails" in tech_lower or "ruby" in tech_lower:
                        frameworks.add("rails")
                    if "django" in tech_lower or "python" in tech_lower:
                        frameworks.add("django")
                    if "node" in tech_lower or "express" in tech_lower:
                        frameworks.add("nodejs")
                    if "laravel" in tech_lower or "php" in tech_lower:
                        frameworks.add("laravel")

            for framework in frameworks:
                fw_props = FRAMEWORK_PROPERTIES.get(framework, [])
                fw_findings = await self._test_properties(
                    http, url, method, fw_props, session, framework
                )
                findings.extend(fw_findings)

        return findings

    async def _test_properties(
        self, http: PencheffHTTPClient,
        url: str, method: str,
        properties: list[dict],
        session: PentestSession,
        framework: str | None = None,
    ) -> list[Finding]:
        """Test injecting extra properties into request bodies."""
        findings: list[Finding] = []

        # First, get a baseline with a normal request
        try:
            baseline = await http.request(
                method, url,
                json_data={"test_field": "test_value"},
                module="mass_assignment",
            )
            baseline_status = baseline.status_code
        except Exception:
            return findings

        for prop in properties[:10]:
            # Merge the privilege property with a normal-looking payload
            payload = {"name": "testuser", "email": "test@example.com"}
            payload.update(prop)

            try:
                resp = await http.request(
                    method, url,
                    json_data=payload,
                    module="mass_assignment",
                )

                # Detect if the property was accepted
                if resp.status_code in (200, 201):
                    try:
                        resp_json = resp.json()
                        if isinstance(resp_json, dict):
                            # Check if our injected property is in the response
                            for key, value in prop.items():
                                if key in resp_json and resp_json[key] == value:
                                    prop_desc = f"{key}={value}"
                                    framework_note = f" ({framework}-specific)" if framework else ""
                                    findings.append(Finding(
                                        title=f"Mass Assignment{framework_note}: {url} [{key}]",
                                        severity=Severity.HIGH,
                                        category="mass_assignment",
                                        owasp_category="A01",
                                        description=(
                                            f"The endpoint accepted and stored the privileged property "
                                            f"'{prop_desc}' that was injected into the request body. "
                                            f"This allows attackers to escalate privileges, modify "
                                            f"pricing, or bypass access controls."
                                        ),
                                        remediation=(
                                            f"Use an allowlist of permitted properties for mass assignment. "
                                            f"Never bind request parameters directly to model attributes. "
                                            f"Use DTOs or strong parameter filtering."
                                        ),
                                        endpoint=url,
                                        parameter=key,
                                        evidence=[Evidence(
                                            request_method=method,
                                            request_url=url,
                                            request_body=json.dumps(payload),
                                            response_status=resp.status_code,
                                            response_body_snippet=resp.text[:300],
                                            description=f"Property '{prop_desc}' accepted and reflected in response",
                                        )],
                                        cwe_id="CWE-915",
                                        cvss_score=8.1,
                                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
                                    ))
                                    return findings  # One finding per endpoint is enough
                    except Exception:
                        pass
            except Exception:
                continue

        return findings
