"""REST API discovery — OpenAPI/Swagger spec detection, route enumeration."""

from __future__ import annotations

import json
from typing import Any

from pencheff.config import Severity
from pencheff.core.findings import Finding
from pencheff.core.http_client import PencheffHTTPClient
from pencheff.core.session import PentestSession
from pencheff.modules.base import BaseTestModule

SPEC_PATHS = [
    "/swagger.json", "/swagger/v1/swagger.json", "/api-docs",
    "/openapi.json", "/openapi.yaml", "/v1/api-docs", "/v2/api-docs",
    "/v3/api-docs", "/api/swagger.json", "/api/openapi.json",
    "/docs", "/redoc", "/_catalog", "/api/v1/swagger.json",
    "/swagger-ui.html", "/swagger-ui/", "/graphql", "/graphiql",
]


class RestDiscoveryModule(BaseTestModule):
    name = "rest_discovery"
    category = "recon"
    owasp_categories = ["A05"]
    description = "REST API endpoint and spec discovery"

    def get_techniques(self) -> list[str]:
        return ["swagger_detection", "openapi_parsing", "graphql_detection"]

    async def run(
        self,
        session: PentestSession,
        http: PencheffHTTPClient,
        targets: list[str] | None = None,
        config: dict[str, Any] | None = None,
    ) -> list[Finding]:
        findings = []
        base_url = session.target.base_url

        for path in SPEC_PATHS:
            try:
                resp = await http.get(
                    f"{base_url}{path}",
                    module="rest_discovery",
                    inject_creds=False,
                )
                if resp.status_code != 200:
                    continue

                content_type = resp.headers.get("content-type", "")

                # Check for Swagger/OpenAPI
                if "json" in content_type or "yaml" in content_type or path.endswith((".json", ".yaml")):
                    try:
                        spec_raw = resp.text
                        spec = resp.json() if "json" in content_type or path.endswith(".json") else {}
                        if not spec:
                            import yaml
                            spec = yaml.safe_load(spec_raw) or {}

                        if "swagger" in spec or "openapi" in spec or "info" in spec:
                            from pencheff.core.openapi_import import parse_api_spec
                            parsed = parse_api_spec(spec_raw, base_url, hint="auto")

                            if "error" not in parsed:
                                # Full seeding via openapi_import
                                existing_urls = {ep["url"] for ep in session.discovered.endpoints}
                                new_eps = [
                                    ep for ep in parsed["endpoints"]
                                    if ep["url"] not in existing_urls
                                ]
                                session.discovered.endpoints.extend(new_eps)
                                session.discovered.api_specs.append({
                                    "type": parsed.get("spec_type", "openapi"),
                                    "url": f"{base_url}{path}",
                                    "title": parsed.get("title", ""),
                                    "version": parsed.get("version", ""),
                                    "endpoint_count": parsed["endpoint_count"],
                                })
                                ep_count = parsed["endpoint_count"]
                            else:
                                # Fallback: basic extraction
                                paths_dict = spec.get("paths", {})
                                for api_path, methods in paths_dict.items():
                                    for method, details in (methods or {}).items():
                                        if method.upper() in ("GET", "POST", "PUT", "DELETE", "PATCH"):
                                            params = [p.get("name", "") for p in details.get("parameters", [])]
                                            session.discovered.endpoints.append({
                                                "url": f"{base_url}{api_path}",
                                                "method": method.upper(),
                                                "source": "openapi_basic",
                                                "params": params,
                                            })
                                ep_count = len(spec.get("paths", {}))
                                session.discovered.api_specs.append({
                                    "type": "openapi",
                                    "url": f"{base_url}{path}",
                                    "version": spec.get("openapi", spec.get("swagger", "unknown")),
                                    "endpoint_count": ep_count,
                                })

                            findings.append(Finding(
                                title=f"API Specification Publicly Accessible: {path}",
                                severity=Severity.LOW,
                                category="misconfiguration",
                                owasp_category="A05",
                                description=(
                                    f"OpenAPI/Swagger spec found at `{path}` with {ep_count} endpoints. "
                                    "Unauthenticated access to API docs reveals the full attack surface "
                                    "including all endpoints, parameters, and data models."
                                ),
                                remediation="Restrict API documentation to authenticated users or internal networks.",
                                endpoint=f"{base_url}{path}",
                                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                                cvss_score=5.3,
                                cwe_id="CWE-200",
                            ))
                    except Exception:
                        pass

                # Check for GraphQL
                if "graphql" in path.lower():
                    # Try introspection query
                    introspection = {
                        "query": '{ __schema { types { name } } }'
                    }
                    try:
                        gql_resp = await http.post(
                            f"{base_url}{path}",
                            json_data=introspection,
                            module="rest_discovery",
                        )
                        if gql_resp.status_code == 200 and "__schema" in gql_resp.text:
                            session.discovered.api_specs.append({
                                "type": "graphql",
                                "url": f"{base_url}{path}",
                                "introspection": True,
                            })
                            session.discovered.endpoints.append({
                                "url": f"{base_url}{path}",
                                "method": "POST",
                                "source": "graphql",
                                "params": ["query"],
                            })
                    except Exception:
                        pass

            except Exception:
                continue

        return findings
