"""Technology fingerprinting via HTTP headers, HTML content, and response patterns."""

from __future__ import annotations

import re
from typing import Any

from pencheff.config import Severity
from pencheff.core.findings import Evidence, Finding
from pencheff.core.http_client import PencheffHTTPClient
from pencheff.core.session import PentestSession
from pencheff.modules.base import BaseTestModule

# Known technology signatures in headers
HEADER_SIGNATURES = {
    "server": {
        "apache": "Apache",
        "nginx": "Nginx",
        "iis": "Microsoft IIS",
        "cloudflare": "Cloudflare",
        "litespeed": "LiteSpeed",
        "openresty": "OpenResty/Nginx",
        "gunicorn": "Gunicorn (Python)",
        "uvicorn": "Uvicorn (Python ASGI)",
        "express": "Express.js",
        "kestrel": "Kestrel (.NET)",
    },
    "x-powered-by": {
        "php": "PHP",
        "asp.net": "ASP.NET",
        "express": "Express.js",
        "next.js": "Next.js",
        "flask": "Flask (Python)",
        "django": "Django (Python)",
    },
}

# HTML/body signatures
BODY_SIGNATURES = [
    (r"wp-content|wp-includes|wordpress", "WordPress"),
    (r"drupal|sites/default", "Drupal"),
    (r"joomla", "Joomla"),
    (r"react|__NEXT_DATA__|_next/static", "React/Next.js"),
    (r"ng-app|ng-controller|angular", "Angular"),
    (r"vue\.js|v-bind|v-model", "Vue.js"),
    (r"laravel|csrf-token.*meta", "Laravel"),
    (r"django|csrfmiddlewaretoken", "Django"),
    (r"spring|jsessionid", "Spring (Java)"),
    (r"rails|csrf-token.*authenticity", "Ruby on Rails"),
    (r"graphql|__schema|graphiql", "GraphQL"),
    (r"swagger|openapi|api-docs", "Swagger/OpenAPI"),
]

# Cookie signatures
COOKIE_SIGNATURES = {
    "PHPSESSID": "PHP",
    "JSESSIONID": "Java",
    "ASP.NET_SessionId": "ASP.NET",
    "connect.sid": "Express.js",
    "csrftoken": "Django",
    "_rails_session": "Ruby on Rails",
    "laravel_session": "Laravel",
    "XSRF-TOKEN": "Angular/Laravel",
}


class TechFingerprintModule(BaseTestModule):
    name = "tech_fingerprint"
    category = "recon"
    owasp_categories = ["A05"]
    description = "Technology stack detection via HTTP responses"

    def get_techniques(self) -> list[str]:
        return ["header_analysis", "body_analysis", "cookie_analysis", "error_probing"]

    async def run(
        self,
        session: PentestSession,
        http: PencheffHTTPClient,
        targets: list[str] | None = None,
        config: dict[str, Any] | None = None,
    ) -> list[Finding]:
        findings = []
        detected: dict[str, list[str]] = {
            "web_server": [],
            "framework": [],
            "language": [],
            "cms": [],
            "frontend": [],
            "other": [],
        }

        base_url = session.target.base_url

        try:
            resp = await http.get(base_url, module="tech_fingerprint", inject_creds=False)
        except Exception:
            return findings

        headers = {k.lower(): v for k, v in resp.headers.items()}
        body = resp.text

        # Header analysis
        for header_name, sigs in HEADER_SIGNATURES.items():
            header_val = headers.get(header_name, "").lower()
            for keyword, tech in sigs.items():
                if keyword in header_val:
                    cat = "web_server" if header_name == "server" else "framework"
                    if tech not in detected[cat]:
                        detected[cat].append(tech)

        # Verbose header check — info disclosure finding
        # Cloud-infra signatures we cannot strip — these are unavoidable
        # headers added by the CDN/load balancer in front of the app.
        # Reporting them as "technology disclosure" is true-positive but
        # accepted-risk; we record the finding (so the user can toggle
        # "Show false positives" and inspect) but pre-suppress it.
        unavoidable_signatures = (
            "amazons3", "amazonec2", "cloudfront", "cloudflare",
            "akamai", "fastly", "google frontend", "gws",
            "vercel", "netlify", "nginx", "apache",  # bare names
        )
        for h in ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"]:
            value = headers.get(h, "")
            if not value:
                continue
            # Skip placeholder / non-informative values that don't
            # actually disclose a technology — e.g. servers that send
            # ``Server: server`` or ``Server: -``. Reporting them as
            # "technology disclosure" is misleading because there's no
            # technology being disclosed.
            stripped = value.strip().strip("-").strip()
            if not stripped or stripped.lower() == h.lower():
                continue
            f = Finding(
                title=f"Technology Disclosure via '{h}' Header",
                severity=Severity.INFO,
                category="misconfiguration",
                owasp_category="A05",
                description=f"The '{h}' header reveals: {value}. "
                            "This helps attackers identify the technology stack.",
                remediation=f"Remove or obfuscate the '{h}' response header.",
                endpoint=base_url,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                cvss_score=5.3,
                cwe_id="CWE-200",
                evidence=[Evidence(
                    request_method="GET",
                    request_url=base_url,
                    response_status=resp.status_code,
                    description=f"{h}: {value}",
                )],
            )
            value_lower = value.lower()
            if any(sig in value_lower for sig in unavoidable_signatures):
                from datetime import datetime, timezone
                from pencheff.core.findings import SuppressReason
                f.suppressed = True
                f.suppress_reason = SuppressReason.ACCEPTED_RISK
                f.suppress_notes = (
                    f"Auto-suppressed: '{value}' is a managed-infrastructure "
                    "signature (CDN/load-balancer/PaaS) that operators "
                    "cannot strip. No exploitable disclosure beyond knowing "
                    "the hosting provider."
                )
                f.suppressed_at = datetime.now(timezone.utc)
            findings.append(f)

        # Body analysis
        for pattern, tech in BODY_SIGNATURES:
            if re.search(pattern, body, re.IGNORECASE):
                for cat in ["cms", "frontend", "framework"]:
                    if tech not in detected[cat]:
                        detected[cat].append(tech)
                        break

        # Cookie analysis
        set_cookie = headers.get("set-cookie", "")
        for cookie_name, tech in COOKIE_SIGNATURES.items():
            if cookie_name.lower() in set_cookie.lower():
                if tech not in detected["language"]:
                    detected["language"].append(tech)

        # Probe common error/info paths
        probe_paths = [
            "/robots.txt", "/sitemap.xml", "/.well-known/security.txt",
            "/favicon.ico", "/humans.txt",
        ]
        for path in probe_paths:
            try:
                probe_resp = await http.get(
                    f"{base_url}{path}", module="tech_fingerprint", inject_creds=False,
                )
                if probe_resp.status_code == 200 and path == "/robots.txt":
                    # Extract disallowed paths as potential endpoints
                    for line in probe_resp.text.split("\n"):
                        line = line.strip()
                        if line.lower().startswith("disallow:"):
                            disallowed = line.split(":", 1)[1].strip()
                            if disallowed and disallowed != "/":
                                session.discovered.endpoints.append({
                                    "url": f"{base_url}{disallowed}",
                                    "method": "GET",
                                    "source": "robots.txt",
                                    "params": [],
                                })
            except Exception:
                continue

        # Clean up and store
        detected = {k: v for k, v in detected.items() if v}
        session.discovered.tech_stack.update(detected)

        return findings
