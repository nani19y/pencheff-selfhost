"""ADCS template-abuse detection via ``certipy``.

Source: SpecterOps "Certified Pre-Owned" (Schroeder, McCullough). Detects
ESC1 / ESC4 / ESC8 candidates from certipy's ``find`` output.
"""

from __future__ import annotations

from pencheff.config import Severity
from pencheff.core.findings import Evidence, Finding
from pencheff.modules.wrapper_base import run_wrapper


_FLAGS = ("ESC1", "ESC2", "ESC3", "ESC4", "ESC5", "ESC6", "ESC7", "ESC8", "ESC11")


async def run(domain: str, *, user: str, password: str, dc_ip: str) -> list[Finding]:
    extra = [
        "find",
        "-vulnerable",
        "-u", f"{user}@{domain}",
        "-p", password,
        "-dc-ip", dc_ip,
        "-text",
    ]
    _, result, _ = await run_wrapper(
        "certipy",
        target=domain,
        target_position="tail",
        extra_args=extra,
        timeout=180.0,
        use_fallback=False,
    )
    findings: list[Finding] = []
    for flag in _FLAGS:
        if flag in result.stdout:
            findings.append(
                Finding(
                    title=f"ADCS {flag} template found",
                    severity=Severity.CRITICAL,
                    category=f"adcs_{flag.lower()}_template",
                    owasp_category="A01",
                    description=f"At least one certificate template is vulnerable to {flag}.",
                    remediation="Restrict the template's enrollment ACL, disable "
                                "client-supplied SAN, and require manager approval.",
                    endpoint=f"ldap://{dc_ip}",
                    evidence=[
                        Evidence(
                            request_method="LDAP",
                            request_url=domain,
                            response_body_snippet=result.stdout[:1000],
                            description=f"certipy find ({flag})",
                        )
                    ],
                )
            )
    return findings
