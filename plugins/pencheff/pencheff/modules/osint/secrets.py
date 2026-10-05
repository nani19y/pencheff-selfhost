"""Secret scanning via TruffleHog.

Source: https://github.com/trufflesecurity/trufflehog README.
"""

from __future__ import annotations

import json

from pencheff.config import Severity
from pencheff.core.findings import Evidence, Finding
from pencheff.modules.wrapper_base import run_wrapper


async def scan_filesystem(path: str) -> list[Finding]:
    _, result, _ = await run_wrapper(
        "trufflehog",
        path,
        target_position="tail",
        extra_args=["filesystem", "--json", "--no-update", "--only-verified"],
        timeout=300.0,
    )
    findings: list[Finding] = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        detector = entry.get("DetectorName") or entry.get("detector") or "unknown"
        sourcename = (
            entry.get("SourceMetadata", {})
                 .get("Data", {})
                 .get("Filesystem", {})
                 .get("file")
            or entry.get("SourceName")
            or path
        )
        findings.append(
            Finding(
                title=f"Verified secret: {detector}",
                severity=Severity.HIGH,
                category="hardcoded_secret",
                owasp_category="A02",
                description=f"TruffleHog verified an active credential from "
                            f"{detector!r} in {sourcename}.",
                remediation="Rotate the credential, scrub from history "
                            "(git filter-repo / BFG), and add a pre-commit hook.",
                endpoint=sourcename,
                evidence=[
                    Evidence(
                        request_method="N/A",
                        request_url=sourcename,
                        response_body_snippet=json.dumps(entry)[:1000],
                        description=detector,
                    )
                ],
            )
        )
    return findings
