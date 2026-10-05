"""Username / profile enumeration via Sherlock.

Source: https://github.com/sherlock-project/sherlock README.
"""

from __future__ import annotations

import json
import re

from pencheff.config import Severity
from pencheff.core.findings import Evidence, Finding
from pencheff.modules.wrapper_base import run_wrapper


_HIT = re.compile(r"^\[\+\] (?P<site>[^:]+): (?P<url>https?://\S+)")


async def sherlock(username: str) -> list[Finding]:
    _, result, _ = await run_wrapper(
        "sherlock",
        username,
        target_position="tail",
        extra_args=["--print-found", "--no-color"],
        timeout=180.0,
    )
    hits = [m.groupdict() for m in _HIT.finditer(result.stdout or "")]
    if not hits:
        return []
    return [
        Finding(
            title=f"Public profiles for {username!r} ({len(hits)})",
            severity=Severity.INFO,
            category="osint_username",
            owasp_category="A05",
            description="Sherlock matched the username on multiple platforms; "
                        "review for OSINT/social-engineering exposure.",
            remediation="Inform the data subject; consider takedown / handle "
                        "rotation where appropriate.",
            endpoint=f"sherlock://{username}",
            evidence=[
                Evidence(
                    request_method="N/A",
                    request_url=f"sherlock://{username}",
                    response_body_snippet=json.dumps(hits[:50]),
                    description="sherlock --print-found",
                )
            ],
        )
    ]
