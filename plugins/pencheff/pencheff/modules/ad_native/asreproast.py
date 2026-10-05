"""AS-REP roasting via ``impacket-getnpusers``.

Source: ADSecurity.org "AS-REP Roasting" article; impacket GetNPUsers.py.
"""

from __future__ import annotations

import re

from pencheff.config import Severity
from pencheff.core.findings import Evidence, Finding
from pencheff.modules.wrapper_base import run_wrapper


_HASH_RE = re.compile(r"\$krb5asrep\$\d+\$.*", re.IGNORECASE)


async def run(domain: str, *, users_file: str, dc_ip: str) -> list[Finding]:
    extra = ["-dc-ip", dc_ip, "-no-pass", "-usersfile", users_file]
    target = f"{domain}/"
    _, result, _ = await run_wrapper(
        "impacket-getnpusers",
        target,
        target_position="tail",
        extra_args=extra,
        timeout=120.0,
        use_fallback=False,
    )
    hashes = _HASH_RE.findall(result.stdout)
    if not hashes:
        return []
    return [
        Finding(
            title=f"AS-REP roastable users ({len(hashes)})",
            severity=Severity.HIGH,
            category="asrep_roastable_user",
            owasp_category="A07",
            description="Account(s) have Kerberos pre-authentication disabled "
                        "and are vulnerable to AS-REP roasting.",
            remediation="Re-enable pre-authentication on all user accounts and "
                        "rotate impacted passwords.",
            endpoint=f"ldap://{dc_ip}",
            evidence=[
                Evidence(
                    request_method="AS-REQ",
                    request_url=domain,
                    response_body_snippet=hashes[0][:500],
                    description="impacket-getnpusers",
                )
            ],
        )
    ]
