"""Kerberoasting via ``impacket-getuserspns``.

Source: SpecterOps "Kerberoasting Revisited" (https://posts.specterops.io)
and impacket's GetUserSPNs.py docs.
"""

from __future__ import annotations

import re

from pencheff.config import Severity
from pencheff.core.findings import Evidence, Finding
from pencheff.modules.wrapper_base import run_wrapper


_HASH_RE = re.compile(r"\$krb5tgs\$\d+\$.*", re.IGNORECASE)


async def run(domain: str, *, user: str, password: str, dc_ip: str) -> list[Finding]:
    target = f"{domain}/{user}:{password}"
    extra = ["-dc-ip", dc_ip, "-request", "-outputfile", "/dev/stdout"]
    _, result, _ = await run_wrapper(
        "impacket-getuserspns",
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
            title=f"Kerberoastable SPNs found ({len(hashes)})",
            severity=Severity.HIGH,
            category="kerberoastable_spn",
            owasp_category="A07",
            description="One or more user accounts have SPNs and are vulnerable "
                        "to offline password cracking via Kerberos TGS-REQ.",
            remediation="Use service accounts with strong (>25 char) random "
                        "passwords or gMSAs; restrict Kerberos delegation.",
            endpoint=f"ldap://{dc_ip}",
            evidence=[
                Evidence(
                    request_method="GETSPN",
                    request_url=domain,
                    response_body_snippet=hashes[0][:500],
                    description="impacket-getuserspns",
                )
            ],
        )
    ]
