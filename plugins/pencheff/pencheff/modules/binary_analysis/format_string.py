"""Format-string sink detection via radare2 cross-reference of ``printf``.

Source: ``r2 -A`` analysis pipeline (radare2 docs §3 "Analysis").
"""

from __future__ import annotations

import re

from pencheff.config import Severity
from pencheff.core.findings import Evidence, Finding
from pencheff.modules.wrapper_base import run_wrapper


_FUNCS = ("printf", "fprintf", "sprintf", "vprintf", "snprintf")


async def run(binary_path: str) -> list[Finding]:
    cmd = ";".join(f"axt @sym.{fn}" for fn in _FUNCS)
    chosen, result, _ = await run_wrapper(
        "radare2",
        binary_path,
        target_position="tail",
        extra_args=["-q0", "-c", cmd],
        timeout=60.0,
    )
    sinks = re.findall(r"0x[0-9a-fA-F]+", result.stdout or "")
    if not sinks:
        return []
    return [
        Finding(
            title=f"{chosen}: {len(sinks)} potential format-string call sites",
            severity=Severity.LOW,
            category="format_string",
            owasp_category="A03",
            description="The binary calls printf-family functions; review each "
                        "site for user-controlled format strings.",
            remediation="Always pass a literal format string. Use compiler "
                        "flag -Wformat-security and avoid %n.",
            endpoint=binary_path,
            evidence=[
                Evidence(
                    request_method="N/A",
                    request_url=binary_path,
                    response_body_snippet=", ".join(sinks[:32]),
                    description=f"radare2 axt for {', '.join(_FUNCS)}",
                )
            ],
        )
    ]
