"""ROP gadget extractor — wraps ROPgadget / ropper.

Source: ROPgadget README (https://github.com/JonathanSalwan/ROPgadget),
ropper README (https://github.com/sashs/Ropper).

Returns the gadget list as a single info-level finding so the upstream
caller can pipeline them into chain templates (modules/binary_analysis/rop
helpers in workflows). No automated exploit synthesis happens here — this is
a building block for the user.
"""

from __future__ import annotations

import re

from pencheff.config import Severity
from pencheff.core.findings import Evidence, Finding
from pencheff.modules.wrapper_base import run_wrapper


_GADGET_LINE = re.compile(r"^0x[0-9a-fA-F]+ : ")


async def run(binary_path: str, *, max_gadgets: int = 200) -> list[Finding]:
    chosen, result, _ = await run_wrapper(
        "ropgadget",
        binary_path,
        target_position="tail",
        extra_args=["--binary"],
        timeout=120.0,
    )
    gadgets = [
        line for line in result.stdout.splitlines() if _GADGET_LINE.match(line)
    ]
    if not gadgets:
        return []
    sample = "\n".join(gadgets[:max_gadgets])
    return [
        Finding(
            title=f"{chosen}: {len(gadgets)} ROP gadgets extracted",
            severity=Severity.INFO,
            category="binary_analysis",
            owasp_category="A05",
            description=f"Extracted {len(gadgets)} gadgets from {binary_path}.",
            remediation="Compile with -fpie -pie -fstack-protector-strong "
                        "-Wl,-z,relro,-z,now to limit gadget reuse.",
            endpoint=binary_path,
            evidence=[
                Evidence(
                    request_method="N/A",
                    request_url=binary_path,
                    response_body_snippet=sample[:2000],
                    description=f"top-{max_gadgets} gadgets",
                )
            ],
        )
    ]
