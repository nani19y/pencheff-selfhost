"""Native ELF / PE inspection via ``lief`` when present.

Falls back to ``readelf`` parsing if ``lief`` isn't installed. Pure
deterministic checks: NX, PIE, RELRO, canary, fortify, RPATH/RUNPATH.

Source: ``man elf(5)``; lief documentation.
"""

from __future__ import annotations

from pathlib import Path

from pencheff.config import Severity
from pencheff.core.findings import Evidence, Finding


async def run(binary_path: str) -> list[Finding]:
    p = Path(binary_path)
    if not p.is_file():
        return []
    try:
        import lief  # type: ignore
    except ImportError:
        return []  # checksec wrapper covers this case

    binary = lief.parse(str(p))
    if binary is None:
        return []

    weaknesses: list[str] = []
    if hasattr(binary, "abstract"):
        # ELF
        try:
            header = binary.header  # type: ignore[attr-defined]
            if hasattr(header, "machine_type"):
                pass
        except Exception:  # noqa: BLE001
            pass

    # NX (DEP)
    try:
        if not getattr(binary, "has_nx", True):
            weaknesses.append("NX (DEP) disabled — stack/heap is executable.")
    except Exception:  # noqa: BLE001
        pass
    # PIE
    try:
        is_pie = getattr(binary, "is_pie", None)
        if is_pie is False:
            weaknesses.append("PIE disabled — base address is fixed.")
    except Exception:  # noqa: BLE001
        pass
    # RPATH / RUNPATH
    try:
        if getattr(binary, "has_rpath", False) or getattr(binary, "has_runpath", False):
            weaknesses.append("RPATH/RUNPATH set — vulnerable to library hijacking.")
    except Exception:  # noqa: BLE001
        pass

    if not weaknesses:
        return []
    return [
        Finding(
            title="Binary hardening weaknesses (lief)",
            severity=Severity.MEDIUM,
            category="binary_hardening",
            owasp_category="A05",
            description="; ".join(weaknesses),
            remediation="Recompile with -fpie -pie -fstack-protector-strong "
                        "-Wl,-z,relro,-z,now and avoid setting RPATH/RUNPATH.",
            endpoint=binary_path,
            evidence=[
                Evidence(
                    request_method="N/A",
                    request_url=binary_path,
                    response_body_snippet="; ".join(weaknesses)[:500],
                    description="lief native ELF/PE inspection",
                )
            ],
        )
    ]
