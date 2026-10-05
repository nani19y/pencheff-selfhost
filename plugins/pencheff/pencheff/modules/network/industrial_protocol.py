"""Parity-only industrial protocol probing (Modbus TCP, BACnet, S7, EtherNet/IP).

These protocols should never be on the public internet. We check whether the
well-known port accepts a connection and emit a Finding if so. We do NOT send
any protocol-level commands — read-only identification is out of scope too.
"""

from __future__ import annotations

import asyncio
import contextlib

from pencheff.config import Severity
from pencheff.core.findings import Evidence, Finding


INDUSTRIAL_SERVICES = {
    502: ("Modbus TCP", "Modbus/TCP on the public internet is always a serious exposure."),
    47808: ("BACnet/IP", "Building automation protocols must be network-isolated."),
    102: ("Siemens S7", "Siemens industrial controllers should never be publicly reachable."),
    44818: ("EtherNet/IP", "Allen-Bradley / Rockwell controllers exposed via EtherNet/IP."),
    20000: ("DNP3", "SCADA DNP3 exposure — restrict to internal segments."),
}


async def scan(host: str) -> list[Finding]:
    findings: list[Finding] = []
    for port, (name, note) in INDUSTRIAL_SERVICES.items():
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=2.0
            )
            findings.append(Finding(
                title=f"Industrial protocol port open: {name} ({port})",
                severity=Severity.HIGH,
                category="misconfiguration",
                owasp_category="A05",
                description=(
                    f"Host {host} accepts TCP on port {port} ({name}). {note}"
                ),
                remediation=(
                    "Segment the device behind a firewall; only permit traffic from the "
                    "control network, never from the internet."
                ),
                endpoint=f"{host}:{port}",
                evidence=[Evidence(
                    request_method="TCP", request_url=f"{host}:{port}",
                    response_status=0, description=f"{name} port accepted connection",
                )],
            ))
            with contextlib.suppress(Exception):
                writer.close()
                await writer.wait_closed()
        except Exception:  # noqa: BLE001
            continue
    return findings
