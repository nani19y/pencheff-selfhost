"""Cert Transparency watcher — pull recent certs, flag new issuances.

Shares the crt.sh feed with continuous_discovery but focuses on cert details
(issuer, validity window, SAN list) for issuance-change alerts.
"""

from __future__ import annotations

import httpx

from pencheff.config import Severity
from pencheff.core.findings import Evidence, Finding


async def watch(domain: str) -> list[Finding]:
    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            r = await client.get(f"https://crt.sh/?q=%.{domain}&output=json")
        if r.status_code != 200:
            return []
        data = r.json()
    except Exception:  # noqa: BLE001
        return []

    # Deduplicate by serial; flag certs issued in last 7 days
    out: list[Finding] = []
    import datetime
    cutoff = datetime.datetime.utcnow() - datetime.timedelta(days=7)
    seen_serial: set[str] = set()
    for row in data:
        serial = row.get("serial_number")
        if serial in seen_serial:
            continue
        seen_serial.add(serial)
        try:
            nb = datetime.datetime.fromisoformat(row.get("not_before", "").replace("Z", ""))
        except Exception:  # noqa: BLE001
            continue
        if nb < cutoff:
            continue
        out.append(Finding(
            title=f"Recent cert issuance: {row.get('common_name','?')}",
            severity=Severity.INFO,
            category="misconfiguration",
            owasp_category="A05",
            description=(
                f"A new certificate was issued for {row.get('common_name','?')} by "
                f"{row.get('issuer_name','?')} on {row.get('not_before','?')}. "
                "Confirm this was authorised — unexpected issuance may indicate a "
                "subdomain takeover or unauthorised cert."
            ),
            remediation=(
                "Review the CAA record, verify the issuance was authorised, and "
                "rotate/revoke if anomalous. Enable CT-log monitoring for long-term visibility."
            ),
            endpoint=row.get("common_name", ""),
            evidence=[Evidence(
                request_method="CT", request_url=f"https://crt.sh/?serial={serial}",
                response_status=200,
                description=f"Issuer: {row.get('issuer_name','?')} Valid {row.get('not_before','?')}..{row.get('not_after','?')}",
            )],
        ))
    return out
