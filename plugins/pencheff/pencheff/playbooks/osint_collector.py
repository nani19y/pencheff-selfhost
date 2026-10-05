"""osint-collector — Tier 1 advisory.

Public unauthenticated lookups (DNS, certificate transparency, Wayback
CDX). No active scanning of the target. Findings are quiet.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from pencheff.core.tier import tier_1
from pencheff.playbooks.base import Playbook, RunResult


class OsintCollectorPlaybook(Playbook):
    name = "osint_collector"
    tier = 1
    phase = "recon"
    noise = "quiet"
    mitre = ["T1589", "T1590", "T1591", "T1596"]
    handoff_to = ["recon_advisor"]
    requires_scope = False
    description = "OSINT: DNS, cert transparency, Wayback. No active scanning."

    @tier_1
    async def run(self, session: Any, eng_db: Any, engagement_id: str | None = None,
                  target: str | None = None, **kwargs: Any) -> RunResult:
        target = target or getattr(getattr(session, "target", None), "base_url", "")
        host = urlparse(target).hostname or target
        actions = []

        # Read-only lookups: each guarded so the playbook stays Tier 1 even if
        # network is unreachable. Tier 1 = "no targeted egress" — these calls
        # are public databases, listed in the source repo's OSINT scope.
        try:
            import socket
            try:
                ips = list({a[4][0] for a in socket.getaddrinfo(host, None)})
            except Exception:
                ips = []
        except Exception:
            ips = []
        actions.append({"action": "dns_lookup", "host": host, "ips": ips})

        artifacts = {
            "host": host,
            "ips": ips,
            "cert_transparency_query": f"https://crt.sh/?q=%25.{host}&output=json",
            "wayback_query": f"https://web.archive.org/cdx/search/cdx?url={host}/*&output=json&fl=original&limit=1000",
            "hibp_doc": "https://haveibeenpwned.com/API/v3/breachedaccount/{email}",
        }

        self._log(eng_db, engagement_id, "osint", summary=f"resolved {host} → {len(ips)} addrs",
                  detail=artifacts)
        return RunResult(
            playbook=self.name,
            summary=f"OSINT for {host}: {len(ips)} address(es).",
            actions=actions,
            handoffs=list(self.handoff_to),
            artifacts=artifacts,
        )
