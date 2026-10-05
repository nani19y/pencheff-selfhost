"""Out-of-Band Application Security Testing (OAST) support.

Generates unique callback URLs for detecting blind SSRF, blind SQLi,
blind XSS, and other out-of-band vulnerabilities.

Backend options (in preference order):
  1. interactsh-client (ProjectDiscovery) — if installed
  2. Burp Collaborator URL — if manually configured via OAST_HOST env var
  3. Lightweight built-in HTTP callback server on localhost (for local testing)

Usage:
  oast = OASTManager()
  url = oast.new_url("ssrf-probe-1")   # unique per-test URL
  # inject url into payload
  hits = oast.poll()                   # returns callback records
"""

from __future__ import annotations

import asyncio
import os
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class OASTHit:
    """A received callback from an OAST probe."""
    probe_id: str
    source_ip: str
    protocol: str          # http, dns, smtp, etc.
    raw: str
    received_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict[str, Any]:
        return {
            "probe_id": self.probe_id,
            "source_ip": self.source_ip,
            "protocol": self.protocol,
            "raw": self.raw[:500],
            "received_at": self.received_at.isoformat(),
        }


class OASTManager:
    """Manages OAST probes and callback tracking for a pentest session."""

    def __init__(self, session_id: str):
        self._session_id = session_id
        self._probes: dict[str, str] = {}   # probe_id → label
        self._hits: list[OASTHit] = []
        self._interactsh_domain: str | None = None
        self._interactsh_token: str | None = None
        self._interactsh_server: str = "oast.fun"
        self._custom_host = os.environ.get("OAST_HOST", "")

    def configure_engagement(
        self, *, domain: str | None, token: str | None, server: str | None = None
    ) -> None:
        """Wire this manager to a per-engagement interactsh-server instance.

        The backend's engagement_oast service provisions a dedicated
        ``interactsh-server`` container and stores ``oast_domain`` +
        ``oast_token`` on the engagement. When a backend-driven scan
        instantiates this manager, it calls ``configure_engagement`` so all
        callbacks land on infrastructure the operator owns instead of the
        shared oast.fun cluster.
        """
        if domain:
            self._interactsh_domain = domain
        if token:
            self._interactsh_token = token
        if server:
            self._interactsh_server = server
        elif domain:
            # Default the upstream server to the engagement's own root.
            self._interactsh_server = domain

    def _backend(self) -> str:
        from pencheff.core.tool_runner import tool_available
        if tool_available("interactsh-client"):
            return "interactsh"
        if self._custom_host:
            return "custom"
        return "none"

    async def register(self) -> dict[str, Any]:
        """Register this session with the OAST backend. Returns status."""
        backend = self._backend()
        # If the engagement already configured a domain + token, we don't
        # need to spawn a discovery interactsh-client — we already know the
        # domain and trust the operator's server.
        if backend == "interactsh" and not self._interactsh_domain:
            try:
                from pencheff.core.tool_runner import run_tool
                args = ["interactsh-client", "-no-color", "-json",
                        "-server", self._interactsh_server]
                if self._interactsh_token:
                    args.extend(["-token", self._interactsh_token])
                result = await run_tool(args, timeout=5.0)
                # Parse first line for domain
                for line in result.stdout.splitlines():
                    if "interactsh.com" in line or "oast" in line:
                        import re
                        m = re.search(r'([a-z0-9]+\.oast\.[a-z]+)', line)
                        if m:
                            self._interactsh_domain = m.group(1)
                            break
            except Exception:
                pass

        return {
            "backend": backend,
            "session_id": self._session_id,
            "interactsh_domain": self._interactsh_domain,
            "interactsh_server": self._interactsh_server,
            "engagement_owned": bool(self._interactsh_token),
            "custom_host": self._custom_host or None,
            "ready": backend != "none",
            "note": (
                "Install interactsh-client for full OAST support: "
                "go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"
                if backend == "none" else None
            ),
        }

    def new_url(self, label: str = "") -> str:
        """Generate a unique OAST callback URL for a probe."""
        probe_id = uuid.uuid4().hex[:12]
        self._probes[probe_id] = label or probe_id

        if self._interactsh_domain:
            return f"http://{probe_id}.{self._interactsh_domain}"
        if self._custom_host:
            return f"http://{probe_id}.{self._custom_host}"
        # Fallback: generate a placeholder — won't receive real callbacks
        # but useful for payload construction awareness
        return f"http://{probe_id}.oast.fun"

    def new_dns(self, label: str = "") -> str:
        """Generate a unique OAST DNS hostname for a probe."""
        probe_id = uuid.uuid4().hex[:12]
        self._probes[probe_id] = label or probe_id

        if self._interactsh_domain:
            return f"{probe_id}.{self._interactsh_domain}"
        if self._custom_host:
            return f"{probe_id}.{self._custom_host}"
        return f"{probe_id}.oast.fun"

    def record_hit(self, probe_id: str, source_ip: str, protocol: str, raw: str) -> None:
        """Manually record a callback hit (used when parsing interactsh output)."""
        self._hits.append(OASTHit(
            probe_id=probe_id,
            source_ip=source_ip,
            protocol=protocol,
            raw=raw,
        ))

    async def poll(self) -> list[dict[str, Any]]:
        """Poll the OAST backend for new callbacks. Returns hit list."""
        backend = self._backend()
        if backend == "interactsh" and self._interactsh_domain:
            try:
                from pencheff.core.tool_runner import run_tool
                args = ["interactsh-client", "-no-color", "-json",
                        "-server", self._interactsh_server, "-poll-interval", "1"]
                if self._interactsh_token:
                    args.extend(["-token", self._interactsh_token])
                result = await run_tool(args, timeout=5.0)
                import json
                import re
                for line in result.stdout.splitlines():
                    try:
                        evt = json.loads(line)
                        uid = evt.get("unique-id", "")
                        # Match probe_id from unique-id subdomain prefix
                        for probe_id in self._probes:
                            if uid.startswith(probe_id):
                                self.record_hit(
                                    probe_id=probe_id,
                                    source_ip=evt.get("remote-address", "unknown"),
                                    protocol=evt.get("protocol", "http"),
                                    raw=str(evt)[:500],
                                )
                    except Exception:
                        continue
            except Exception:
                pass

        return [h.to_dict() for h in self._hits]

    def summary(self) -> dict[str, Any]:
        return {
            "backend": self._backend(),
            "probes_registered": len(self._probes),
            "hits_received": len(self._hits),
            "probes": self._probes,
        }


# Per-session store
_oast_managers: dict[str, OASTManager] = {}


def get_oast(session_id: str) -> OASTManager:
    if session_id not in _oast_managers:
        _oast_managers[session_id] = OASTManager(session_id)
    return _oast_managers[session_id]
