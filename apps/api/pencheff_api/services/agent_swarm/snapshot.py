"""ReconSnapshot — the read-only handoff from Phase 1 to Phase 2.

Frozen by construction: every nested collection is a tuple or a
read-only mapping. Once Recon publishes a snapshot, no breaker can
mutate it.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Literal, Mapping


class ReconFailed(Exception):
    """Raised by ``run_recon_phase`` when recon crashed or produced an
    empty surface. The orchestrator catches this and routes to the
    catastrophic-fallback gate (legacy single-agent loop)."""


@dataclass(frozen=True)
class DiscoveredEndpoint:
    url: str
    method: str
    status: int | None
    content_type: str | None
    parameters: tuple[str, ...]


@dataclass(frozen=True)
class ReconSnapshot:
    # Provenance / scope
    target_base_url: str
    profile: Literal["quick", "standard", "deep"]
    scope_include: tuple[str, ...]
    scope_exclude: tuple[str, ...]

    # Surface
    endpoints: tuple[DiscoveredEndpoint, ...]
    api_spec_urls: tuple[str, ...]
    subdomains: tuple[str, ...]
    robots_txt: str | None
    sitemap_urls: tuple[str, ...]
    security_txt: str | None

    # Fingerprint
    tech_stack: Mapping[str, str]
    waf_vendor: str | None

    # Auth handoff
    authenticated: bool
    auth_login_url: str | None
    auth_cookies: tuple[tuple[str, str], ...]
    auth_tokens: Mapping[str, str]

    # OAST
    oast_session_handle: str | None

    # Provenance / debugging
    recon_agent_summary: str
    recon_findings_ids: tuple[str, ...]
    snapshot_built_at: datetime

    # Operator transport/protocol config (grpc plaintext/tls_verify/reflection,
    # graphql introspection, websocket subprotocols, …) so per-breaker sessions
    # can re-apply it — the protocol tools read it via _kind_config_for_session.
    kind_config: Mapping[str, Any] = field(default_factory=dict)
