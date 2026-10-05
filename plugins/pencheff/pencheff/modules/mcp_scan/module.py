# pencheff/modules/mcp_scan/module.py
"""Static MCP scan module: connect → enumerate → static analyzers + fingerprint.
Dynamic tool-invocation fuzzing is gated by the dynamic_invocation config key (Plan 3 Task D)."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any
import logging

import httpx

from pencheff.core.findings import Finding
from pencheff.modules.base import BaseTestModule

from .client import connect_and_enumerate, connect_session
from .fingerprint import fingerprint
from .static_analyzers import baseline_hash, run_all_static
from . import transport_probes
from . import dynamic as dyn_module
from . import agent_probe


class _OastAdapter:
    """Adapts pencheff OASTManager (new_url/poll) to the .url + async poll() shape
    fuzz_tools expects. Reserves one canary URL upfront for payload embedding."""
    def __init__(self, manager, *, label: str = "mcp-fuzz"):
        self._m = manager
        self.url = manager.new_url(label)

    async def poll(self):
        return await self._m.poll()


@dataclass
class _ProbeResp:
    status_code: int
    session_id: str | None = None


def _make_http_probe_getter(*, transport=None):
    """Return an async http_get(url, headers=...) -> _ProbeResp for transport probes.
    A read-timeout on an SSE endpoint means the server began streaming (accepted the
    request) -> reported as status 200. `transport` is for tests (httpx.MockTransport)."""
    async def _get(url: str, **kwargs):
        headers = kwargs.get("headers") or {}
        client_kwargs = dict(verify=False, timeout=httpx.Timeout(10.0), follow_redirects=False)
        if transport is not None:
            client_kwargs["transport"] = transport
        async with httpx.AsyncClient(**client_kwargs) as client:
            try:
                resp = await client.get(url, headers=headers)
            except httpx.ReadTimeout:
                return _ProbeResp(status_code=200, session_id=None)
            sid = resp.headers.get("Mcp-Session-Id") or resp.headers.get("mcp-session-id")
            return _ProbeResp(status_code=resp.status_code, session_id=sid)
    return _get


def _auth_headers(session) -> dict[str, str]:
    """Build request headers from the target's stored credentials (Authorization /
    X-API-Key / cookie / custom headers). Empty dict when no creds — an
    auth-protected MCP server 401s without these, which silently yields an
    empty manifest and a false clean grade."""
    try:
        store = getattr(session, "credentials", None)
        cs = store.get("default") if store is not None else None
        return cs.inject_into_headers({}) if cs is not None else {}
    except Exception:
        return {}


class McpStaticScanModule(BaseTestModule):
    name = "mcp_static_scan"
    category = "MCP Security"
    owasp_categories = ["LLM01", "LLM02", "LLM05", "LLM06"]
    description = "Enumerate an MCP server and statically analyze its tool/resource/prompt manifest."

    async def run(self, session, http=None, targets=None, config=None) -> list[Finding]:
        cfg = (config or {}).get("mcp_config") or {}
        source_type = cfg.get("source_type")
        if source_type in ("agent_http", "agent_browser"):
            # Agent sources: route to agent_probe instead of connect_and_enumerate.
            try:
                return await agent_probe.run_agent_probe(session, cfg)
            except Exception:
                return []  # non-fatal
        if source_type is None:
            return []
        headers = _auth_headers(session)
        logging.getLogger(__name__).info("scan_progress: connecting to MCP server (%s)", cfg.get("transport") or cfg.get("source_type") or "http")
        manifest = await connect_and_enumerate(cfg, headers=headers)
        logging.getLogger(__name__).info("scan_progress: enumerated %d tools / %d resources / %d prompts", len(manifest.tools), len(manifest.resources), len(manifest.prompts))
        findings = run_all_static(manifest)
        findings.extend(fingerprint(manifest, command=cfg.get("command")))
        # Stamp the rug-pull baseline hash on every finding's metadata for drift tracking.
        digest = baseline_hash(manifest)
        for f in findings:
            f.metadata = {**(f.metadata or {}), "manifest_baseline": digest}
        # Transport / auth CVE probes (Plan 3 Task C).
        # Only fire for HTTP transports; no-op for stdio.
        if manifest.transport in ("sse", "streamable_http"):
            try:
                getter = _make_http_probe_getter()
                findings.extend(await transport_probes.build_transport_findings(manifest, http_get=getter))
            except Exception:
                pass  # never let probe errors abort the scan

        # Dynamic tool-invocation fuzzing (Plan 3 Task D).
        # Gated by dynamic_invocation=True in mcp_config; never runs unless explicitly enabled.
        dyn_cfg = cfg.get("dynamic_invocation") or {}
        if dyn_cfg:
            try:
                fuzz_findings = await _fuzz_just_in_time(session, manifest, cfg, dyn_cfg, headers=headers)
                findings.extend(fuzz_findings)
            except Exception:
                pass  # non-fatal; never abort the static scan

        return findings

    def get_techniques(self) -> list[str]:
        return ["mcp:line-jumping", "mcp:unicode-tag-smuggling", "mcp:excessive-agency",
                "mcp:weak-schema", "mcp:sensitive-resource", "mcp:prompt-poisoning",
                "mcp:known-vuln", "mcp:param-injection:command", "mcp:param-injection:traversal",
                "mcp:param-injection:ssrf"]


async def _fuzz_just_in_time(session, manifest, cfg: dict, dyn_cfg: dict, headers: dict | None = None) -> list[Finding]:
    """Open a fresh MCP connection, fuzz tools, and close it.

    dyn_cfg keys (all optional):
        allow       list[str]  tool allowlist (empty = all tools)
        deny        list[str]  tool denylist
        destructive bool       if True, include destructive tools (default False)
        max_calls   int        hard cap on tool invocations (default 50)
        oast_url    str        pre-provisioned OAST URL if no live OAST object
    """
    allow: list[str] = dyn_cfg.get("allow") or []
    deny: list[str] = dyn_cfg.get("deny") or []
    destructive: bool = bool(dyn_cfg.get("destructive_opt_in", False))
    max_calls: int = int(dyn_cfg.get("max_calls", 50))

    oast = None
    try:
        from pencheff.core.oast import get_oast
        sid = getattr(session, "id", None)
        if sid:
            oast = _OastAdapter(get_oast(sid))
    except Exception:
        oast = None

    # Open a fresh just-in-time live session for fuzzing.
    async with connect_session(cfg, headers=headers) as live:
        return await dyn_module.fuzz_tools(
            live,
            manifest.tools,
            oast=oast,
            allow=allow,
            deny=deny,
            dynamic=True,
            destructive=destructive,
            endpoint=manifest.endpoint,
            max_calls=max_calls,
        )
