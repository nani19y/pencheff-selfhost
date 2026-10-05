# pencheff/modules/mcp_scan/agent_probe.py
"""Toxic-flow analysis + agent-endpoint probing for MCP agent sources.

Covers source_type in {"agent_http", "agent_browser"}.

Pure logic (lethal_trifecta_present, build_agent_probe_config) is fully
unit-tested. Live LLM probing via run_agent_probe is integration surface;
it degrades non-fatally on any error.
"""
from __future__ import annotations

import logging
from typing import Any

log = logging.getLogger(__name__)

from pencheff.config import Severity
from pencheff.core.findings import Finding

from .manifest import McpTool
from .static_analyzers import lethal_trifecta_present


# ---------------------------------------------------------------------------
# Config builder
# ---------------------------------------------------------------------------

_AGENT_DEFAULT_CATEGORIES = ["LLM01", "LLM02", "LLM04", "LLM05", "LLM06", "LLM07", "LLM10"]
# Total probe budget for an agent scan (the runner splits it across the selected
# modules). Conservative because agents respond in tens of seconds per turn.
_AGENT_DEFAULT_MAX_PAYLOADS = 36
_AGENT_DEFAULT_REDTEAM = {"strategies": ["jailbreak", "crescendo"], "plugins": ["mcp"]}


def _resolve_agent_redteam(cfg: dict) -> tuple[list[str], dict]:
    """Curated agent default merged with an optional per-target ``cfg['redteam']``
    override. Present override keys replace the default for that key. Empty/invalid
    override categories fall back to the curated default (never scan zero modules)."""
    override = cfg.get("redteam") if isinstance(cfg.get("redteam"), dict) else {}
    cats = override.get("categories")
    if not isinstance(cats, list) or not [c for c in cats if isinstance(c, str)]:
        cats = list(_AGENT_DEFAULT_CATEGORIES)
    redteam = {**_AGENT_DEFAULT_REDTEAM, **{k: v for k, v in override.items() if k != "categories"}}
    return [c for c in cats if isinstance(c, str)], redteam


def build_agent_probe_config(cfg: dict[str, Any], *, base_url: str) -> dict[str, Any]:
    """Map an agent McpConfig into the llm_config dict shape consumed by LlmProbe.

    Sets redteam.plugins=["mcp"] so the existing mcp.yaml attack pack runs.
    """
    source_type = cfg.get("source_type", "")

    if source_type == "agent_http":
        return {
            "provider": cfg["provider"],
            "model": cfg.get("model"),
            "request_template": cfg.get("request_template"),
            "response_path": cfg.get("response_path"),
            "redteam": {"plugins": ["mcp"]},
        }

    if source_type == "agent_browser":
        return {
            "provider": "browser",
            "browser": {
                "url": cfg.get("url"),
                "prompt_selector": cfg.get("prompt_selector"),
                "send_selector": cfg.get("send_selector"),
                "response_selector": cfg.get("response_selector"),
            },
            "redteam": {"plugins": ["mcp"]},
        }

    # Fallback: return a minimal config with the base_url
    return {
        "provider": "unknown",
        "url": base_url,
        "redteam": {"plugins": ["mcp"]},
    }


# ---------------------------------------------------------------------------
# Live agent probe (integration surface — non-fatal)
# ---------------------------------------------------------------------------

async def run_agent_probe(session, mcp_config: dict[str, Any]) -> list[Finding]:
    """Probe an agent_http or agent_browser endpoint using the llm_red_team pack.

    Pure logic (trifecta + config building) runs unconditionally.
    Live LLM probing is attempted but never fatal.
    """
    findings: list[Finding] = []
    source_type = mcp_config.get("source_type", "")
    url = mcp_config.get("url", "")

    # Build the probe config regardless of live probing success.
    probe_cfg = build_agent_probe_config(mcp_config, base_url=url)

    # --- Live LLM red-team probe (best-effort) ---
    try:
        from pencheff.modules.llm_red_team.runner import run_red_team_categories
        categories, redteam_cfg = _resolve_agent_redteam(mcp_config)
        probe_cfg["redteam"] = {**(probe_cfg.get("redteam") or {}), **redteam_cfg}
        if hasattr(session, "llm_config"):
            session.llm_config = probe_cfg
        # Agents are SLOW (tens of seconds/turn); 6 uncapped modules × strategy
        # fan-out would blow the scan timeout. Cap total probes conservatively
        # (split across modules by the runner). Override via redteam.max_payloads.
        # ponytail: fixed default, not profile-threaded; thread the profile cap if agents need depth tuning.
        max_payloads = (mcp_config.get("redteam") or {}).get("max_payloads") if isinstance(mcp_config.get("redteam"), dict) else None
        if not isinstance(max_payloads, int) or max_payloads <= 0:
            max_payloads = _AGENT_DEFAULT_MAX_PAYLOADS
        live_findings = await run_red_team_categories(
            session, categories, max_payloads, module_label="agent_red_team")
        findings.extend(live_findings)
    except Exception as e:
        # Live probing is integration surface — degrade non-fatally, but log so failures are observable.
        log.warning("mcp agent live-probe failed: %s", e)

    # --- Toxic-flow static analysis ---
    # Pull tool list from session or mcp_config if available.
    tools: list[McpTool] = []
    try:
        tools_raw = mcp_config.get("tools") or []
        tools = [
            McpTool(name=t.get("name", ""), description=t.get("description", ""))
            if isinstance(t, dict) else t
            for t in tools_raw
        ]
        # Also check session-level tool info if present.
        if not tools and hasattr(session, "mcp_config") and session.mcp_config:
            tools_raw = session.mcp_config.get("tools") or []
            tools = [
                McpTool(name=t.get("name", ""), description=t.get("description", ""))
                if isinstance(t, dict) else t
                for t in tools_raw
            ]
    except Exception:
        tools = []

    if tools and lethal_trifecta_present(tools):
        findings.append(
            Finding(
                title="MCP Toxic-Flow: Confused Deputy / Data Exfiltration Risk",
                severity=Severity.HIGH,
                category="MCP Security",
                owasp_category="LLM06",
                description=(
                    "The agent's tool set combines untrusted-input ingestion, private-data "
                    "access, and an egress/exfiltration capability — the three-bucket "
                    "precondition for a confused-deputy attack. A compromised or adversarial "
                    "tool call can read private data and exfiltrate it via the egress tool "
                    "without explicit user consent (MCP toxic-flow pattern)."
                ),
                remediation=(
                    "Apply least-privilege: restrict which tools can be combined in a single "
                    "agent session. Use MCP elicitation / consent gates before any tool that "
                    "reads private data. Monitor egress tool calls for anomalous data volumes."
                ),
                endpoint=url,
                cwe_id="CWE-441",
                references=[
                    "https://simonwillison.net/2025/Apr/9/mcp-prompt-injection/",
                    "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
                ],
                metadata={"technique": "mcp:toxic-flow"},
            )
        )

    return findings
