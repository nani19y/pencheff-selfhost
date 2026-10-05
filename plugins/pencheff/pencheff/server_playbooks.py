"""MCP tool registrations for the pentest-ai-agents integration.

Importing this module attaches one ``@mcp.tool()`` per playbook plus
six engagement-DB tools to the existing FastMCP server in
:mod:`pencheff.server`.

Tools mirror the CLI surface so an MCP client gets the same methodology
over MCP that ``pencheff engage`` provides on the shell.
"""

from __future__ import annotations

from typing import Any

from pencheff.core.engagement_db import EngagementDB
from pencheff.core.scope_guard import ScopeGuard, set_scope
from pencheff.core.session import create_session, get_session
from pencheff.config import SCAN_PROFILES
from pencheff.playbooks import REGISTRY
from pencheff.server import mcp


def _get_or_create_session(session_id: str | None, target: str | None) -> Any:
    if session_id:
        existing = get_session(session_id)
        if existing:
            return existing
    p = SCAN_PROFILES["standard"]
    return create_session(target_url=target or "http://placeholder.invalid", depth=p["depth"])


def _result(res: Any, session_id: str, engagement_id: str | None) -> dict[str, Any]:
    return {
        "session_id": session_id,
        "engagement_id": engagement_id,
        "playbook": res.playbook,
        "summary": res.summary,
        "findings_added": res.findings_added,
        "actions": res.actions,
        "handoffs": res.handoffs,
        "artifacts": res.artifacts,
        "error": res.error,
    }


def _make_pb_tool(name: str, cls: type) -> None:
    """Register a single playbook as an MCP tool."""

    desc = f"Pencheff playbook: {name} (Tier {cls.tier}). {cls.description}"

    @mcp.tool(name=f"playbook_{name}", description=desc)
    async def _tool(
        target: str | None = None,
        engagement_id: str | None = None,
        scope: dict[str, Any] | None = None,
        session_id: str | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        # Scope sourcing: dict, file path, or none
        if isinstance(scope, dict) and scope:
            set_scope(ScopeGuard.from_dict(scope))
        elif isinstance(scope, str) and scope:
            set_scope(ScopeGuard.from_file(scope))
        eng_db = EngagementDB()
        if engagement_id is None:
            engagement_id = eng_db.init_engagement(
                client="mcp", engagement_type="external",
                scope=scope if isinstance(scope, dict) else None,
            )
        session = _get_or_create_session(session_id, target)
        pb = cls()
        try:
            res = await pb.run(session, eng_db, engagement_id, scope=scope, **kwargs)
        except Exception as exc:
            return {"playbook": name, "error": f"{type(exc).__name__}: {exc}",
                    "engagement_id": engagement_id, "session_id": session.id}
        return _result(res, session.id, engagement_id)


for _name, _cls in REGISTRY.items():
    _make_pb_tool(_name, _cls)


# ── Engagement-DB MCP tools ──────────────────────────────────────────
@mcp.tool(name="engagement_init",
          description="Create a new pencheff engagement DB row.")
async def engagement_init(client: str, type: str = "external",
                          scope: dict[str, Any] | None = None,
                          notes: str = "") -> dict[str, Any]:
    eng = EngagementDB()
    eid = eng.init_engagement(client=client, engagement_type=type,
                              scope=scope, notes=notes)
    return {"engagement_id": eid, "client": client, "type": type}


@mcp.tool(name="engagement_log",
          description="Append an entry to the engagement session_log.")
async def engagement_log(engagement_id: str, agent: str, action: str,
                         summary: str = "", detail: str = "") -> dict[str, Any]:
    eng = EngagementDB()
    rid = eng.log(engagement_id, agent=agent, action=action,
                  summary=summary, detail=detail)
    return {"engagement_id": engagement_id, "log_id": rid}


@mcp.tool(name="engagement_handoff",
          description="Record a from→to handoff in the session_log.")
async def engagement_handoff(engagement_id: str, from_agent: str,
                             to_agent: str, payload: str = "") -> dict[str, Any]:
    eng = EngagementDB()
    rid = eng.handoff(engagement_id, from_agent=from_agent,
                      to_agent=to_agent, payload=payload)
    return {"engagement_id": engagement_id, "log_id": rid}


@mcp.tool(name="engagement_show",
          description="Return the engagement state — hosts, vulns, chains, log.")
async def engagement_show(engagement_id: str) -> dict[str, Any]:
    eng = EngagementDB()
    data = eng.show(engagement_id)
    return data or {"error": "not found", "engagement_id": engagement_id}


@mcp.tool(name="engagement_export",
          description="Render the engagement as a markdown summary.")
async def engagement_export(engagement_id: str,
                            format: str = "md") -> dict[str, Any]:
    eng = EngagementDB()
    if format == "json":
        return eng.show(engagement_id) or {"error": "not found"}
    return {"engagement_id": engagement_id,
            "markdown": eng.export_markdown(engagement_id)}


@mcp.tool(name="engagement_chains",
          description="List discovered/verified attack chains for an engagement.")
async def engagement_chains(engagement_id: str) -> dict[str, Any]:
    eng = EngagementDB()
    return {"engagement_id": engagement_id, "chains": eng.list_chains(engagement_id)}
