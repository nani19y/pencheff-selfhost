# pencheff/modules/mcp_scan/client.py
"""MCP protocol client — connect over stdio / SSE / streamable-HTTP and
normalize the server surface into an McpManifest.

Normalization (_normalize_*, enumerate_session) is pure and unit-tested.
connect_and_enumerate wires the mcp SDK transports; verify the SDK import
paths against the installed mcp version (>=1.23.0)."""
from __future__ import annotations

import contextlib
from typing import Any

from .manifest import McpManifest, McpPrompt, McpResource, McpTool


def _getattr(o: Any, *names, default=None):
    for n in names:
        v = getattr(o, n, None)
        if v is not None:
            return v
    return default


def _normalize_tools(raw: list[Any]) -> list[McpTool]:
    return [McpTool(
        name=str(_getattr(t, "name", default="")),
        description=str(_getattr(t, "description", default="") or ""),
        input_schema=_getattr(t, "inputSchema", "input_schema", default=None) or {},
    ) for t in (raw or [])]


def _normalize_resources(raw: list[Any]) -> list[McpResource]:
    return [McpResource(
        uri=str(_getattr(r, "uri", default="")),
        name=str(_getattr(r, "name", default="") or ""),
        description=str(_getattr(r, "description", default="") or ""),
        mime_type=_getattr(r, "mimeType", "mime_type"),
    ) for r in (raw or [])]


def _normalize_prompts(raw: list[Any]) -> list[McpPrompt]:
    return [McpPrompt(
        name=str(_getattr(p, "name", default="")),
        description=str(_getattr(p, "description", default="") or ""),
        arguments=list(_getattr(p, "arguments", default=[]) or []),
    ) for p in (raw or [])]


class McpHandshakeError(RuntimeError):
    """The MCP ``initialize`` handshake failed — the endpoint is unreachable,
    rejected auth, or is not an MCP server. Distinct from a server that
    initializes cleanly but exposes zero tools (a legitimately empty scan)."""


async def enumerate_session(session: Any, *, transport: str, endpoint: str) -> McpManifest:
    """Given an initialized-or-initializable MCP ClientSession, enumerate it.

    Raises McpHandshakeError if ``initialize`` fails — callers must surface this
    as a scan error rather than silently grading an unreachable target clean."""
    server_name = server_version = None
    try:
        init = await session.initialize()
    except Exception as e:
        raise McpHandshakeError(
            f"MCP initialize handshake failed for {endpoint!r} over {transport}: {e}"
        ) from e
    info = _getattr(init, "serverInfo", "server_info")
    if info is not None:
        server_name = _getattr(info, "name")
        server_version = _getattr(info, "version")

    async def _safe(coro_name: str, attr: str) -> list[Any]:
        fn = getattr(session, coro_name, None)
        if fn is None:
            return []
        with contextlib.suppress(Exception):
            res = await fn()
            return _getattr(res, attr, default=[]) or []
        return []

    tools = _normalize_tools(await _safe("list_tools", "tools"))
    resources = _normalize_resources(await _safe("list_resources", "resources"))
    prompts = _normalize_prompts(await _safe("list_prompts", "prompts"))
    return McpManifest(
        transport=transport, endpoint=endpoint,
        server_name=server_name, server_version=server_version,
        tools=tools, resources=resources, prompts=prompts,
    )


from contextlib import asynccontextmanager


@asynccontextmanager
async def connect_session(cfg: dict, headers: dict | None = None):
    """Open the MCP transport for cfg.source_type and yield a live, initialized
    ClientSession (for dynamic tool invocation). Mirrors connect_and_enumerate's
    transport selection but yields the session instead of enumerating.

    ``headers`` carries the target's auth (e.g. Authorization / X-API-Key) for
    HTTP transports; ignored for stdio."""
    from mcp import ClientSession  # type: ignore

    st = cfg.get("source_type")
    if st == "mcp_stdio":
        from mcp import StdioServerParameters  # type: ignore
        from mcp.client.stdio import stdio_client  # type: ignore
        command = cfg["command"]
        params = StdioServerParameters(command=command[0], args=list(command[1:]),
                                       env=cfg.get("env") or None)
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                with contextlib.suppress(Exception):
                    await session.initialize()
                yield session
        return
    if st == "mcp_http":
        url = cfg["url"]
        transport = cfg.get("transport") or "sse"
        if transport == "streamable_http":
            from mcp.client.streamable_http import streamablehttp_client  # type: ignore
            async with streamablehttp_client(url, headers=headers or None) as (read, write, _):
                async with ClientSession(read, write) as session:
                    with contextlib.suppress(Exception):
                        await session.initialize()
                    yield session
            return
        from mcp.client.sse import sse_client  # type: ignore
        async with sse_client(url, headers=headers or None) as (read, write):
            async with ClientSession(read, write) as session:
                with contextlib.suppress(Exception):
                    await session.initialize()
                yield session
        return
    raise ValueError(f"connect_session: unsupported source_type {st!r}")


async def connect_and_enumerate(cfg: dict, headers: dict | None = None) -> McpManifest:
    """Open the right transport for cfg.source_type and enumerate.

    cfg is the McpConfig dict. ``headers`` carries the target's auth (e.g.
    Authorization / X-API-Key) for HTTP transports; ignored for stdio. SDK
    import paths verified against mcp>=1.23.0:
      mcp.client.stdio.stdio_client  -- yields (read, write)
      mcp.client.sse.sse_client      -- yields (read, write)
      mcp.client.streamable_http.streamablehttp_client -- yields (read, write, session_id_cb)
      mcp.ClientSession
      mcp.StdioServerParameters
    """
    from mcp import ClientSession  # type: ignore

    st = cfg.get("source_type")
    if st == "mcp_stdio":
        from mcp import StdioServerParameters  # type: ignore
        from mcp.client.stdio import stdio_client  # type: ignore
        command = cfg["command"]
        params = StdioServerParameters(command=command[0], args=list(command[1:]),
                                       env=cfg.get("env") or None)
        endpoint = "stdio:" + " ".join(command)
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                return await enumerate_session(session, transport="stdio", endpoint=endpoint)
    elif st == "mcp_http":
        url = cfg["url"]
        transport = cfg.get("transport") or "sse"
        if transport == "streamable_http":
            from mcp.client.streamable_http import streamablehttp_client  # type: ignore
            async with streamablehttp_client(url, headers=headers or None) as (read, write, _):
                async with ClientSession(read, write) as session:
                    return await enumerate_session(session, transport="streamable_http", endpoint=url)
        from mcp.client.sse import sse_client  # type: ignore
        async with sse_client(url, headers=headers or None) as (read, write):
            async with ClientSession(read, write) as session:
                return await enumerate_session(session, transport="sse", endpoint=url)
    raise ValueError(f"connect_and_enumerate: unsupported source_type {st!r} (agent_* sources use the LlmProbe path, Plan 3)")
