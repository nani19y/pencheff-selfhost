# pencheff/modules/mcp_scan/manifest.py
"""Normalized, transport-agnostic representation of an MCP server's surface.

The protocol client (client.py) populates these from any transport; the static
analyzers (static_analyzers.py) consume ONLY these, so analyzers are pure and
testable without a live server.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class McpTool:
    name: str
    description: str = ""
    input_schema: dict[str, Any] = field(default_factory=dict)


@dataclass
class McpResource:
    uri: str
    name: str = ""
    description: str = ""
    mime_type: str | None = None


@dataclass
class McpPrompt:
    name: str
    description: str = ""
    arguments: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class McpManifest:
    transport: str  # "stdio" | "sse" | "streamable_http"
    server_name: str | None = None
    server_version: str | None = None
    tools: list[McpTool] = field(default_factory=list)
    resources: list[McpResource] = field(default_factory=list)
    prompts: list[McpPrompt] = field(default_factory=list)
    endpoint: str = ""
