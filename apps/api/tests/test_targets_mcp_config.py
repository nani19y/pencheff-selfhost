# apps/api/tests/test_targets_mcp_config.py
"""Validation tests for the McpConfig kind_config variant."""
from __future__ import annotations

import pytest
from pydantic import ValidationError, TypeAdapter

from pencheff_api.schemas.targets import KindConfig

_adapter = TypeAdapter(KindConfig)


def _parse(data: dict):
    return _adapter.validate_python(data)


def _parse_agent(data: dict):
    """Parse an agent kind_config (source_type agent_http/agent_browser)."""
    return _adapter.validate_python(data)


def test_mcp_http_requires_url_and_transport():
    ok = _parse({"kind": "mcp", "source_type": "mcp_http",
                 "url": "https://mcp.example.com/sse", "transport": "sse"})
    assert ok.source_type == "mcp_http"
    with pytest.raises(ValidationError):
        _parse({"kind": "mcp", "source_type": "mcp_http"})  # no url/transport


def test_mcp_stdio_requires_command():
    ok = _parse({"kind": "mcp", "source_type": "mcp_stdio",
                 "command": ["npx", "some-mcp-server"]})
    assert ok.command == ["npx", "some-mcp-server"]
    with pytest.raises(ValidationError):
        _parse({"kind": "mcp", "source_type": "mcp_stdio"})  # no command


def test_agent_http_requires_provider():
    # agent_http/agent_browser now live under kind="agent" (AgentConfig), not kind="mcp"
    ok = _parse_agent({"kind": "agent", "source_type": "agent_http", "provider": "openai-chat",
                       "url": "https://api.openai.com/v1/chat/completions"})
    assert ok.provider == "openai-chat"
    with pytest.raises(ValidationError):
        _parse_agent({"kind": "agent", "source_type": "agent_http"})  # no provider
    # openai-chat with no url is rejected (would otherwise use agent:// → HTTP 0)
    with pytest.raises(ValidationError):
        _parse_agent({"kind": "agent", "source_type": "agent_http", "provider": "openai-chat"})


def test_agent_browser_requires_url_and_selectors():
    # agent_http/agent_browser now live under kind="agent" (AgentConfig), not kind="mcp"
    ok = _parse_agent({"kind": "agent", "source_type": "agent_browser",
                       "url": "https://agent.example.com",
                       "prompt_selector": "#in", "send_selector": "#go",
                       "response_selector": "#out"})
    assert ok.prompt_selector == "#in"
    with pytest.raises(ValidationError):
        _parse_agent({"kind": "agent", "source_type": "agent_browser",
                      "url": "https://agent.example.com"})  # missing selectors


def test_destructive_defaults_false_and_extra_forbidden():
    cfg = _parse({"kind": "mcp", "source_type": "mcp_stdio", "command": ["x"]})
    assert cfg.dynamic_invocation is False
    assert cfg.destructive_opt_in is False
    with pytest.raises(ValidationError):
        _parse({"kind": "mcp", "source_type": "mcp_stdio", "command": ["x"],
                "bogus_field": 1})  # extra="forbid" inherited from _KindConfigBase


def test_agent_http_custom_provider_requires_template_and_path():
    # agent_http now lives under kind="agent" (AgentConfig), not kind="mcp"
    with pytest.raises(ValidationError):
        _parse_agent({"kind": "agent", "source_type": "agent_http", "provider": "custom"})
    ok = _parse_agent({"kind": "agent", "source_type": "agent_http", "provider": "custom",
                       "url": "https://api.example.com/v1/chat/completions",
                       "request_template": "{\"q\":\"{{prompt}}\"}", "response_path": "$.a"})
    assert ok.provider == "custom"


def test_tool_allow_deny_overlap_rejected():
    with pytest.raises(ValidationError):
        _parse({"kind": "mcp", "source_type": "mcp_stdio", "command": ["x"],
                "tool_allowlist": ["a", "b"], "tool_denylist": ["b"]})


def test_destructive_requires_dynamic_invocation():
    with pytest.raises(ValidationError):
        _parse({"kind": "mcp", "source_type": "mcp_stdio", "command": ["x"],
                "destructive_opt_in": True})  # dynamic_invocation defaults False
    ok = _parse({"kind": "mcp", "source_type": "mcp_stdio", "command": ["x"],
                 "dynamic_invocation": True, "destructive_opt_in": True})
    assert ok.destructive_opt_in is True
