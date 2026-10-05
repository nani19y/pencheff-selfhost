"""Gateway-side agent-firewall: response tool-call gating + redaction.

Pure functions (no DB / no network). Requires ``pencheff_sentry`` on the
path — run with ``PYTHONPATH`` including ``plugins/sentry`` (the Docker
image installs it; CI/local mirror that)."""
from __future__ import annotations

import json

import pytest

from pencheff_api.services.agent_firewall import (
    default_firewall_config,
    firewall_enabled,
    firewall_metadata,
    gate_response_tool_calls,
    normalize_firewall_config,
)


def _resp(tool_name: str, arguments) -> dict:
    """An OpenAI chat-completion response carrying one tool call."""
    if not isinstance(arguments, str):
        arguments = json.dumps(arguments)
    return {
        "choices": [
            {
                "message": {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [
                        {"id": "call_1", "type": "function",
                         "function": {"name": tool_name, "arguments": arguments}},
                    ],
                }
            }
        ]
    }


def test_firewall_enabled_flag():
    assert firewall_enabled({"enabled": True}) is True
    assert firewall_enabled({"enabled": False}) is False
    assert firewall_enabled({}) is False
    assert firewall_enabled(None) is False


def test_benign_tool_call_passes():
    payload = _resp("http_get", {"url": "https://api.example.com/users"})
    assert gate_response_tool_calls(payload, firewall_cfg={"enabled": True}) is None


def test_no_tool_calls_passes():
    payload = {"choices": [{"message": {"role": "assistant", "content": "hi"}}]}
    assert gate_response_tool_calls(payload, firewall_cfg={"enabled": True}) is None


def test_blocks_ssrf_metadata_tool_call():
    payload = _resp("http_get", {"url": "http://169.254.169.254/latest/meta-data/"})
    decision = gate_response_tool_calls(payload, firewall_cfg={"enabled": True})
    assert decision is not None
    assert decision["verdict"] == "block"
    assert decision["category"] == "LLM06"
    assert decision["detector"] == "firewall:ssrf-cloud-metadata"


def test_redacts_secret_in_tool_args_and_forwards():
    secret = "ghp_" + "b" * 36
    payload = _resp("send_message", {"token": secret, "to": "ops"})
    decision = gate_response_tool_calls(payload, firewall_cfg={"enabled": True})
    assert decision is None  # forwarded, not blocked
    forwarded_args = payload["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"]
    assert secret not in forwarded_args
    assert "[REDACTED]" in forwarded_args
    assert "ops" in forwarded_args  # non-secret arg preserved


def test_custom_require_approval_rule():
    cfg = {
        "enabled": True,
        "rules": [
            {"id": "guard-deletes", "action": "require_approval",
             "tools": ["delete_*"], "reason": "destructive op"},
        ],
    }
    payload = _resp("delete_user", {"id": "42"})
    decision = gate_response_tool_calls(payload, firewall_cfg=cfg)
    assert decision is not None
    assert decision["detector"] == "firewall:guard-deletes"
    assert "approval" in decision["reason"]


def test_custom_allowlist_preempts_default_block():
    # A custom ALLOW rule placed before defaults lets an operator
    # whitelist an otherwise-blocked destination (first match wins).
    cfg = {
        "enabled": True,
        "rules": [
            {"id": "allow-internal-metadata", "action": "allow",
             "tools": ["http_get"], "arg_patterns": ["169\\.254\\.169\\.254"]},
        ],
    }
    payload = _resp("http_get", {"url": "http://169.254.169.254/ok"})
    assert gate_response_tool_calls(payload, firewall_cfg=cfg) is None


def test_invalid_custom_rule_is_ignored():
    cfg = {"enabled": True, "rules": [{"id": "x", "action": "not-an-action"}]}
    # Bad rule dropped; defaults still apply → SSRF still blocked.
    payload = _resp("http_get", {"url": "http://169.254.169.254/"})
    decision = gate_response_tool_calls(payload, firewall_cfg=cfg)
    assert decision is not None
    assert decision["detector"] == "firewall:ssrf-cloud-metadata"


# ── config normalizer (write-time validation) ───────────────────────

def test_default_config_is_disabled():
    cfg = default_firewall_config()
    assert cfg == {"enabled": False, "default_action": "allow", "rules": []}


def test_metadata_lists_actions_and_default_rules():
    md = firewall_metadata()
    assert set(md["actions"]) == {"allow", "block", "require_approval", "redact_args"}
    ids = {r["id"] for r in md["default_rules"]}
    assert "ssrf-cloud-metadata" in ids and "secret-in-args" in ids


def test_normalize_accepts_and_canonicalizes_a_valid_config():
    cfg = normalize_firewall_config({
        "enabled": True,
        "default_action": "allow",
        "rules": [
            {"id": "no-prod-delete", "action": "block",
             "tools": ["delete_*"], "arg_patterns": ["prod"], "reason": "x"},
        ],
    })
    assert cfg["enabled"] is True
    assert cfg["rules"][0]["id"] == "no-prod-delete"
    assert cfg["rules"][0]["arg_patterns"] == ["prod"]


def test_normalize_rejects_bad_action():
    with pytest.raises(ValueError):
        normalize_firewall_config({"rules": [{"id": "r", "action": "nope", "tools": ["x"]}]})


def test_normalize_rejects_uncompilable_regex():
    with pytest.raises(ValueError):
        normalize_firewall_config({"rules": [{"id": "r", "action": "block", "arg_patterns": ["("]}]})


def test_normalize_rejects_rule_without_match_conditions():
    with pytest.raises(ValueError):
        normalize_firewall_config({"rules": [{"id": "r", "action": "block"}]})


def test_normalize_rejects_bad_default_action():
    with pytest.raises(ValueError):
        normalize_firewall_config({"default_action": "destroy"})
