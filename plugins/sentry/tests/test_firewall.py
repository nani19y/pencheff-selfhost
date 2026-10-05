# SPDX-License-Identifier: AGPL-3.0-or-later
"""Unit tests for the agent firewall policy engine (pure, no I/O)."""
from __future__ import annotations

from pencheff_sentry.firewall import (
    Action,
    FirewallPolicy,
    FirewallRule,
    default_policy,
    evaluate_tool_call,
)


# ── default policy: high-signal blocks ──────────────────────────────

def test_default_allows_a_benign_call():
    d = evaluate_tool_call(default_policy(), "http_get", {"url": "https://api.example.com/v1/users"})
    assert d.action == Action.ALLOW
    assert d.allowed is True


def test_blocks_cloud_metadata_ssrf():
    d = evaluate_tool_call(default_policy(), "http_get", {"url": "http://169.254.169.254/latest/meta-data/iam/"})
    assert d.action == Action.BLOCK
    assert d.rule_id == "ssrf-cloud-metadata"
    assert d.allowed is False


def test_blocks_gcp_metadata_hostname():
    d = evaluate_tool_call(default_policy(), "fetch", {"url": "http://metadata.google.internal/computeMetadata/v1/"})
    assert d.action == Action.BLOCK
    assert d.rule_id == "ssrf-cloud-metadata"


def test_blocks_sensitive_file_read():
    for path in ("/etc/shadow", "/home/u/.ssh/id_rsa", "/root/.aws/credentials", "/srv/app/.env.production"):
        d = evaluate_tool_call(default_policy(), "read_file", {"path": path})
        assert d.action == Action.BLOCK, path
        assert d.rule_id == "sensitive-file-read", path


def test_blocks_destructive_shell():
    for cmd in ("rm -rf /", "sudo rm -Rf ~", "dd if=/dev/zero of=/dev/sda", "shutdown -h now"):
        d = evaluate_tool_call(default_policy(), "bash", {"command": cmd})
        assert d.action == Action.BLOCK, cmd
        assert d.rule_id == "destructive-shell", cmd


def test_normal_shell_is_allowed():
    d = evaluate_tool_call(default_policy(), "bash", {"command": "ls -la && git status"})
    assert d.action == Action.ALLOW


# ── redaction (forward but scrub) ───────────────────────────────────

def test_redacts_secret_in_args_but_allows():
    d = evaluate_tool_call(
        default_policy(), "send_webhook",
        {"token": "ghp_" + "a" * 36, "channel": "ops"},
    )
    assert d.action == Action.REDACT_ARGS
    assert d.rule_id == "secret-in-args"
    assert d.allowed is True                      # forwarded, not blocked
    assert "token" in d.redactions
    assert d.redactions["token"].startswith("ghp") and "***" in d.redactions["token"]
    assert "channel" not in d.redactions          # only the secret value is masked


def test_redacts_aws_key():
    d = evaluate_tool_call(default_policy(), "deploy", {"key": "AKIAIOSFODNN7EXAMPLE"})
    assert d.action == Action.REDACT_ARGS
    assert "key" in d.redactions


# ── matching mechanics ──────────────────────────────────────────────

def test_tool_glob_and_require_approval():
    policy = FirewallPolicy(rules=(
        FirewallRule(id="guard-deletes", action=Action.REQUIRE_APPROVAL,
                     reason="destructive op needs human sign-off", tools=("delete_*", "drop_*")),
    ))
    d = evaluate_tool_call(policy, "delete_user", {"id": "42"})
    assert d.action == Action.REQUIRE_APPROVAL
    assert d.allowed is False
    # non-matching tool falls through to default ALLOW
    assert evaluate_tool_call(policy, "get_user", {"id": "42"}).action == Action.ALLOW


def test_json_string_arguments_are_parsed():
    # OpenAI-shaped tool calls deliver arguments as a JSON string.
    d = evaluate_tool_call(default_policy(), "http_get", '{"url": "http://169.254.169.254/"}')
    assert d.action == Action.BLOCK
    assert d.rule_id == "ssrf-cloud-metadata"


def test_nested_arguments_are_flattened_and_matched():
    d = evaluate_tool_call(default_policy(), "batch", {"requests": [{"target": "/etc/shadow"}]})
    assert d.action == Action.BLOCK
    assert d.rule_id == "sensitive-file-read"


def test_first_matching_rule_wins():
    policy = FirewallPolicy(rules=(
        FirewallRule(id="allowlist-internal", action=Action.ALLOW, tools=("http_get",),
                     arg_patterns=(r"internal\.corp",)),
        FirewallRule(id="block-all-http", action=Action.BLOCK, tools=("http_get",)),
    ))
    assert evaluate_tool_call(policy, "http_get", {"url": "https://internal.corp/x"}).action == Action.ALLOW
    assert evaluate_tool_call(policy, "http_get", {"url": "https://evil.example/x"}).action == Action.BLOCK


def test_default_action_can_be_deny():
    policy = FirewallPolicy(
        rules=(FirewallRule(id="allow-read", action=Action.ALLOW, tools=("read_*",)),),
        default_action=Action.BLOCK,
    )
    assert evaluate_tool_call(policy, "read_file", {"path": "a.txt"}).action == Action.ALLOW
    assert evaluate_tool_call(policy, "write_file", {"path": "a.txt"}).action == Action.BLOCK
