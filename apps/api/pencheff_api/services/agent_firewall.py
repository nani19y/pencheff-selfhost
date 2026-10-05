# SPDX-License-Identifier: AGPL-3.0-or-later
"""Per-target agent-firewall config + response tool-call gating.

The content guardrails (``services.guardrails``) decide whether prompt /
response *text* is safe. The firewall decides whether a *tool call* the
model wants to make is permitted. Config lives on
``Target.llm_config["firewall"]``:

    {
        "enabled": false,                  # default OFF — opt-in per target
        "default_action": "allow",         # action for unmatched tool calls
        "rules": [                          # optional, evaluated before defaults
            {"id": "no-prod-deletes", "action": "block",
             "tools": ["delete_*"], "arg_patterns": ["prod"]}
        ]
    }

When enabled, the proxy evaluates every ``tool_call`` the model returned
against ``pencheff_sentry.firewall.default_policy()`` + the custom rules:

  * BLOCK / REQUIRE_APPROVAL → the whole response is refused (403), so the
    calling app never receives the dangerous tool call.
  * REDACT_ARGS            → credential-shaped argument values are masked
    in place and the response is forwarded.

Enforcement-seam note: at the gateway this gates the model's *intent* to
call a tool — it cannot stop an app from executing a tool it never routed
through the proxy. Execution-time blocking is the in-process SDK's job,
which calls the same ``evaluate_tool_call``.
"""
from __future__ import annotations

import logging
import re
from typing import Any, Iterator

log = logging.getLogger("pencheff.agent_firewall")

# Actions an operator may pick in a custom rule / as the default action.
_VALID_ACTIONS = ("allow", "block", "require_approval", "redact_args")

# The always-on baseline rules (from default_policy()). Surfaced to the UI
# read-only so the operator can see what's enforced even with no custom
# rules. Custom rules are evaluated BEFORE these, so an allowlist rule can
# pre-empt one of them.
DEFAULT_RULES_META = (
    {"id": "ssrf-cloud-metadata", "action": "block",
     "reason": "targets a cloud metadata endpoint (SSRF / credential theft)"},
    {"id": "sensitive-file-read", "action": "block",
     "reason": "accesses a credential / secret file"},
    {"id": "destructive-shell", "action": "block",
     "reason": "destructive or system-altering shell command"},
    {"id": "secret-in-args", "action": "redact_args",
     "reason": "argument carries a credential-like value (masked, not blocked)"},
)


def default_firewall_config() -> dict[str, Any]:
    return {"enabled": False, "default_action": "allow", "rules": []}


def firewall_metadata() -> dict[str, Any]:
    """Static bits the UI needs to render the editor."""
    return {"actions": list(_VALID_ACTIONS), "default_rules": list(DEFAULT_RULES_META)}


def normalize_firewall_config(cfg: dict[str, Any] | None) -> dict[str, Any]:
    """Validate + coerce a config to the canonical shape.

    Raises ``ValueError`` on a bad action or a non-compiling regex so a
    broken rule is rejected at write time — the proxy must never hit a
    ``re.error`` at request time.
    """
    cfg = cfg or {}
    default_action = str(cfg.get("default_action") or "allow")
    if default_action not in _VALID_ACTIONS:
        raise ValueError(f"invalid default_action: {default_action!r}")

    out_rules: list[dict[str, Any]] = []
    for i, r in enumerate(cfg.get("rules") or []):
        if not isinstance(r, dict):
            raise ValueError(f"rule #{i + 1} must be an object")
        rid = str(r.get("id") or "").strip()
        if not rid:
            raise ValueError(f"rule #{i + 1} is missing an id")
        action = str(r.get("action") or "")
        if action not in _VALID_ACTIONS:
            raise ValueError(f"rule {rid!r} has invalid action {action!r}")
        tools = [str(t) for t in (r.get("tools") or []) if str(t).strip()]
        arg_patterns = [str(p) for p in (r.get("arg_patterns") or []) if str(p).strip()]
        for p in arg_patterns:
            try:
                re.compile(p)
            except re.error as exc:
                raise ValueError(f"rule {rid!r} has an invalid regex {p!r}: {exc}")
        if not tools and not arg_patterns:
            raise ValueError(
                f"rule {rid!r} must set at least one of tools / arg_patterns"
            )
        try:
            risk = float(r.get("risk", 1.0))
        except (TypeError, ValueError):
            risk = 1.0
        out_rules.append({
            "id": rid, "action": action, "reason": str(r.get("reason", "")),
            "tools": tools, "arg_patterns": arg_patterns, "risk": risk,
        })

    return {
        "enabled": bool(cfg.get("enabled")),
        "default_action": default_action,
        "rules": out_rules,
    }


def firewall_enabled(firewall_cfg: dict[str, Any] | None) -> bool:
    return bool((firewall_cfg or {}).get("enabled"))


def _build_policy(firewall_cfg: dict[str, Any] | None):
    """default_policy() rules + any operator custom rules. Custom rules go
    FIRST so an explicit allowlist can pre-empt a default block (first
    match wins)."""
    from pencheff_sentry.firewall import (
        Action,
        FirewallPolicy,
        FirewallRule,
        default_policy,
    )

    custom: list = []
    for r in (firewall_cfg or {}).get("rules") or []:
        if not isinstance(r, dict) or not r.get("id") or not r.get("action"):
            continue
        try:
            action = Action(str(r["action"]))
        except ValueError:
            continue
        custom.append(
            FirewallRule(
                id=str(r["id"]),
                action=action,
                reason=str(r.get("reason", "")),
                tools=tuple(str(t) for t in (r.get("tools") or [])),
                arg_patterns=tuple(str(p) for p in (r.get("arg_patterns") or [])),
                risk=float(r.get("risk", 1.0)),
            )
        )
    try:
        default_action = Action(str((firewall_cfg or {}).get("default_action") or "allow"))
    except ValueError:
        default_action = Action.ALLOW
    return FirewallPolicy(
        rules=tuple(custom) + default_policy().rules,
        default_action=default_action,
    )


def _iter_response_tool_calls(
    payload: dict[str, Any],
) -> Iterator[tuple[str, object, dict[str, Any]]]:
    """Yield ``(name, arguments, tool_call_dict)`` for every tool call the
    model returned. OpenAI shape: ``choices[].message.tool_calls[].function
    .{name, arguments}`` (``arguments`` is a JSON string)."""
    for choice in payload.get("choices") or []:
        msg = (choice or {}).get("message") or {}
        for tc in msg.get("tool_calls") or []:
            fn = (tc or {}).get("function") or {}
            yield fn.get("name") or "", fn.get("arguments"), tc


def _redact_arguments(arguments: object, patterns: tuple[str, ...]) -> object:
    """Mask credential-shaped substrings in a tool call's argument string.
    Operates on the raw JSON-string form (OpenAI shape); leaves non-string
    arguments untouched."""
    if not isinstance(arguments, str):
        return arguments
    out = arguments
    for p in patterns:
        out = re.sub(p, "[REDACTED]", out)
    return out


def gate_response_tool_calls(
    payload: dict[str, Any], *, firewall_cfg: dict[str, Any] | None,
) -> dict[str, Any] | None:
    """Evaluate the model's tool calls. Returns a block-decision dict (shape
    matching ``services.guardrails``) when a call is blocked or needs
    approval; otherwise ``None``. Mutates ``payload`` in place to apply
    REDACT_ARGS masking."""
    try:
        from pencheff_sentry.firewall import Action, evaluate_tool_call
    except ImportError:
        # The firewall is ENABLED on this target but its engine is missing
        # from the image — this is a fail-open security gap, not a normal
        # path. Make it loud so it's caught in logs rather than silently
        # allowing every tool call.
        log.error(
            "agent firewall ENABLED but pencheff_sentry.firewall is not "
            "importable — tool calls are NOT being gated (failing open). "
            "Ensure plugins/sentry is installed in the API image."
        )
        return None

    policy = _build_policy(firewall_cfg)
    rule_patterns = {r.id: r.arg_patterns for r in policy.rules}

    for name, arguments, tc in _iter_response_tool_calls(payload):
        decision = evaluate_tool_call(policy, name, arguments)
        if decision.action in (Action.BLOCK, Action.REQUIRE_APPROVAL):
            verb = (
                "requires human approval"
                if decision.action == Action.REQUIRE_APPROVAL
                else "blocked by the agent firewall"
            )
            reason = f"tool call {name!r} {verb}"
            if decision.reason:
                reason += f": {decision.reason}"
            return {
                "verdict": "block",
                "category": "LLM06",  # Excessive Agency
                "detector": f"firewall:{decision.rule_id or 'default'}",
                "reason": reason,
            }
        if decision.action == Action.REDACT_ARGS and isinstance(tc.get("function"), dict):
            tc["function"]["arguments"] = _redact_arguments(
                tc["function"].get("arguments"),
                rule_patterns.get(decision.rule_id or "", ()),
            )
    return None
