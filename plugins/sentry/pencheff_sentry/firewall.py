# SPDX-License-Identifier: AGPL-3.0-or-later
"""Agent firewall — tool/action policy enforcement.

Where :mod:`pencheff_sentry.core` decides whether prompt / response *text*
is safe, the firewall decides whether an agent *action* — a tool call the
model wants to make, or a tool *result* being fed back into context — is
permitted. Pure functions, no I/O (the same contract as ``core``), so the
hosted gateway and the embeddable SDK call the identical evaluator.

Enforcement-seam note (important — keeps value claims honest):
A chat-completions *gateway* sees tool calls only in the model's response
and tool results in the next request. It can refuse to forward a dangerous
tool call the model asked for, and it can gate data flowing back in tool
results — but it does NOT sit at the point of execution, so it cannot stop
an app from running a tool it never routed through the proxy. True
execution-time blocking belongs to the in-process SDK / sidecar, which
calls :func:`evaluate_tool_call` at the actual call site. Same function,
two seams: the gateway gates *intent + data flow*, the SDK gates *action*.
"""
from __future__ import annotations

import fnmatch
import json
import re
from dataclasses import dataclass, field
from enum import Enum


class Action(str, Enum):
    ALLOW = "allow"
    BLOCK = "block"
    REQUIRE_APPROVAL = "require_approval"  # hold for human confirmation
    REDACT_ARGS = "redact_args"            # forward, but scrub matched values


@dataclass
class FirewallDecision:
    action: Action
    rule_id: str | None = None
    reason: str = ""
    # {arg dotted-path: masked preview}; populated when action == REDACT_ARGS.
    redactions: dict[str, str] = field(default_factory=dict)
    risk_score: float = 0.0

    @classmethod
    def allow(cls) -> "FirewallDecision":
        return cls(action=Action.ALLOW, reason="default")

    @property
    def allowed(self) -> bool:
        """True when the call may proceed (possibly after redaction)."""
        return self.action in (Action.ALLOW, Action.REDACT_ARGS)


@dataclass(frozen=True)
class FirewallRule:
    """One match→action rule.

    A rule fires when *every* supplied condition holds. ``tools`` matches
    the tool name (fnmatch globs); ``arg_patterns`` are regexes tested
    against the stringified argument values. A rule with neither condition
    is a catch-all. For ``REDACT_ARGS`` the same ``arg_patterns`` both fire
    the rule and select which values get masked.
    """

    id: str
    action: Action
    reason: str = ""
    tools: tuple[str, ...] = ()
    arg_patterns: tuple[str, ...] = ()
    risk: float = 1.0


@dataclass(frozen=True)
class FirewallPolicy:
    rules: tuple[FirewallRule, ...]
    default_action: Action = Action.ALLOW


def _flatten_args(arguments: object) -> dict[str, str]:
    """Flatten (possibly nested, possibly JSON-string) tool arguments into
    ``{dotted.path: stringified value}`` for matching. Tool-call arguments
    arrive as a JSON string from OpenAI-shaped responses or as a dict from
    in-process callers — both normalise here."""
    if isinstance(arguments, str):
        try:
            arguments = json.loads(arguments)
        except (ValueError, TypeError):
            return {"": arguments}
    out: dict[str, str] = {}

    def walk(prefix: str, val: object) -> None:
        if isinstance(val, dict):
            for k, v in val.items():
                walk(f"{prefix}.{k}" if prefix else str(k), v)
        elif isinstance(val, (list, tuple)):
            for i, v in enumerate(val):
                walk(f"{prefix}[{i}]", v)
        else:
            out[prefix] = str(val)

    walk("", arguments)
    return out


def _rule_matches(rule: FirewallRule, tool_name: str, flat: dict[str, str]) -> bool:
    if rule.tools and not any(fnmatch.fnmatch(tool_name, g) for g in rule.tools):
        return False
    if rule.arg_patterns:
        haystack = "\n".join(flat.values())
        if not any(re.search(p, haystack) for p in rule.arg_patterns):
            return False
    return True


def _mask(value: str) -> str:
    return "***" if len(value) <= 8 else f"{value[:3]}***{value[-2:]}"


def evaluate_tool_call(
    policy: FirewallPolicy, tool_name: str, arguments: object,
) -> FirewallDecision:
    """Evaluate one tool call against ``policy``. First matching rule wins;
    no match → the policy's ``default_action``."""
    flat = _flatten_args(arguments)
    for rule in policy.rules:
        if not _rule_matches(rule, tool_name, flat):
            continue
        if rule.action == Action.REDACT_ARGS:
            redactions = {
                path: _mask(val)
                for path, val in flat.items()
                if any(re.search(p, val) for p in rule.arg_patterns)
            }
            return FirewallDecision(
                action=Action.REDACT_ARGS, rule_id=rule.id, reason=rule.reason,
                redactions=redactions, risk_score=rule.risk,
            )
        return FirewallDecision(
            action=rule.action, rule_id=rule.id, reason=rule.reason,
            risk_score=rule.risk,
        )
    return FirewallDecision(action=policy.default_action, reason="default")


def default_policy() -> FirewallPolicy:
    """A small, concrete starter policy. Intentionally narrow — high-signal
    rules only — so it's safe to ship default-on without drowning real
    agents in false positives. Workspaces extend it via stored config."""
    return FirewallPolicy(
        rules=(
            FirewallRule(
                id="ssrf-cloud-metadata",
                action=Action.BLOCK,
                reason="targets a cloud metadata endpoint (SSRF / credential theft)",
                arg_patterns=(
                    r"169\.254\.169\.254",
                    r"metadata\.google\.internal",
                    r"(?i)fd00:ec2::254",
                ),
            ),
            FirewallRule(
                id="sensitive-file-read",
                action=Action.BLOCK,
                reason="accesses a credential / secret file",
                arg_patterns=(
                    r"/etc/(?:shadow|passwd)\b",
                    r"(?:^|/)\.ssh/id_(?:rsa|ed25519|ecdsa)",
                    r"(?:^|/)\.aws/credentials\b",
                    r"(?:^|/)\.env(?:\.[\w.-]+)?\b",
                ),
            ),
            FirewallRule(
                id="destructive-shell",
                action=Action.BLOCK,
                reason="destructive or system-altering shell command",
                arg_patterns=(
                    r"(?i)\brm\s+-[a-z]*r[a-z]*f",
                    r"(?i)\bmkfs\b",
                    r"(?i)\bshred\b",
                    r"(?i)\bdd\s+if=",
                    r"(?i)\b(?:shutdown|reboot|halt)\b",
                    r">\s*/dev/sd[a-z]",
                ),
            ),
            FirewallRule(
                id="secret-in-args",
                action=Action.REDACT_ARGS,
                reason="argument carries a credential-like value",
                risk=0.5,
                arg_patterns=(
                    r"ghp_[A-Za-z0-9]{30,}",
                    r"\bAKIA[0-9A-Z]{16}\b",
                    r"\bsk-[A-Za-z0-9]{20,}",
                    r"xox[baprs]-[A-Za-z0-9-]{10,}",
                ),
            ),
        ),
    )
