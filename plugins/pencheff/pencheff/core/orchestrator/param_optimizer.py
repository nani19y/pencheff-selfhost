"""Per-tool CLI argument builder.

Reads ``parameters.yaml`` and returns the argv list for a tool given the
intensity tier (``stealth`` / ``default`` / ``aggressive``). The throttle
adapter may downgrade the tier when WAF / 429 signals appear.
"""

from __future__ import annotations

from pencheff.core.orchestrator.policies import Policies, load_policies


VALID_TIERS = ("stealth", "default", "aggressive")


class ParamOptimizer:
    def __init__(self, policies: Policies | None = None) -> None:
        self._policies = policies or load_policies()

    def args_for(
        self,
        tool: str,
        *,
        tier: str = "default",
        variant: str | None = None,
    ) -> list[str]:
        """Return the CLI args for ``tool`` at the requested ``tier``.

        ``variant`` selects an alternative key (e.g. ``"udp"`` for nmap),
        otherwise the named ``tier`` is used. Falls back to ``default`` when
        the requested tier is missing.
        """
        if tier not in VALID_TIERS:
            raise ValueError(f"unknown tier {tier!r}")
        tools = self._policies.parameters.get("tools", {})
        block = tools.get(tool, {}) or {}
        if variant and variant in block:
            return list(block[variant])
        if tier in block:
            return list(block[tier])
        if "default" in block:
            return list(block["default"])
        return []

    def downgrade_tier(self, tier: str) -> str:
        """Return the next-quieter tier (used by Throttle on 429/503)."""
        order = ("aggressive", "default", "stealth")
        if tier not in order:
            return "stealth"
        idx = order.index(tier)
        return order[min(idx + 1, len(order) - 1)]
