"""ParamOptimizer returns CLI args per tool/tier."""

from __future__ import annotations

import pytest

from pencheff.core.orchestrator.param_optimizer import ParamOptimizer


def test_nmap_default_returns_argv():
    p = ParamOptimizer()
    args = p.args_for("nmap", tier="default")
    assert "-sS" in args
    assert "-sV" in args


def test_nmap_stealth_quieter_than_aggressive():
    p = ParamOptimizer()
    stealth = p.args_for("nmap", tier="stealth")
    aggressive = p.args_for("nmap", tier="aggressive")
    # Stealth should be a subset of "smaller scope" — at minimum contains -T2
    assert "-T2" in stealth
    assert "-T4" in aggressive


def test_unknown_tool_returns_empty_list():
    p = ParamOptimizer()
    assert p.args_for("not_a_real_tool") == []


def test_unknown_tier_raises():
    p = ParamOptimizer()
    with pytest.raises(ValueError):
        p.args_for("nmap", tier="nuclear")


def test_variant_overrides_tier():
    p = ParamOptimizer()
    udp = p.args_for("nmap", variant="udp")
    assert "-sU" in udp


def test_downgrade_tier():
    p = ParamOptimizer()
    assert p.downgrade_tier("aggressive") == "default"
    assert p.downgrade_tier("default") == "stealth"
    assert p.downgrade_tier("stealth") == "stealth"
