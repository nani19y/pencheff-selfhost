"""ChainPlanner matches preconditions deterministically."""

from __future__ import annotations

from dataclasses import dataclass, field

from pencheff.core.orchestrator.chain_planner import ChainPlanner


@dataclass
class FakeFinding:
    id: str
    finding_type: str
    attributes: dict = field(default_factory=dict)


def test_ssrf_matches_chain():
    planner = ChainPlanner()
    plans = planner.plan([FakeFinding(id="f1", finding_type="ssrf")])
    chain_ids = [p.id for p in plans]
    assert "ssrf_to_iam" in chain_ids


def test_no_match_when_precondition_missing():
    planner = ChainPlanner()
    plans = planner.plan([FakeFinding(id="f1", finding_type="info_disclosure")])
    assert all(p.id != "ssrf_to_iam" for p in plans)


def test_multi_precondition_chain_requires_all():
    planner = ChainPlanner()
    plans = planner.plan([FakeFinding(id="f1", finding_type="open_redirect")])
    chain_ids = [p.id for p in plans]
    assert "oauth_takeover" not in chain_ids

    plans = planner.plan(
        [
            FakeFinding(id="f1", finding_type="open_redirect"),
            FakeFinding(id="f2", finding_type="oauth_endpoint_present"),
        ]
    )
    chain_ids = [p.id for p in plans]
    assert "oauth_takeover" in chain_ids


def test_severity_sort_critical_first():
    planner = ChainPlanner()
    plans = planner.plan(
        [
            FakeFinding(id="f1", finding_type="ssrf"),
            FakeFinding(id="f2", finding_type="idor", attributes={"numeric_id": True}),
        ]
    )
    severities = [p.severity for p in plans]
    # Critical should come before high in the output order.
    if "critical" in severities and "high" in severities:
        assert severities.index("critical") < severities.index("high")


def test_attribute_required_for_match():
    planner = ChainPlanner()
    # idor without numeric_id attribute should not match idor_privesc
    plans = planner.plan([FakeFinding(id="f1", finding_type="idor")])
    assert all(p.id != "idor_privesc" for p in plans)

    plans = planner.plan(
        [FakeFinding(id="f1", finding_type="idor", attributes={"numeric_id": True})]
    )
    assert any(p.id == "idor_privesc" for p in plans)


def test_deterministic_ordering_across_runs():
    planner = ChainPlanner()
    findings = [FakeFinding(id="f1", finding_type="ssrf")]
    a = [p.id for p in planner.plan(findings)]
    b = [p.id for p in planner.plan(findings)]
    assert a == b
