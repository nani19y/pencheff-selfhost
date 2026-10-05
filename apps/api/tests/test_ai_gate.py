from pencheff_api.services.ai_gate import AI_PLANS, plan_has_ai


def test_free_plan_does_not_have_ai() -> None:
    assert plan_has_ai("free") is False


def test_unknown_or_missing_plan_defaults_to_free() -> None:
    assert plan_has_ai(None) is False
    assert plan_has_ai("") is False
    assert plan_has_ai("starter") is False


def test_paid_and_self_hosted_plans_have_ai() -> None:
    for plan in ("pro", "team", "self_hosted"):
        assert plan_has_ai(plan) is True


def test_ai_plans_set_matches_documented_tiers() -> None:
    assert AI_PLANS == frozenset({"pro", "team", "self_hosted"})
