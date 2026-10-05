"""Golden-trace test for the engagement state machine."""

from __future__ import annotations

from pencheff.core.orchestrator.state_machine import (
    EngagementPhase,
    PHASE_ORDER,
    StateMachine,
    StateMachineContext,
)


def test_phases_run_in_order():
    sm = StateMachine()
    log: list[str] = []
    for phase in PHASE_ORDER:
        sm.register(phase, lambda _ctx, p=phase: log.append(p.value) or {})
    ctx = StateMachineContext(target="t", target_profile="web")
    sm.run(ctx)
    assert log == [p.value for p in PHASE_ORDER]


def test_unregistered_phase_is_skipped():
    sm = StateMachine()
    sm.register(EngagementPhase.SCOPE, lambda _c: {})
    sm.register(EngagementPhase.RECON_PASSIVE, lambda _c: {})
    ctx = StateMachineContext(target="t", target_profile="web")
    sm.run(ctx)
    skipped = [t for t in ctx.transitions if t.skipped]
    assert any(t.phase == EngagementPhase.RECON_ACTIVE for t in skipped)


def test_precondition_skip():
    sm = StateMachine()
    sm.register(EngagementPhase.SCOPE, lambda _c: {})
    sm.register(
        EngagementPhase.RECON_PASSIVE,
        lambda _c: {"actions": ["should-not-run"]},
        precondition=lambda _c: False,
    )
    ctx = StateMachineContext(target="t", target_profile="web")
    sm.run(ctx)
    skipped = next(t for t in ctx.transitions if t.phase == EngagementPhase.RECON_PASSIVE)
    assert skipped.skipped
    assert skipped.skip_reason == "precondition not met"


def test_cancel_short_circuits_remaining_phases():
    sm = StateMachine()

    def cancel_handler(ctx):
        ctx.cancelled = True
        ctx.cancel_reason = "out of scope"
        return {}

    sm.register(EngagementPhase.SCOPE, cancel_handler)
    for phase in PHASE_ORDER[1:]:
        sm.register(phase, lambda _c: {"actions": ["ran"]})
    ctx = StateMachineContext(target="t", target_profile="web")
    sm.run(ctx)
    later = [t for t in ctx.transitions if t.phase != EngagementPhase.SCOPE]
    # All later phases are skipped with the cancel reason.
    assert all(
        t.skipped and t.skip_reason == "out of scope"
        for t in later
        if t.phase != EngagementPhase.DONE
    )
