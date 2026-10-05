"""Engagement finite-state machine.

Phases run in order; each phase has a ``precondition`` callable, an ``action``
callable, and a ``postcondition`` callable. Transitions are recorded so
golden-trace tests can assert that an unchanged policy + unchanged target
produce the same trace twice.

The state machine itself is dumb — it doesn't know about HTTP or
subprocess. It calls the engine's phase callbacks. That keeps unit tests
clean: replace the callbacks with stubs and the machine is fully testable.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class EngagementPhase(str, Enum):
    SCOPE = "scope"
    RECON_PASSIVE = "recon_passive"
    RECON_ACTIVE = "recon_active"
    AUTH = "auth"
    SURFACE_MAP = "surface_map"
    VULN_PROBE = "vuln_probe"
    EXPLOIT = "exploit"
    POST_EX = "post_ex"
    REPORT = "report"
    DONE = "done"


PHASE_ORDER: tuple[EngagementPhase, ...] = (
    EngagementPhase.SCOPE,
    EngagementPhase.RECON_PASSIVE,
    EngagementPhase.RECON_ACTIVE,
    EngagementPhase.AUTH,
    EngagementPhase.SURFACE_MAP,
    EngagementPhase.VULN_PROBE,
    EngagementPhase.EXPLOIT,
    EngagementPhase.POST_EX,
    EngagementPhase.REPORT,
)


@dataclass
class Transition:
    phase: EngagementPhase
    skipped: bool = False
    skip_reason: str = ""
    actions: list[str] = field(default_factory=list)
    findings_added: int = 0
    duration_ms: float = 0.0


PhaseFn = Callable[["StateMachineContext"], dict[str, Any]]


@dataclass
class StateMachineContext:
    """State carried between phases. Engine subclasses extend this."""

    target: str
    target_profile: str
    intensity: str = "default"
    findings: list[Any] = field(default_factory=list)
    artefacts: dict[str, Any] = field(default_factory=dict)
    transitions: list[Transition] = field(default_factory=list)
    cancelled: bool = False
    cancel_reason: str = ""


class StateMachine:
    """Drives PHASE_ORDER, calling the registered handler per phase."""

    def __init__(self) -> None:
        self._handlers: dict[EngagementPhase, PhaseFn] = {}
        self._preconds: dict[EngagementPhase, Callable[[StateMachineContext], bool]] = {}

    def register(
        self,
        phase: EngagementPhase,
        handler: PhaseFn,
        *,
        precondition: Callable[[StateMachineContext], bool] | None = None,
    ) -> None:
        self._handlers[phase] = handler
        if precondition:
            self._preconds[phase] = precondition

    def run(self, ctx: StateMachineContext) -> StateMachineContext:
        import time

        for phase in PHASE_ORDER:
            if ctx.cancelled:
                ctx.transitions.append(
                    Transition(
                        phase=phase, skipped=True, skip_reason=ctx.cancel_reason
                    )
                )
                continue

            handler = self._handlers.get(phase)
            if not handler:
                ctx.transitions.append(
                    Transition(
                        phase=phase,
                        skipped=True,
                        skip_reason="no handler registered",
                    )
                )
                continue

            cond = self._preconds.get(phase)
            if cond and not cond(ctx):
                ctx.transitions.append(
                    Transition(
                        phase=phase,
                        skipped=True,
                        skip_reason="precondition not met",
                    )
                )
                continue

            t0 = time.monotonic()
            before = len(ctx.findings)
            result = handler(ctx) or {}
            duration = (time.monotonic() - t0) * 1000.0
            ctx.transitions.append(
                Transition(
                    phase=phase,
                    actions=list(result.get("actions", [])),
                    findings_added=len(ctx.findings) - before,
                    duration_ms=duration,
                )
            )

        ctx.transitions.append(Transition(phase=EngagementPhase.DONE))
        return ctx
