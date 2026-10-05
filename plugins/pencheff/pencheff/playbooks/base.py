"""Playbook ABC + RunResult.

Each of the 28 specialist playbooks subclasses :class:`Playbook` and
implements ``run`` (async). The orchestrator (`swarm_orchestrator`) reads
class attributes (tier, phase, noise, mitre, handoff_to) to build a phase
DAG before any code runs.

Tier 1 playbooks must not invoke ``tool_runner`` or any module that does
network egress beyond DNS resolution; this is enforced via the
:func:`pencheff.core.tier.tier_1` / ``tier_2`` decorators on ``run``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, ClassVar, Literal, Optional


Phase = Literal["scope", "recon", "vuln", "exploit", "postex", "detect", "report"]
Noise = Literal["quiet", "moderate", "loud"]


@dataclass
class RunResult:
    playbook: str
    summary: str = ""
    findings_added: int = 0
    actions: list[dict[str, Any]] = field(default_factory=list)
    handoffs: list[str] = field(default_factory=list)
    artifacts: dict[str, Any] = field(default_factory=dict)
    error: str | None = None


class Playbook:
    """Specialist playbook ABC."""

    name: ClassVar[str] = ""
    tier: ClassVar[int] = 1                    # 1 = advisory, 2 = execution
    phase: ClassVar[Phase] = "recon"
    noise: ClassVar[Noise] = "moderate"
    mitre: ClassVar[list[str]] = []            # technique IDs implemented
    handoff_to: ClassVar[list[str]] = []       # downstream playbook names
    requires_scope: ClassVar[bool] = True

    description: ClassVar[str] = ""

    async def run(
        self,
        session: Any,
        eng_db: Any,
        engagement_id: Optional[str] = None,
        **kwargs: Any,
    ) -> RunResult:                              # pragma: no cover
        raise NotImplementedError

    def _log(
        self,
        eng_db: Any,
        engagement_id: Optional[str],
        action: str,
        summary: str = "",
        detail: Any = None,
    ) -> None:
        if eng_db and engagement_id:
            eng_db.log(engagement_id, agent=self.name, action=action,
                       summary=summary, detail=detail)
