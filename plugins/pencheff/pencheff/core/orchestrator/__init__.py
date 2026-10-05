"""Deterministic pentest orchestrator.

Drives a full engagement end-to-end via a finite-state machine + decision
tables. No language model in the loop — every choice is a YAML lookup.

Public entry points:

- ``Orchestrator(session).run(profile, target, objective)``
- ``select_tool(profile, objective) -> [Candidate]``
- ``optimize_params(tool, profile_tier, throttle_state) -> [str]``
- ``plan_chains(findings) -> [ChainPlan]``
"""

from pencheff.core.orchestrator.cache import OrchestratorCache
from pencheff.core.orchestrator.chain_planner import ChainPlan, ChainPlanner
from pencheff.core.orchestrator.engine import Orchestrator
from pencheff.core.orchestrator.fallback import FallbackResolver
from pencheff.core.orchestrator.param_optimizer import ParamOptimizer
from pencheff.core.orchestrator.policies import Policies, load_policies
from pencheff.core.orchestrator.rng import deterministic_rng
from pencheff.core.orchestrator.selector import Selector, ToolCandidate
from pencheff.core.orchestrator.state_machine import EngagementPhase, StateMachine
from pencheff.core.orchestrator.throttle import Throttle, ThrottleState

__all__ = [
    "Orchestrator",
    "OrchestratorCache",
    "ChainPlan",
    "ChainPlanner",
    "EngagementPhase",
    "FallbackResolver",
    "ParamOptimizer",
    "Policies",
    "Selector",
    "StateMachine",
    "Throttle",
    "ThrottleState",
    "ToolCandidate",
    "deterministic_rng",
    "load_policies",
]
