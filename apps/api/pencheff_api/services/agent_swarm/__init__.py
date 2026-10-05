"""Parallel multi-agent scan swarm.

See docs/superpowers/specs/2026-05-05-parallel-agent-swarm-design.md
for the design and IP-safety contract.

Manual smoke checklist (operations):
  1. SWARM_ENABLED=true: run a scan against DVWA / Juice-Shop. Confirm
     the SSE event log shows interleaved [Recon]…[InjectionAgent]…
     [AuthAgent]…[Chain]… prefixes.
  2. Force a recon failure (set AGENT_LLM_API_KEY to something that
     401s). Confirm the catastrophic-fallback line appears and the scan
     finishes via the legacy agent_runner path.
  3. SWARM_ENABLED=false: run again. Confirm only plain unprefixed
     events appear, proving the killswitch reroutes through
     agent_runner.run_agent.
"""
from .orchestrator import BreakerResult, SwarmOutcome, run_swarm

__all__ = ["run_swarm", "SwarmOutcome", "BreakerResult"]
