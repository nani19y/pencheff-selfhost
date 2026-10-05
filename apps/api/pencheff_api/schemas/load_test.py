# pencheff_api/schemas/load_test.py
"""Load-test config + report shapes.

Load testing runs as a distinct scan ``profile="load"`` — a kind-aware load
generator instead of the security pipeline. All limits are HARD server-side
bounds: load generation is DoS-adjacent, so a scan can never exceed them even
if a client sends larger values.
"""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

# Hard ceilings — a load scan is clamped to these regardless of input.
MAX_DURATION_S = 300      # 5 minutes (simple mode single run)
MAX_CONCURRENCY = 500     # virtual users (bounded: load runs on the shared VM)
MAX_TARGET_RPS = 5000
MAX_STAGES = 10
MAX_STAGE_DURATION_S = 120
MAX_TOTAL_BUDGET_S = 600


class LoadThresholds(BaseModel):
    """SLA gates. None = let the agent seed a sensible default."""
    p95_ms: int | None = Field(None, ge=1, le=120_000)
    error_rate: float | None = Field(None, ge=0.0, le=1.0)


class LoadTestConfig(BaseModel):
    """Operator-tunable load parameters (bounded). Read-only requests only —
    the engine never sends mutating methods under load (see engine)."""

    duration_s: int = Field(30, ge=5)
    concurrency: int = Field(20, ge=1)
    # Optional aggregate RPS cap; None = as fast as concurrency allows.
    target_rps: int | None = Field(None, ge=1)
    ramp_s: int = Field(5, ge=0)
    think_time_ms: int = Field(0, ge=0)
    mode: Literal["agentic", "simple"] = "agentic"
    profile_shape: Literal["ramp", "steady", "spike", "soak", "arrival_rate"] = "ramp"
    thresholds: LoadThresholds = Field(default_factory=LoadThresholds)
    max_stages: int = Field(6, ge=1)
    stage_duration_s: int = Field(25, ge=5)
    total_budget_s: int = Field(240, ge=10)

    def clamped(self) -> "LoadTestConfig":
        """Return a copy with every field clamped to its hard ceiling."""
        return LoadTestConfig(
            duration_s=min(self.duration_s, MAX_DURATION_S),
            concurrency=min(self.concurrency, MAX_CONCURRENCY),
            target_rps=(min(self.target_rps, MAX_TARGET_RPS)
                        if self.target_rps else None),
            ramp_s=min(self.ramp_s, 60),
            think_time_ms=min(self.think_time_ms, 5000),
            mode=self.mode,
            profile_shape=self.profile_shape,
            thresholds=self.thresholds,
            max_stages=min(self.max_stages, MAX_STAGES),
            stage_duration_s=min(self.stage_duration_s, MAX_STAGE_DURATION_S),
            total_budget_s=min(self.total_budget_s, MAX_TOTAL_BUDGET_S),
        )


DEFAULT_LOAD_CONFIG = LoadTestConfig()


class LoadReport(BaseModel):
    """Result summary stored on ``Scan.summary["load_report"]``."""

    kind: str
    ok: bool
    error: str | None = None
    duration_s: float = 0.0
    total_requests: int = 0
    error_count: int = 0
    error_rate: float = 0.0            # 0..1
    rps: float = 0.0                   # achieved requests/sec
    latency_ms: dict[str, float] = Field(default_factory=dict)  # p50/p90/p95/p99/max
    # Per-endpoint / per-op breakdown (rest_api, grpc, …).
    by_target: list[dict] = Field(default_factory=list)
    # Free-form protocol extras (llm tokens/sec + TTFT, ws connect rate, …).
    extra: dict = Field(default_factory=dict)
    stages: list[dict] = Field(default_factory=list)
    breaking_point: dict | None = None
    threshold_results: list[dict] = Field(default_factory=list)
    timeseries: dict = Field(default_factory=dict)
    agent_narrative: str = ""
    cost_cents: int = 0
