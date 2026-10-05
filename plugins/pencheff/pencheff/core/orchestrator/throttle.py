"""AIMD-style request-rate adapter.

The throttle holds a single floating ``rate_rps`` per session. Each successful
probe nudges it up by ``additive_increase_per_sec``; a 429/503 cuts it by
``multiplicative_decrease``. Latency triggers also drag the rate down. The
adapter exposes ``before_request()`` so the calling code can sleep just
enough to honour the current cap.

Implementation note: this module is sync because tools shell out via blocking
subprocess on most platforms. For the async ``http_client`` integration,
``Throttle.before_request_async`` returns the same delay.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from threading import Lock

from pencheff.core.orchestrator.policies import Policies, load_policies


@dataclass
class ThrottleState:
    rate_rps: float
    last_request_at: float = 0.0
    successes_in_window: int = 0
    backoffs: int = 0
    stopped: bool = False
    stop_reason: str = ""
    p95_ms_window: list[float] = field(default_factory=list)


class Throttle:
    def __init__(
        self,
        policies: Policies | None = None,
        *,
        service: str | None = None,
    ) -> None:
        self._policies = policies or load_policies()
        cfg = self._policies.throttle
        global_cfg = cfg.get("global", {})
        services = cfg.get("services", {})

        if service and service in services:
            svc_cfg = {**global_cfg, **services[service]}
        else:
            svc_cfg = global_cfg

        self._cfg = svc_cfg
        self._initial_rate = float(svc_cfg.get("initial_rate_rps", 5.0))
        self._min_rate = float(svc_cfg.get("min_rate_rps", 0.2))
        self._max_rate = float(svc_cfg.get("max_rate_rps", 50.0))
        self._aimd_inc = float(svc_cfg.get("additive_increase_per_sec", 1.0))
        self._aimd_dec = float(svc_cfg.get("multiplicative_decrease", 0.5))
        self._jitter_min = float(svc_cfg.get("jitter_ms_min", 50)) / 1000.0
        self._jitter_max = float(svc_cfg.get("jitter_ms_max", 200)) / 1000.0
        self._retry_budget = int(svc_cfg.get("retry_budget", 3))
        self._timeout = float(svc_cfg.get("request_timeout_seconds", 30))

        self._state = ThrottleState(rate_rps=self._initial_rate)
        self._lock = Lock()

    # ─── public API ─────────────────────────────────────────────────────
    @property
    def state(self) -> ThrottleState:
        return self._state

    @property
    def request_timeout(self) -> float:
        return self._timeout

    def delay_for_next(self, *, jitter_rng=None) -> float:
        """Return seconds to sleep before the next request."""
        with self._lock:
            if self._state.stopped:
                return float("inf")
            min_interval = 1.0 / max(self._state.rate_rps, 1e-6)
            now = time.monotonic()
            since = now - self._state.last_request_at
            base = max(0.0, min_interval - since)
            jitter = self._sample_jitter(jitter_rng)
            return base + jitter

    def before_request(self, *, jitter_rng=None) -> None:
        delay = self.delay_for_next(jitter_rng=jitter_rng)
        if delay == float("inf"):
            raise RuntimeError(f"throttle stopped: {self._state.stop_reason}")
        if delay > 0:
            time.sleep(delay)
        with self._lock:
            self._state.last_request_at = time.monotonic()

    async def before_request_async(self, *, jitter_rng=None) -> None:
        delay = self.delay_for_next(jitter_rng=jitter_rng)
        if delay == float("inf"):
            raise RuntimeError(f"throttle stopped: {self._state.stop_reason}")
        if delay > 0:
            await asyncio.sleep(delay)
        with self._lock:
            self._state.last_request_at = time.monotonic()

    def on_response(
        self,
        *,
        status: int,
        latency_ms: float | None = None,
        retry_after: float | None = None,
    ) -> None:
        """Update the rate based on the response.

        ``status`` may be -1 for transport errors; we treat that as a soft
        backoff signal.
        """
        triggers = self._policies.throttle.get("status_triggers", {})
        rule = triggers.get(str(status))
        if rule:
            action = rule.get("action")
            if action == "stop":
                with self._lock:
                    self._state.stopped = True
                    self._state.stop_reason = rule.get("notes", f"status {status}")
                return
            if action == "backoff":
                multiplier = float(rule.get("multiplier", 0.5))
                self._apply_backoff(multiplier)
                if rule.get("honor_retry_after") and retry_after:
                    # Honour Retry-After by sleeping immediately.
                    time.sleep(min(retry_after, 60.0))
                return
            if action == "probe_alt_ua":
                # No rate change; signal handled at request layer.
                return
            if action == "continue":
                pass

        if latency_ms is not None:
            self._state.p95_ms_window.append(latency_ms)
            # Bounded ring of last 30s — coarse: keep newest 100 samples.
            if len(self._state.p95_ms_window) > 100:
                self._state.p95_ms_window = self._state.p95_ms_window[-100:]
            self._evaluate_latency_triggers()

        if 200 <= status < 400:
            self._aimd_increase()

    # ─── internal ───────────────────────────────────────────────────────
    def _apply_backoff(self, multiplier: float) -> None:
        with self._lock:
            self._state.rate_rps = max(
                self._min_rate, self._state.rate_rps * multiplier
            )
            self._state.backoffs += 1

    def _aimd_increase(self) -> None:
        with self._lock:
            self._state.successes_in_window += 1
            self._state.rate_rps = min(
                self._max_rate, self._state.rate_rps + self._aimd_inc
            )

    def _evaluate_latency_triggers(self) -> None:
        if len(self._state.p95_ms_window) < 5:
            return
        sorted_window = sorted(self._state.p95_ms_window)
        idx = max(0, int(len(sorted_window) * 0.95) - 1)
        p95 = sorted_window[idx]
        for trig in self._policies.throttle.get("latency_triggers", []):
            if p95 >= float(trig.get("p95_ms_over", 1e9)):
                if trig.get("action") == "stop":
                    with self._lock:
                        self._state.stopped = True
                        self._state.stop_reason = trig.get("notes", f"p95={p95}ms")
                    return
                if trig.get("action") == "backoff":
                    self._apply_backoff(float(trig.get("multiplier", 0.7)))
                    return

    def _sample_jitter(self, rng) -> float:
        if rng is None:
            return self._jitter_min
        return rng.uniform(self._jitter_min, self._jitter_max)
