"""Throttle AIMD behaviour."""

from __future__ import annotations

from pencheff.core.orchestrator.throttle import Throttle


def test_starts_at_initial_rate():
    t = Throttle()
    assert t.state.rate_rps > 0
    assert t.state.rate_rps <= 50.0


def test_429_triggers_backoff():
    t = Throttle()
    initial = t.state.rate_rps
    t.on_response(status=429)
    assert t.state.rate_rps < initial
    assert t.state.backoffs == 1


def test_503_triggers_backoff():
    t = Throttle()
    initial = t.state.rate_rps
    t.on_response(status=503)
    assert t.state.rate_rps < initial


def test_418_stops_completely():
    t = Throttle()
    t.on_response(status=418)
    assert t.state.stopped
    assert "tea-pot" in t.state.stop_reason.lower() or t.state.stop_reason


def test_success_increases_rate():
    t = Throttle()
    t.on_response(status=429)  # drop the rate first
    after_drop = t.state.rate_rps
    for _ in range(5):
        t.on_response(status=200)
    assert t.state.rate_rps > after_drop


def test_rate_clamped_to_min():
    t = Throttle()
    for _ in range(20):
        t.on_response(status=429)
    assert t.state.rate_rps >= 0.2 - 1e-9


def test_service_override_for_cloudflare():
    t = Throttle(service="cloudflare")
    assert t.state.rate_rps <= 2.0


def test_high_p95_latency_triggers_backoff():
    t = Throttle()
    initial = t.state.rate_rps
    for _ in range(10):
        t.on_response(status=200, latency_ms=6000.0)
    assert t.state.rate_rps <= initial
