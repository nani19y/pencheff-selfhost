"""Sampler factory.

Wraps ``ParentBased(TraceIdRatioBased(ratio))`` so a sampled root span
guarantees its descendants are also sampled — operators reading a
trace waterfall never see "missing middle" gaps from independent
ratio decisions per child.

Ratio of 1.0 = capture everything (the default); 0.1 = 10% of root
spans, all of their descendants.
"""
from __future__ import annotations


def build_sampler(ratio: float):
    from opentelemetry.sdk.trace.sampling import (
        ALWAYS_OFF,
        ALWAYS_ON,
        ParentBased,
        TraceIdRatioBased,
    )

    if ratio <= 0.0:
        return ALWAYS_OFF
    if ratio >= 1.0:
        return ALWAYS_ON
    return ParentBased(root=TraceIdRatioBased(ratio))
