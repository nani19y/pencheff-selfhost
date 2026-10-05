"""Runtime tracing: SDK-ingest span normalization (pure, no DB)."""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from pencheff_api.services.tracing import (
    build_request_spans,
    new_trace_id,
    normalize_ingested_spans,
)

WS = "ws-1"


# ── gateway span linkage (regression: id default fires at flush, so the
#    child's parent_span_id was being set to None at construction) ──────

def test_gateway_block_trace_links_child_to_root():
    spans = build_request_spans(
        workspace_id=WS, target_id="tgt", duration_ms=12, status="blocked",
        model="m", block_attrs={"kind": "firewall", "reason": "x"},
    )
    assert len(spans) == 2
    root, child = spans
    assert root.id is not None
    assert root.parent_span_id is None
    assert child.parent_span_id == root.id          # the bug the advisor caught
    assert root.trace_id == child.trace_id
    assert child.kind == "firewall" and child.status == "blocked"


def test_gateway_success_trace_links_llm_child_to_root():
    spans = build_request_spans(
        workspace_id=WS, target_id="tgt", duration_ms=30, status="ok",
        model="m", llm_attrs={"prompt_tokens": 10, "completion_tokens": 5},
    )
    assert len(spans) == 2
    root, child = spans
    assert child.parent_span_id == root.id
    assert child.kind == "llm"
    assert child.attributes["completion_tokens"] == 5


def test_gateway_trace_ids_are_unique_per_call():
    a = build_request_spans(workspace_id=WS, target_id=None, duration_ms=1, status="ok", llm_attrs={})
    b = build_request_spans(workspace_id=WS, target_id=None, duration_ms=1, status="ok", llm_attrs={})
    assert a[0].trace_id != b[0].trace_id
    assert a[0].id != b[0].id


def test_new_trace_id_is_hex_and_unique():
    a, b = new_trace_id(), new_trace_id()
    assert a != b
    assert all(c in "0123456789abcdef" for c in a)


def test_normalizes_a_valid_payload():
    payload = {
        "trace_id": "t-abc",
        "spans": [
            {"span_id": "s1", "name": "agent.run", "kind": "request",
             "status": "ok", "start_time": "2026-06-07T10:00:00Z",
             "end_time": "2026-06-07T10:00:01Z"},
            {"span_id": "s2", "parent_span_id": "s1", "name": "llm.chat",
             "kind": "llm", "duration_ms": 250, "attributes": {"model": "x"}},
        ],
    }
    out = normalize_ingested_spans(payload, workspace_id=WS)
    assert len(out) == 2
    assert out[0]["trace_id"] == "t-abc"
    assert out[0]["workspace_id"] == WS
    assert out[0]["source"] == "sdk"
    assert out[0]["duration_ms"] == 1000          # derived from start/end
    assert out[1]["parent_span_id"] == "s1"
    assert out[1]["attributes"] == {"model": "x"}


def test_missing_spans_list_raises():
    with pytest.raises(ValueError):
        normalize_ingested_spans({"trace_id": "t"}, workspace_id=WS)


def test_empty_spans_raises():
    with pytest.raises(ValueError):
        normalize_ingested_spans({"spans": []}, workspace_id=WS)


def test_too_many_spans_raises():
    payload = {"spans": [{"name": "x"} for _ in range(501)]}
    with pytest.raises(ValueError):
        normalize_ingested_spans(payload, workspace_id=WS)


def test_span_without_name_raises():
    with pytest.raises(ValueError):
        normalize_ingested_spans({"spans": [{"kind": "llm"}]}, workspace_id=WS)


def test_unknown_kind_and_status_are_coerced():
    out = normalize_ingested_spans(
        {"spans": [{"name": "x", "kind": "weird", "status": "nope"}]},
        workspace_id=WS,
    )
    assert out[0]["kind"] == "other"
    assert out[0]["status"] == "ok"


def test_missing_trace_id_is_generated():
    out = normalize_ingested_spans({"spans": [{"name": "x"}]}, workspace_id=WS)
    assert out[0]["trace_id"]  # non-empty generated id


def test_epoch_millis_timestamp_parses():
    ts = 1_700_000_000_000  # ms
    out = normalize_ingested_spans(
        {"spans": [{"name": "x", "start_time": ts}]}, workspace_id=WS,
    )
    assert isinstance(out[0]["start_time"], datetime)
    assert out[0]["start_time"].tzinfo is not None
