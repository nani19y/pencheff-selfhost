"""Dispatch-routing smoke tests for feature 001 — verifies that
``scan_runner._run_kind_aware_scan`` routes every new kind to the correct
orchestrator (artifact vs hybrid) with the right (target, kind_credentials)
arguments. The orchestrators themselves are mocked here; their internals
are covered by the dedicated test files.
"""
from __future__ import annotations

import pytest

from pencheff_api.services.scan_runner import _run_kind_aware_scan


class _FakeTarget:
    def __init__(self, kind: str, kind_config: dict | None = None) -> None:
        self.kind = kind
        self.kind_config = kind_config or {"kind": kind}


# Every kind that should reach an orchestrator + the orchestrator we expect.
_KIND_TO_ORCHESTRATOR_TEST_MATRIX: dict[str, str] = {
    "source_code":      "artifact",
    "container_image":  "artifact",
    "iac":              "artifact",
    "package_registry": "artifact",
    "sbom":             "artifact",
    "cicd_pipeline":    "hybrid",
    "k8s_cluster":      "hybrid",
    "cloud_account":    "cloud",
    "serverless_function": "cloud",
    "cloud_storage":    "cloud",
    "load_balancer_cdn": "cloud",
    "cloud_database":   "cloud",
    "secrets_manager":  "cloud",
}


@pytest.mark.asyncio
@pytest.mark.parametrize("kind, expected", _KIND_TO_ORCHESTRATOR_TEST_MATRIX.items())
async def test_run_kind_aware_scan_routes_to_correct_orchestrator(
    kind: str, expected: str, monkeypatch,
) -> None:
    called: dict[str, dict] = {}

    async def fake_artifact(*, scan_id, target, Session, kind_credentials=None):
        called["artifact"] = {"scan_id": scan_id, "kind": target.kind, "creds": kind_credentials}

    async def fake_hybrid(*, scan_id, target, Session, kind_credentials=None):
        called["hybrid"] = {"scan_id": scan_id, "kind": target.kind, "creds": kind_credentials}

    async def fake_cloud(*, scan_id, target, Session, kind_credentials=None):
        called["cloud"] = {"scan_id": scan_id, "kind": target.kind, "creds": kind_credentials}

    # Patch the orchestrators where _run_kind_aware_scan imports them (lazily,
    # inside the function body).
    import pencheff_api.services.agent_swarm.artifact_orchestrator as ao
    import pencheff_api.services.agent_swarm.hybrid_orchestrator as ho
    import pencheff_api.services.agent_swarm.cloud_orchestrator as co
    monkeypatch.setattr(ao, "run_artifact_orchestrator", fake_artifact)
    monkeypatch.setattr(ho, "run_hybrid_orchestrator", fake_hybrid)
    monkeypatch.setattr(co, "run_cloud_orchestrator", fake_cloud)

    target = _FakeTarget(kind=kind)
    # Session is never called by the fakes; pass None.
    await _run_kind_aware_scan("scan-test-id", target, None)

    assert expected in called, f"expected {expected!r} orchestrator to be invoked for kind={kind!r}"
    assert called[expected]["kind"] == kind
    # The other orchestrator must NOT have been invoked.
    for other in {"artifact", "hybrid", "cloud"} - {expected}:
        assert other not in called, f"unexpectedly invoked {other!r} orchestrator for kind={kind!r}"


@pytest.mark.asyncio
async def test_run_kind_aware_scan_dast_kinds_raise_not_implemented_error(monkeypatch) -> None:
    """DAST cluster kinds must NOT reach _run_kind_aware_scan — the scan_runner
    branch routes them through the existing url path. If somehow they do reach
    this function, it raises NotImplementedError with a clear message pointing
    at the spec."""
    for kind in ["web_app", "rest_api", "graphql", "websocket", "grpc"]:
        target = _FakeTarget(kind=kind)
        with pytest.raises(NotImplementedError, match=f"kind={kind!r}"):
            await _run_kind_aware_scan("scan-dast-id", target, None)


@pytest.mark.asyncio
async def test_run_kind_aware_scan_rejects_unknown_kind() -> None:
    """Defensive — an unknown / typo'd kind hits the ValueError fall-through."""
    target = _FakeTarget(kind="not_a_kind")
    with pytest.raises(ValueError, match="unsupported kind"):
        await _run_kind_aware_scan("scan-bad-id", target, None)
