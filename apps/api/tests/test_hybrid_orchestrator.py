"""Tests for the hybrid orchestrator (Phase A always, Phase B conditional)."""
from __future__ import annotations

import pytest

from pencheff_api.services.agent_swarm import hybrid_orchestrator as ho


class _FakeTarget:
    def __init__(self, kind: str, kind_config: dict | None = None) -> None:
        self.kind = kind
        self.kind_config = kind_config


def test_has_live_phase_b_cicd_default_false() -> None:
    t = _FakeTarget("cicd_pipeline", {"provider": "github_actions"})
    assert ho._has_live_phase_b(t) is False


def test_has_live_phase_b_cicd_when_live_api_enabled() -> None:
    t = _FakeTarget("cicd_pipeline", {"provider": "github_actions", "live_api_enabled": True})
    assert ho._has_live_phase_b(t) is True


def test_has_live_phase_b_k8s_default_manifests_only() -> None:
    t = _FakeTarget("k8s_cluster", {"target": "manifests_only"})
    assert ho._has_live_phase_b(t) is False


def test_has_live_phase_b_k8s_live_cluster() -> None:
    t = _FakeTarget("k8s_cluster", {"target": "live_cluster"})
    assert ho._has_live_phase_b(t) is True


def test_has_live_phase_b_non_hybrid_kind_returns_false() -> None:
    t = _FakeTarget("web_app", {"kind": "web_app"})
    assert ho._has_live_phase_b(t) is False


def test_phase_a_args_for_cicd_with_clone() -> None:
    args = ho._phase_a_args_for("cicd_pipeline", "run_checkov",
                                 acquired={"local_path": "/tmp/cloned"}, cfg={})
    assert args == {"source_path": "/tmp/cloned"}


def test_phase_a_args_for_cicd_without_clone() -> None:
    args = ho._phase_a_args_for("cicd_pipeline", "run_checkov",
                                 acquired={}, cfg={})
    assert args is None


def test_phase_a_args_for_k8s_passes_kubernetes_framework() -> None:
    args = ho._phase_a_args_for("k8s_cluster", "run_checkov",
                                 acquired={"local_path": "/tmp/manifests"}, cfg={})
    assert args == {"source_path": "/tmp/manifests", "framework": "kubernetes"}


def test_kind_to_hybrid_phase_a_tools_covers_2_hybrid_kinds() -> None:
    assert set(ho.KIND_TO_HYBRID_PHASE_A_TOOLS.keys()) == {"cicd_pipeline", "k8s_cluster"}


@pytest.mark.asyncio
async def test_orchestrator_rejects_non_hybrid_kind() -> None:
    target = _FakeTarget("web_app", {"kind": "web_app"})
    with pytest.raises(ValueError, match="non-hybrid kind"):
        await ho.run_hybrid_orchestrator(scan_id="x", target=target, Session=None)
