"""Hydra — multi-objective parallel multi-turn dispatcher."""
from __future__ import annotations

import asyncio
import json

import httpx
import pytest

from pencheff.config import Severity
from pencheff.modules.llm_red_team.attacker import AttackerLlm
from pencheff.modules.llm_red_team.engine import LlmProbe, TestCase
from pencheff.modules.llm_red_team.hydra import (
    HydraResult,
    hydra_objectives_for,
    run_hydra_attack,
)


def _attacker(handler) -> AttackerLlm:
    a = AttackerLlm(cfg={"enabled": True, "endpoint": "http://attacker/x", "model": "a"})
    a._client = httpx.AsyncClient(transport=httpx.MockTransport(handler), timeout=5.0)
    return a


def _probe(handler) -> LlmProbe:
    p = LlmProbe("http://target/x", None, {"provider": "openai-chat", "model": "m"})
    p._client = httpx.AsyncClient(transport=httpx.MockTransport(handler), timeout=5.0)
    return p


# ── core ──────────────────────────────────────────────────────────


def test_hydra_objectives_default_to_success_indicators():
    tc = TestCase(
        id="h", category="LLM01", technique="t",
        title="T", severity=Severity.HIGH, prompt="x",
        success_indicators=["A", "B"],
    )
    assert hydra_objectives_for(tc) == [
        "Elicit output that matches: A",
        "Elicit output that matches: B",
    ]


def test_hydra_objectives_can_be_overridden_via_metadata():
    tc = TestCase(
        id="h", category="LLM01", technique="t", title="T",
        severity=Severity.HIGH, prompt="x",
        metadata={"hydra_objectives": ["O1", "O2", "O3"]},
    )
    assert hydra_objectives_for(tc) == ["O1", "O2", "O3"]


def test_yaml_loader_propagates_metadata_to_test_case():
    """Regression: every YAML / dict loader must pass `metadata` into TestCase.

    Without this, a YAML probe shipping ``metadata: {hydra_objectives: [...]}``
    would silently lose its objectives and Hydra would fall back to the
    success_indicator list.
    """
    from pencheff.modules.llm_red_team.addon_plugins import _to_case
    from pencheff.modules.llm_red_team.datasets import _case_from_obj

    yaml_entry = {
        "id": "x", "category": "LLM06", "technique": "t",
        "title": "T", "severity": "high", "prompt": "p",
        "metadata": {"hydra_objectives": ["A", "B"]},
    }
    tc1 = _to_case(yaml_entry, file_name="test.yaml")
    assert tc1.metadata == {"hydra_objectives": ["A", "B"]}

    tc2 = _case_from_obj(yaml_entry, dataset="custom", idx=1)
    assert tc2 is not None
    assert tc2.metadata == {"hydra_objectives": ["A", "B"]}


def test_hydra_fans_out_one_branch_per_objective_and_converges_on_one():
    """Three objectives, three concurrent branches, branch 2 converges."""
    # Target replies tracked per branch via the user prompt content.
    target_log: list[str] = []

    def target_handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        last_user = body["messages"][-1]["content"]
        target_log.append(last_user)
        # Branch 2 (objective "OBJ-2") gets a complying reply on the
        # attacker-driven turn; the others stay refused.
        if "OBJ-2" in last_user:
            return httpx.Response(200, json={"choices": [{"message": {"content": "Sure: HYDRA-CANARY-OK"}}]})
        return httpx.Response(200, json={"choices": [{"message": {"content": "I cannot help."}}]})

    def attacker_handler(request: httpx.Request) -> httpx.Response:
        # Each branch's attacker call gets a `next_turn` that contains
        # the branch objective so the target handler above can identify
        # the branch.
        body = json.loads(request.content)
        last_user_msg = body["messages"][-1]["content"]
        # The attacker user payload is JSON; pull the objective.
        try:
            payload = json.loads(last_user_msg)
            objective = payload.get("objective", "")
        except (ValueError, KeyError):
            objective = "UNKNOWN"
        next_turn = f"Refined for objective: {objective}"
        return httpx.Response(200, json={"choices": [{"message": {"content": json.dumps({"next_turn": next_turn})}}]})

    probe = _probe(target_handler)
    attacker = _attacker(attacker_handler)
    tc = TestCase(
        id="h", category="LLM01", technique="direct:hydra",
        title="reveal", severity=Severity.HIGH, prompt="seed",
        success_indicators=["HYDRA-CANARY-OK"],
        refusal_patterns=[r"i cannot"],
        metadata={"hydra_objectives": ["OBJ-1", "OBJ-2", "OBJ-3"]},
    )

    async def go() -> HydraResult:
        try:
            return await run_hydra_attack(probe, tc, attacker, max_turns=2)
        finally:
            await probe.close()
            await attacker.close()

    result = asyncio.run(go())
    assert result.converged is True
    assert "HYDRA-CANARY-OK" in result.final.text
    assert result.final_objective == "OBJ-2"
    # Three branches recorded, only the OBJ-2 one converged.
    assert len(result.branches) == 3
    converged = [b for b in result.branches if b.converged]
    assert len(converged) == 1
    assert converged[0].objective == "OBJ-2"


def test_hydra_returns_longest_branch_when_no_convergence():
    """All branches refused — caller still gets a final response, plus all transcripts."""
    def target_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"choices": [{"message": {"content": "I cannot help."}}]})

    def attacker_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"choices": [{"message": {"content": json.dumps({"next_turn": "follow-up"})}}]})

    probe = _probe(target_handler)
    attacker = _attacker(attacker_handler)
    tc = TestCase(
        id="h", category="LLM01", technique="direct:hydra",
        title="reveal", severity=Severity.HIGH, prompt="seed",
        success_indicators=["X"], refusal_patterns=[r"i cannot"],
        metadata={"hydra_objectives": ["A", "B"]},
    )

    async def go() -> HydraResult:
        try:
            return await run_hydra_attack(probe, tc, attacker, max_turns=3)
        finally:
            await probe.close()
            await attacker.close()

    result = asyncio.run(go())
    assert result.converged is False
    assert len(result.branches) == 2
    # Each branch ran to max_turns.
    for b in result.branches:
        assert len(b.turns) >= 1


def test_hydra_concurrency_cap_serializes_branches():
    """concurrency=1 with 3 objectives ⇒ branches run sequentially.

    We can't easily measure wall-clock concurrency in unit tests, but
    we can confirm the semaphore doesn't break the scheduler — every
    branch still runs and the result count matches the objective count.
    """
    def target_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"choices": [{"message": {"content": "nope"}}]})

    def attacker_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"choices": [{"message": {"content": json.dumps({"next_turn": "go"})}}]})

    probe = _probe(target_handler)
    attacker = _attacker(attacker_handler)
    tc = TestCase(
        id="h", category="LLM01", technique="direct:hydra",
        title="x", severity=Severity.HIGH, prompt="seed",
        success_indicators=["X"], refusal_patterns=[r"nope"],
        metadata={"hydra_objectives": ["A", "B", "C"]},
    )

    async def go() -> HydraResult:
        try:
            return await run_hydra_attack(probe, tc, attacker, max_turns=2, concurrency=1)
        finally:
            await probe.close()
            await attacker.close()

    result = asyncio.run(go())
    assert len(result.branches) == 3
    assert {b.objective for b in result.branches} == {"A", "B", "C"}
