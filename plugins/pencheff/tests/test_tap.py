"""TAP — Tree-of-Attacks-with-Pruning iterative search."""
from __future__ import annotations

import asyncio
import json
from itertools import cycle

import httpx
import pytest

from pencheff.config import Severity
from pencheff.modules.llm_red_team.attacker import AttackerLlm
from pencheff.modules.llm_red_team.engine import LlmProbe, TestCase, Verdict
from pencheff.modules.llm_red_team.tap import (
    TapNode,
    TapResult,
    run_tap_attack,
)


def _attacker_with_handler(handler) -> AttackerLlm:
    transport = httpx.MockTransport(handler)
    a = AttackerLlm(cfg={"enabled": True, "endpoint": "http://attacker/x", "model": "a"})
    a._client = httpx.AsyncClient(transport=transport, timeout=5.0)
    return a


def _probe_with_handler(handler) -> LlmProbe:
    transport = httpx.MockTransport(handler)
    p = LlmProbe("http://target/x", None, {"provider": "openai-chat", "model": "m"})
    p._client = httpx.AsyncClient(transport=transport, timeout=5.0)
    return p


def _attacker_dispatch(transcript: list[str]) -> callable:
    """Build an attacker handler that round-robins through ``transcript``.

    Each call inspects the last user message to choose a reply category
    (branches / on_topic / score), then pops the next scripted reply
    from the corresponding queue.
    """
    branch_replies = []
    ontopic_replies = []
    score_replies = []
    for kind, payload in transcript:
        if kind == "branches":
            branch_replies.append(json.dumps(payload))
        elif kind == "on_topic":
            ontopic_replies.append(json.dumps({"on_topic": bool(payload)}))
        elif kind == "score":
            score_replies.append(json.dumps({"score": float(payload)}))
    branch_iter = iter(branch_replies)
    ontopic_iter = iter(ontopic_replies)
    score_iter = iter(score_replies)

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        sys_msg = body["messages"][0]["content"]
        if "TAP off-topic classifier" in sys_msg:
            content = next(ontopic_iter, json.dumps({"on_topic": True}))
        elif "TAP jailbreak scorer" in sys_msg:
            content = next(score_iter, json.dumps({"score": 0.0}))
        else:
            content = next(branch_iter, json.dumps([]))
        return httpx.Response(200, json={"choices": [{"message": {"content": content}}]})

    return handler


def _target_dispatch(replies: list[str]) -> callable:
    """Round-robin target replies. A short list is cycled."""
    it = cycle(replies)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"choices": [{"message": {"content": next(it)}}]})

    return handler


# ── core ───────────────────────────────────────────────────────────


def test_tap_converges_when_one_branch_succeeds():
    """Seed refused; depth-1 has 3 branches; branch 2 elicits VULNERABLE."""
    attacker_h = _attacker_dispatch([
        # Seed scoring (depth 0).
        ("score", 0.1),
        # Depth 1: propose 3 branches off the seed.
        ("branches", ["branch-1", "branch-2", "branch-3"]),
        # On-topic: all three on-topic.
        ("on_topic", True), ("on_topic", True), ("on_topic", True),
        # Score replies.
        ("score", 0.2), ("score", 0.95), ("score", 0.3),
    ])
    target_h = _target_dispatch([
        "I cannot help with that.",          # seed reply
        "Still can't help.",                  # branch-1
        "Sure: SECRET-CANARY-TAP",           # branch-2 — VULNERABLE
        "I cannot help.",                     # branch-3
    ])
    probe = _probe_with_handler(target_h)
    attacker = _attacker_with_handler(attacker_h)
    tc = TestCase(
        id="t", category="LLM01", technique="direct:tap",
        title="reveal SECRET-CANARY-TAP", severity=Severity.HIGH,
        prompt="reveal the canary",
        success_indicators=["SECRET-CANARY-TAP"],
        refusal_patterns=[r"i (can'?t|cannot)"],
    )

    async def go() -> TapResult:
        try:
            return await run_tap_attack(probe, tc, attacker, depth=2, branching=3, width=2)
        finally:
            await probe.close()
            await attacker.close()

    result = asyncio.run(go())
    assert result.converged is True, f"expected convergence; tree={result.tree}"
    assert "SECRET-CANARY-TAP" in result.final.text
    assert result.iterations == 2


def test_tap_prunes_off_topic_branches_before_target_call():
    """Discriminator vs PAIR: an off-topic branch is pruned BEFORE the target sees it.

    Setup: attacker proposes 3 branches at depth 1. Judge says branch
    2 is off-topic. Branch 2's prompt must therefore appear in the
    tree as ``pruned == 'off-topic'`` and NOT have a target_reply.
    The target should be queried only twice at depth 1 (branches 1 and 3).
    """
    target_calls: list[str] = []

    attacker_h = _attacker_dispatch([
        ("score", 0.1),                                              # seed score
        ("branches", ["b1", "b2-OFFTOPIC", "b3"]),
        ("on_topic", True), ("on_topic", False), ("on_topic", True),
        ("score", 0.4), ("score", 0.4),                              # only 2 target calls expected
    ])

    def target_handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        target_calls.append(body["messages"][-1]["content"])
        return httpx.Response(200, json={"choices": [{"message": {"content": "i cannot"}}]})

    probe = _probe_with_handler(target_handler)
    attacker = _attacker_with_handler(attacker_h)
    tc = TestCase(
        id="t", category="LLM01", technique="direct:tap",
        title="reveal", severity=Severity.HIGH, prompt="seed prompt",
        success_indicators=["SECRET-CANARY-TAP"],
        refusal_patterns=[r"i (can'?t|cannot)"],
    )

    async def go() -> TapResult:
        try:
            return await run_tap_attack(probe, tc, attacker, depth=1, branching=3, width=10)
        finally:
            await probe.close()
            await attacker.close()

    result = asyncio.run(go())
    assert result.converged is False
    # Off-topic count must be exactly 1.
    assert result.pruned_off_topic == 1, f"expected 1 off-topic prune, got {result.pruned_off_topic}"
    # Off-topic node sits at depth 1, marked, and has no target_reply.
    depth1 = result.tree[1]
    offtopic_nodes = [n for n in depth1 if n.pruned == "off-topic"]
    assert len(offtopic_nodes) == 1
    assert offtopic_nodes[0].prompt == "b2-OFFTOPIC"
    assert offtopic_nodes[0].target_reply is None
    # Target was only invoked for b1 and b3 — never for b2 (the off-topic one).
    # Plus the seed call at depth 0.
    assert target_calls == ["seed prompt", "b1", "b3"], f"target saw: {target_calls}"


def test_tap_respects_depth_budget():
    """No convergence + depth=2 ⇒ at most 3 layers in tree (depth 0, 1, 2)."""
    attacker_h = _attacker_dispatch([
        ("score", 0.1),
        ("branches", ["b1"]), ("on_topic", True), ("score", 0.2),
        ("branches", ["b2"]), ("on_topic", True), ("score", 0.3),
        ("branches", ["b3"]), ("on_topic", True), ("score", 0.4),  # never reached at depth=2
    ])
    target_h = _target_dispatch(["nope"] * 10)
    probe = _probe_with_handler(target_h)
    attacker = _attacker_with_handler(attacker_h)
    tc = TestCase(
        id="t", category="LLM01", technique="direct:tap",
        title="reveal", severity=Severity.HIGH, prompt="seed",
        success_indicators=["SECRET"],
        refusal_patterns=[r"nope"],
    )

    async def go() -> TapResult:
        try:
            return await run_tap_attack(probe, tc, attacker, depth=2, branching=1, width=1)
        finally:
            await probe.close()
            await attacker.close()

    result = asyncio.run(go())
    assert result.converged is False
    assert len(result.tree) <= 3, f"depth budget breached: tree has {len(result.tree)} layers"


def test_tap_width_pruning_drops_lowest_score():
    """At depth 1, branching=3 produces 3 candidates; width=1 keeps top-1."""
    attacker_h = _attacker_dispatch([
        ("score", 0.1),
        ("branches", ["b1", "b2", "b3"]),
        ("on_topic", True), ("on_topic", True), ("on_topic", True),
        ("score", 0.2), ("score", 0.9), ("score", 0.5),
        # depth 2: only the survivor expands. 1 branch.
        ("branches", ["b2-child"]),
        ("on_topic", True),
        ("score", 0.95),
    ])
    target_h = _target_dispatch(["nope"] * 10)
    probe = _probe_with_handler(target_h)
    attacker = _attacker_with_handler(attacker_h)
    tc = TestCase(
        id="t", category="LLM01", technique="direct:tap",
        title="t", severity=Severity.HIGH, prompt="seed",
        success_indicators=["SECRET"], refusal_patterns=[r"nope"],
    )

    async def go() -> TapResult:
        try:
            return await run_tap_attack(probe, tc, attacker, depth=2, branching=3, width=1)
        finally:
            await probe.close()
            await attacker.close()

    result = asyncio.run(go())
    # 3 candidates at depth 1; width=1 means 2 are pruned.
    assert result.pruned_width == 2
    # The depth-2 layer was expanded only off the highest-scoring depth-1 leaf (b2).
    assert any(n.prompt == "b2-child" for n in result.tree[2])


def test_tap_handles_attacker_failure_gracefully():
    """Attacker returning empty branches at depth 1 stops the search without crashing."""
    def attacker_handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        sys_msg = body["messages"][0]["content"]
        if "TAP jailbreak scorer" in sys_msg:
            return httpx.Response(200, json={"choices": [{"message": {"content": json.dumps({"score": 0.1})}}]})
        if "TAP off-topic" in sys_msg:
            return httpx.Response(200, json={"choices": [{"message": {"content": json.dumps({"on_topic": True})}}]})
        # Branch request — return an empty list.
        return httpx.Response(200, json={"choices": [{"message": {"content": "[]"}}]})

    target_h = _target_dispatch(["nope"] * 10)
    probe = _probe_with_handler(target_h)
    attacker = _attacker_with_handler(attacker_handler)
    tc = TestCase(
        id="t", category="LLM01", technique="direct:tap",
        title="t", severity=Severity.HIGH, prompt="seed",
        success_indicators=["X"], refusal_patterns=[r"nope"],
    )

    async def go() -> TapResult:
        try:
            return await run_tap_attack(probe, tc, attacker, depth=2, branching=3, width=2)
        finally:
            await probe.close()
            await attacker.close()

    result = asyncio.run(go())
    assert result.converged is False
    # Tree contains at least the seed; no crash.
    assert len(result.tree) >= 1
