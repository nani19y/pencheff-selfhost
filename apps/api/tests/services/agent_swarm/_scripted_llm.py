"""Scripted LLM stub for swarm tests.

Each ``ScriptedTurn`` is one chat-completions response. ``ScriptedLLM``
patches ``httpx.AsyncClient.post`` so each call pops the next scripted
turn off the queue and returns it as a real ``httpx.Response``.

Use ``with_tool_call`` to build a tool-call turn, ``with_finish`` to
build a final ``finish`` turn, and ``with_transient_error`` to script
a transient HTTP failure.

This helper is NOT a test module (filename starts with ``_``) so pytest
will not auto-collect it.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

import httpx


@dataclass
class ScriptedTurn:
    """One scripted chat-completions response."""

    tool_calls: list[dict[str, Any]] = field(default_factory=list)
    content: str | None = None
    usage: dict[str, Any] | None = None
    status_code: int = 200
    body_override: str | None = None  # raw body for non-200 responses


def with_tool_call(name: str, args: dict[str, Any], call_id: str = "call_1") -> ScriptedTurn:
    return ScriptedTurn(tool_calls=[{
        "id": call_id,
        "type": "function",
        "function": {"name": name, "arguments": json.dumps(args)},
    }])


def with_finish(summary: str, call_id: str = "call_finish") -> ScriptedTurn:
    return with_tool_call("finish", {"summary": summary}, call_id=call_id)


def with_transient_error(status_code: int = 503, body: str = "upstream down") -> ScriptedTurn:
    return ScriptedTurn(status_code=status_code, body_override=body)


class ScriptedLLM:
    """Patches httpx.AsyncClient.post to return scripted turns in order."""

    def __init__(self, turns: list[ScriptedTurn]) -> None:
        self._turns = list(turns)
        self.calls: list[dict[str, Any]] = []  # captured request bodies

    def install(self, monkeypatch) -> None:
        async def _fake_post(self_client, url, headers=None, json=None, **kw):
            self_outer.calls.append({"url": url, "json": json})
            if not self_outer._turns:
                raise AssertionError("ScriptedLLM exhausted: no turns left")
            turn = self_outer._turns.pop(0)
            request = httpx.Request("POST", url)
            if turn.status_code != 200:
                return httpx.Response(
                    status_code=turn.status_code,
                    request=request,
                    text=turn.body_override or "",
                )
            payload = {
                "choices": [{
                    "message": {
                        "content": turn.content,
                        "tool_calls": turn.tool_calls or None,
                    },
                    "finish_reason": "tool_calls" if turn.tool_calls else "stop",
                }],
            }
            if turn.usage is not None:
                payload["usage"] = turn.usage
            return httpx.Response(status_code=200, request=request, json=payload)

        self_outer = self
        monkeypatch.setattr(httpx.AsyncClient, "post", _fake_post)

    @property
    def remaining(self) -> int:
        return len(self._turns)
