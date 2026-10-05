from __future__ import annotations

import asyncio
import concurrent.futures
from dataclasses import dataclass, field
from typing import Protocol


@dataclass
class ChatMessage:
    role: str          # "system" | "user" | "assistant"
    content: str


@dataclass
class ChatResult:
    text: str
    raw: dict = field(default_factory=dict)
    input_tokens: int = 0
    output_tokens: int = 0


class ChatClient(Protocol):
    provider: str
    model: str

    async def chat(
        self,
        messages: list[ChatMessage],
        *,
        temperature: float = 0.0,
        max_tokens: int = 1024,
        json: bool = False,
        timeout: float = 60.0,
    ) -> ChatResult:
        ...


def run_sync(coro):
    """Run an async coroutine from sync code, safely even if an event loop is
    already running on this thread (which would make asyncio.run raise).

    Used by the single sync AI call site (services/llm.py). When no loop is
    running, asyncio.run is used directly. When one IS running, the coroutine
    is executed on a fresh loop in a worker thread and the result awaited.
    """
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    # A loop is already running on this thread → offload to a thread.
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
        return ex.submit(lambda: asyncio.run(coro)).result()
