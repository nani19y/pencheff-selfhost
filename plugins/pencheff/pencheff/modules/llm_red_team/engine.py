"""LLM red-team probe engine.

Three pieces:

1. ``LlmProbe`` — async wrapper around HTTP or executable targets that knows how to
   shape a chat request for the ``openai-chat`` preset, render a
   user-supplied template for ``custom`` mode, or invoke a local command
   for app-pipeline testing. Concurrency-bounded, per-call timeout.

2. ``TestCase`` — a single payload loaded from a YAML file. Carries
   the prompt, optional system override, regex success indicators,
   regex refusal patterns, and metadata for the eventual Finding.

3. ``evaluate(test_case, response_text)`` — pure verdict function.
   No LLM-as-judge: refusal-pattern match (case/dotall-insensitive)
   beats success-indicator match, ambiguity emits no finding.

The engine is deliberately tiny and dependency-free (no jsonpath-ng,
no jinja). The custom-mode template only substitutes three explicit
placeholders; the response extractor only handles the dotted-path
subset of JSONPath that real chat APIs use in practice.
"""
from __future__ import annotations

import asyncio
import json
import logging
import re
import time
import uuid
from collections import OrderedDict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import httpx

from pencheff.config import Severity

log = logging.getLogger(__name__)


# ── Provider presets ────────────────────────────────────────────────

# Hard cap on every chat call — without it a single gpt-4-class
# request against an unbounded probe (LLM10) can run away in cost.
# 4096 leaves enough headroom for reasoning models (DeepSeek-R1,
# Nemotron, QwQ) whose ``<think>…</think>`` traces routinely consume
# 1–2K tokens before producing the visible answer. With a 1024 cap
# the visible content was usually empty, leaving the verdict
# AMBIGUOUS with no signal. Per-call override is still possible via
# ``llm_config.max_tokens``.
_MAX_TOKENS_DEFAULT = 4096


class ProviderError(RuntimeError):
    """Raised when a probe response can't be parsed under the
    configured provider preset. The orchestrator catches this and
    emits a single INFO finding ("LLM endpoint unreachable") rather
    than crashing the whole scan."""


class _RateLimiter:
    """Lightweight async token bucket.

    Refills at ``rate`` tokens/second (capped at ``capacity``). Each
    ``acquire()`` consumes one token, blocking until one is available.
    Shared across all LlmProbe instances targeting the same endpoint
    via ``_RateLimiter.get_shared`` so 10 OWASP modules dispatching
    concurrently against OpenRouter respect the provider's per-key
    RPS/RPM cap rather than each running their own private bucket.

    No-op when ``rate <= 0``.
    """

    __slots__ = ("rate", "capacity", "_tokens", "_last", "_lock", "_until")

    # Process-wide registry. Keyed on (endpoint, rate) so two scans
    # against the same endpoint with the same configured rate share
    # one bucket, but two scans with different rate caps don't
    # interfere. Lives for the worker's lifetime — scans within the
    # same process get the right shared throttling automatically.
    # No lock around dict access: CPython dict operations are
    # atomic for single keys, and the worst-case race is a transient
    # duplicate bucket that gets discarded after one use.
    _SHARED: "dict[tuple[str, float], _RateLimiter]" = {}

    def __init__(self, rate: float, capacity: float | None = None) -> None:
        self.rate = max(0.0, float(rate or 0.0))
        # Default capacity = rate (1-second burst). Callers can pass
        # an explicit capacity to allow short bursts above steady-state.
        self.capacity = float(capacity if capacity is not None else max(self.rate, 1.0))
        self._tokens = self.capacity
        self._last = time.perf_counter()
        self._lock = asyncio.Lock()
        # Hard "do not even try until this monotonic time" — set when
        # an upstream Retry-After header tells us to back off. Honors
        # the provider's request even when our token bucket would
        # otherwise allow new traffic, which prevents thundering-herd
        # 429s on free-tier endpoints.
        self._until = 0.0

    @classmethod
    def get_shared(cls, endpoint: str, rate: float, capacity: float | None = None) -> "_RateLimiter":
        key = (endpoint, round(float(rate or 0.0), 3))
        existing = cls._SHARED.get(key)
        if existing is not None:
            return existing
        rl = cls(rate=rate, capacity=capacity)
        cls._SHARED[key] = rl
        return rl

    def stall_until(self, monotonic_deadline: float) -> None:
        """Force every future ``acquire()`` to sleep at least until
        the given perf_counter deadline. Used by 429 retry handling
        to honor Retry-After across all concurrent dispatchers."""
        if monotonic_deadline > self._until:
            self._until = monotonic_deadline

    async def acquire(self) -> None:
        if self.rate <= 0 and self._until <= time.perf_counter():
            return
        async with self._lock:
            # Honor any global stall first — otherwise a tiny burst
            # capacity drains and we still hit Retry-After windows.
            now = time.perf_counter()
            if now < self._until:
                await asyncio.sleep(self._until - now)
                now = time.perf_counter()
            if self.rate <= 0:
                return
            elapsed = now - self._last
            self._tokens = min(self.capacity, self._tokens + elapsed * self.rate)
            self._last = now
            if self._tokens < 1.0:
                wait_s = (1.0 - self._tokens) / self.rate
                await asyncio.sleep(wait_s)
                now2 = time.perf_counter()
                self._tokens = min(self.capacity, self._tokens + (now2 - self._last) * self.rate)
                self._last = now2
            self._tokens -= 1.0


@dataclass
class ProbeResponse:
    text: str
    http_status: int
    request_body: str
    response_body: str
    latency_ms: int
    input_tokens: int | None = None
    output_tokens: int | None = None
    cached: bool = False
    tool_calls: list[dict[str, Any]] = field(default_factory=list)


class BudgetExceeded(ProviderError):
    """Raised when the scan-level budget is exhausted."""


@dataclass
class ProbeBudget:
    """Lightweight per-scan budget / kill switch."""

    max_calls: int | None = None
    max_tokens: int | None = None
    max_cost_usd: float | None = None
    input_cost_per_1k: float = 0.0
    output_cost_per_1k: float = 0.0
    calls: int = 0
    tokens: int = 0
    cost_usd: float = 0.0

    @classmethod
    def from_config(cls, cfg: dict[str, Any]) -> "ProbeBudget | None":
        raw = cfg.get("budget") or (cfg.get("redteam") or {}).get("budget")
        if not isinstance(raw, dict):
            return None
        return cls(
            max_calls=_int_or_none(raw.get("max_calls")),
            max_tokens=_int_or_none(raw.get("max_tokens")),
            max_cost_usd=_float_or_none(raw.get("max_cost_usd")),
            input_cost_per_1k=float(raw.get("input_cost_per_1k", 0.0) or 0.0),
            output_cost_per_1k=float(raw.get("output_cost_per_1k", 0.0) or 0.0),
        )

    def check_before_call(self) -> None:
        if self.max_calls is not None and self.calls >= self.max_calls:
            raise BudgetExceeded(f"LLM red-team budget exceeded: max_calls={self.max_calls}")
        if self.max_tokens is not None and self.tokens >= self.max_tokens:
            raise BudgetExceeded(f"LLM red-team budget exceeded: max_tokens={self.max_tokens}")
        if self.max_cost_usd is not None and self.cost_usd >= self.max_cost_usd:
            raise BudgetExceeded(f"LLM red-team budget exceeded: max_cost_usd={self.max_cost_usd}")

    def record(self, resp: ProbeResponse) -> None:
        if resp.cached:
            return
        self.calls += 1
        in_tok = int(resp.input_tokens or 0)
        out_tok = int(resp.output_tokens or 0)
        self.tokens += in_tok + out_tok
        self.cost_usd += (
            (in_tok / 1000.0) * self.input_cost_per_1k
            + (out_tok / 1000.0) * self.output_cost_per_1k
        )


def _int_or_none(value: Any) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _float_or_none(value: Any) -> float | None:
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


# ── Lightweight JSONPath ────────────────────────────────────────────

_PATH_RE = re.compile(r"\$|\.[A-Za-z_][A-Za-z0-9_]*|\[\d+\]")


def extract_path(path: str, data: Any) -> Any:
    """Resolve a dotted/indexed JSONPath against a parsed JSON value.

    Supports:
      ``$``                — root
      ``$.a``              — attribute access
      ``$.a.b``            — chained attribute access
      ``$.a[0]``           — array index
      ``$.a[0].b[2].c``    — mixed

    Anything fancier (filters, recursive descent, slices) is rejected
    — promptfoo / langfuse scope; we don't need it for chat APIs.
    Returns ``None`` if any step misses.
    """
    if not path or path == "$":
        return data
    if not path.startswith("$"):
        raise ValueError(f"path must start with $: {path!r}")
    pos = 1
    cur: Any = data
    while pos < len(path):
        m = _PATH_RE.match(path, pos)
        if not m or m.group() == "$":
            raise ValueError(f"unparseable JSONPath segment near {path[pos:]!r}")
        seg = m.group()
        pos = m.end()
        if seg.startswith("."):
            key = seg[1:]
            if isinstance(cur, dict):
                cur = cur.get(key)
            else:
                return None
        elif seg.startswith("["):
            idx = int(seg[1:-1])
            if isinstance(cur, list) and 0 <= idx < len(cur):
                cur = cur[idx]
            else:
                return None
        if cur is None:
            return None
    return cur


# ── Test cases + verdict ────────────────────────────────────────────

class Verdict(str, Enum):
    VULNERABLE = "vulnerable"
    REFUSED = "refused"
    AMBIGUOUS = "ambiguous"


@dataclass
class TestCase:
    """One YAML-defined red-team payload.

    The two regex lists are the engine's verdict. Both are matched
    case-insensitively over the *full* response text (DOTALL); first
    pattern that hits wins for its bucket. ``success_indicators``
    means "the attacker got what they wanted"; ``refusal_patterns``
    means "the model said no". Refusal beats success — a model that
    parrots ``CANARY-2718`` while explicitly refusing has not been
    compromised in any operationally meaningful sense.
    """

    # Tell pytest's auto-collection to leave this dataclass alone —
    # it walks any class whose name starts with "Test" and tries to
    # instantiate it as a test class. ``__test__ = False`` opts out.
    __test__ = False

    id: str
    category: str        # "LLM01" | "LLM02" | "LLM05" | "LLM07" | "LLM10"
    technique: str       # "direct_injection" | "role_play" | …
    title: str
    severity: Severity
    prompt: str
    turns: list[str] = field(default_factory=list)
    system: str | None = None
    success_indicators: list[str] = field(default_factory=list)
    refusal_patterns: list[str] = field(default_factory=list)
    # Optional anchor strings for embedding-similarity grading. When
    # set and an Embedder is configured on the session, a high-cosine
    # match against any anchor counts as VULNERABLE even if no regex
    # success_indicator hit. Refusal patterns still beat embedding.
    success_embeddings: list[str] = field(default_factory=list)
    description: str = ""
    remediation: str = ""
    cwe: str | None = None
    # Free-form metadata — read by Hydra (``hydra_objectives``), the
    # plugin SDK, and any future strategy that needs case-scoped state.
    metadata: dict[str, Any] = field(default_factory=dict)


def evaluate(tc: TestCase, response_text: str) -> Verdict:
    """Pure verdict function. No side effects, no LLM, no network.

    Truth table:

      matched  refused  → VULNERABLE
      matched  ¬refused → VULNERABLE
      ¬matched refused  → REFUSED
      ¬matched ¬refused → AMBIGUOUS

    AMBIGUOUS does *not* emit a finding — that's how we keep this
    feature's false-positive rate at zero."""
    return evaluate_with_reason(tc, response_text)[0]


def evaluate_with_reason(tc: TestCase, response_text: str) -> tuple[Verdict, str]:
    """Same truth table as ``evaluate`` but also returns the regex
    that fired (or a description of why the verdict came out as it
    did). Used by the local transcript-dump instrumentation so users
    can see *why* each probe was scored the way it was."""
    if response_text is None:
        return Verdict.AMBIGUOUS, "ambiguous: response_text was None (transport error or empty body)"
    flags = re.IGNORECASE | re.DOTALL
    refused_pat: str | None = None
    for p in tc.refusal_patterns:
        if re.search(p, response_text, flags):
            refused_pat = p
            break
    matched_pat: str | None = None
    for p in tc.success_indicators:
        if re.search(p, response_text, flags):
            matched_pat = p
            break
    if matched_pat and not refused_pat:
        return Verdict.VULNERABLE, f"vulnerable: success_indicator matched /{matched_pat}/"
    if matched_pat and refused_pat:
        return (
            Verdict.REFUSED,
            f"refused: success /{matched_pat}/ matched but refusal /{refused_pat}/ also matched (refusal beats success)",
        )
    if refused_pat:
        return Verdict.REFUSED, f"refused: refusal_pattern matched /{refused_pat}/"
    return (
        Verdict.AMBIGUOUS,
        "ambiguous: no success_indicator or refusal_pattern matched — verdict pending judge/embedder/factuality if configured",
    )


def _append_tool_call_text(text: str, tool_calls: list[dict[str, Any]]) -> str:
    if not tool_calls:
        return text
    rendered = json.dumps(tool_calls, sort_keys=True, separators=(",", ":"), default=str)
    return (text + "\n\n" if text else "") + f"[tool_calls]\n{rendered}"


def _iter_sse_json(raw_text: str) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for block in re.split(r"\r?\n\r?\n", raw_text.strip()):
        data_lines: list[str] = []
        for line in block.splitlines():
            line = line.strip()
            if not line.startswith("data:"):
                continue
            value = line[5:].strip()
            if value == "[DONE]":
                continue
            data_lines.append(value)
        if not data_lines:
            continue
        try:
            parsed = json.loads("\n".join(data_lines))
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            events.append(parsed)
    return events


# ── LLM probe ───────────────────────────────────────────────────────

class LlmProbe:
    """Async HTTP wrapper that turns a TestCase into a single chat
    request against the configured LLM endpoint.

    Construct once per scan; reuse across all test cases. Carries the
    httpx client so the connection is keep-aliveable and the
    semaphore so concurrency is bounded."""

    def __init__(
        self,
        endpoint: str,
        headers: dict[str, str] | None,
        llm_config: dict[str, Any],
    ):
        self.endpoint = endpoint
        self.headers = dict(headers or {})
        self.headers.setdefault("Content-Type", "application/json")
        self.headers.setdefault(
            "User-Agent", "Mozilla/5.0 (compatible; PencheffLLMRedTeam/0.1)"
        )
        self.cfg = dict(llm_config or {})
        self.provider: str = self.cfg.get("provider", "openai-chat")
        self.model: str | None = self.cfg.get("model")
        self.system_baseline: str | None = self.cfg.get("system_prompt")
        # Per-target ``max_tokens`` override. Falls back to the module
        # default (4096). Reasoning targets that emit big ``<think>``
        # traces typically need 6K–8K to leave room for the visible
        # answer. Cost-bound targets can lower it.
        try:
            self.max_tokens: int = int(self.cfg.get("max_tokens") or _MAX_TOKENS_DEFAULT)
        except (TypeError, ValueError):
            self.max_tokens = _MAX_TOKENS_DEFAULT
        if self.max_tokens <= 0:
            self.max_tokens = _MAX_TOKENS_DEFAULT
        self.timeout = float(self.cfg.get("timeout_s", 30))
        self.concurrency = int(self.cfg.get("concurrency", 5))
        self.retries = max(0, int(self.cfg.get("retries", 0) or 0))
        self.backoff_s = max(0.0, float(self.cfg.get("backoff_s", 0.25) or 0.0))
        self.cache_enabled = bool(self.cfg.get("cache", True))
        self.cache_size = max(0, int(self.cfg.get("cache_size", 256) or 0))
        self._cache: OrderedDict[str, ProbeResponse] = OrderedDict()
        self.budget = ProbeBudget.from_config(self.cfg)
        # Rate limiter: explicit max_rps wins; otherwise derive from
        # max_rpm. A 0 / None value disables throttling. The bucket
        # is *shared* across every LlmProbe targeting the same endpoint
        # at the same rate, so 10 OWASP modules dispatching concurrently
        # don't multiply the effective RPS by 10.
        rps = float(self.cfg.get("max_rps") or 0)
        if rps <= 0:
            rpm = float(self.cfg.get("max_rpm") or 0)
            rps = rpm / 60.0 if rpm > 0 else 0.0
        burst = self.cfg.get("rate_burst")
        self._rate_limiter = _RateLimiter.get_shared(
            endpoint=endpoint,
            rate=rps,
            capacity=float(burst) if burst is not None else None,
        )
        self._sem = asyncio.Semaphore(max(1, self.concurrency))
        self._client: httpx.AsyncClient | None = None
        # Cloud-auth caches (populated lazily on first use; tied to
        # the LlmProbe lifetime so credentials/tokens don't leak
        # between scans).
        self._bedrock_signer: Any | None = None
        self._vertex_auth: Any | None = None
        self._azure_auth: Any | None = None

    async def _get(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(self.timeout),
                follow_redirects=False,
                verify=True,
            )
        return self._client

    async def close(self) -> None:
        if self._client is not None:
            try:
                await self._client.aclose()
            finally:
                self._client = None

    # ── Provider-specific request body shaping ────────────────────

    def _build_openai(
        self,
        prompt: str,
        system: str | None,
        history: list[dict[str, str]] | None = None,
    ) -> dict[str, Any]:
        msgs: list[dict[str, str]] = []
        if system:
            msgs.append({"role": "system", "content": system})
        if history:
            msgs.extend(history)
        msgs.append({"role": "user", "content": prompt})
        body: dict[str, Any] = {"messages": msgs, "max_tokens": self.max_tokens}
        if self.model:
            body["model"] = self.model
        return body

    def _build_custom(
        self,
        prompt: str,
        system: str | None,
        history: list[dict[str, str]] | None = None,
    ) -> dict[str, Any]:
        tpl: str | None = self.cfg.get("request_template")
        if not tpl:
            raise ProviderError("custom provider requires request_template")
        # Substitute the three explicit placeholders. JSON-escape the
        # values so the rendered string is still valid JSON. We
        # render *into* a JSON string and then ``json.loads`` it back
        # — that catches malformed templates fast.
        def _enc(v: str | None) -> str:
            return json.dumps(v if v is not None else "")[1:-1]
        rendered = (
            tpl.replace("{{prompt}}", _enc(prompt))
               .replace("{{system}}", _enc(system))
               .replace("{{model}}", _enc(self.model))
               .replace("{{messages}}", _enc(json.dumps(list(history or []) + [{"role": "user", "content": prompt}], separators=(",", ":"))))
        )
        try:
            return json.loads(rendered)
        except json.JSONDecodeError as e:
            raise ProviderError(
                f"custom request_template did not render to valid JSON: {e}"
            ) from e

    def _extract_openai(self, body: dict[str, Any]) -> tuple[str, int | None, int | None, list[dict[str, Any]]]:
        message = extract_path("$.choices[0].message", body) or {}
        text = message.get("content") if isinstance(message, dict) else ""
        tool_calls: list[dict[str, Any]] = []
        if isinstance(message, dict):
            raw_tool_calls = message.get("tool_calls")
            if isinstance(raw_tool_calls, list):
                tool_calls.extend(x for x in raw_tool_calls if isinstance(x, dict))
            raw_function_call = message.get("function_call")
            if isinstance(raw_function_call, dict):
                tool_calls.append({"type": "function_call", "function": raw_function_call})
        text = _append_tool_call_text(str(text or ""), tool_calls)
        usage = body.get("usage") or {}
        return (
            text,
            usage.get("prompt_tokens"),
            usage.get("completion_tokens"),
            tool_calls,
        )

    def _extract_custom(self, body: Any) -> tuple[str, int | None, int | None, list[dict[str, Any]]]:
        rp: str | None = self.cfg.get("response_path")
        if not rp:
            raise ProviderError("custom provider requires response_path")
        text = extract_path(rp, body) or ""
        return (str(text), None, None, [])

    # ── Cloud-auth provider builders ──────────────────────────────

    def _build_bedrock(
        self,
        prompt: str,
        system: str | None,
        history: list[dict[str, str]] | None,
    ) -> tuple[dict[str, Any], str]:
        from .cloud_auth import build_bedrock_request
        model_id = self.model or self.cfg.get("model_id") or ""
        if not model_id:
            raise ProviderError("bedrock provider requires model (Bedrock model id)")
        return build_bedrock_request(model_id, prompt, system, history)

    def _sign_bedrock(self, body: dict[str, Any]) -> dict[str, str]:
        from .cloud_auth import BedrockSigner
        if self._bedrock_signer is None:
            self._bedrock_signer = BedrockSigner(
                region=str(self.cfg.get("aws_region") or self.cfg.get("region") or "us-east-1"),
                profile=self.cfg.get("aws_profile"),
                access_key_id=self.headers.get("X-AWS-Access-Key-Id") or self.cfg.get("aws_access_key_id"),
                secret_access_key=self.headers.get("X-AWS-Secret-Access-Key") or self.cfg.get("aws_secret_access_key"),
                session_token=self.headers.get("X-AWS-Session-Token") or self.cfg.get("aws_session_token"),
            )
        body_bytes = json.dumps(body, separators=(",", ":")).encode("utf-8")
        # Sanitised header set: SigV4 strips Content-Type if we hand it in
        # already, then re-adds it; we still pass our User-Agent.
        base = {k: v for k, v in self.headers.items()
                if k.lower() in {"user-agent", "content-type", "accept"}}
        return self._bedrock_signer.sign(self.endpoint, body_bytes, base)

    def _build_vertex(
        self,
        prompt: str,
        system: str | None,
        history: list[dict[str, str]] | None,
    ) -> tuple[dict[str, Any], str]:
        from .cloud_auth import build_vertex_request
        return build_vertex_request(prompt, system, history)

    def _auth_vertex(self) -> dict[str, str]:
        from .cloud_auth import VertexAuth
        if self._vertex_auth is None:
            self._vertex_auth = VertexAuth(scopes=self.cfg.get("scopes"))
        token = self._vertex_auth.access_token()
        return {**self.headers, "Authorization": f"Bearer {token}"}

    def _build_azure_openai(
        self,
        prompt: str,
        system: str | None,
        history: list[dict[str, str]] | None,
    ) -> tuple[dict[str, Any], str]:
        from .cloud_auth import build_azure_openai_request
        return build_azure_openai_request(self.model, prompt, system, history)

    def _auth_azure(self) -> dict[str, str]:
        # Allow api-key auth via Authorization / api-key header
        # to bypass DefaultAzureCredential — useful for shared keys
        # in test deployments.
        if self.headers.get("api-key") or self.headers.get("Authorization"):
            return self.headers
        from .cloud_auth import AzureOpenAIAuth
        if self._azure_auth is None:
            self._azure_auth = AzureOpenAIAuth()
        token = self._azure_auth.access_token()
        return {**self.headers, "Authorization": f"Bearer {token}"}

    def _extract_streaming(self, raw_text: str) -> tuple[str, int | None, int | None, list[dict[str, Any]]]:
        """Extract text and tool-call deltas from common SSE chat streams."""
        text_parts: list[str] = []
        tool_calls: list[dict[str, Any]] = []
        for event in _iter_sse_json(raw_text):
            if self.provider == "openai-chat":
                delta = extract_path("$.choices[0].delta", event) or {}
                if isinstance(delta, dict):
                    if delta.get("content"):
                        text_parts.append(str(delta["content"]))
                    if isinstance(delta.get("tool_calls"), list):
                        tool_calls.extend(x for x in delta["tool_calls"] if isinstance(x, dict))
                    if isinstance(delta.get("function_call"), dict):
                        tool_calls.append({"type": "function_call", "function": delta["function_call"]})
        text = _append_tool_call_text("".join(text_parts), tool_calls)
        return text, None, None, tool_calls

    async def _chat_executable(
        self,
        prompt: str,
        system: str | None,
        history: list[dict[str, str]] | None = None,
    ) -> ProbeResponse:
        """Run a local executable provider.

        The command receives a JSON object on stdin and may return either
        plain text or JSON. If ``response_path`` is configured, stdout is
        parsed as JSON and that path is extracted.
        """
        command = self.cfg.get("command")
        if not isinstance(command, list) or not command:
            raise ProviderError("executable provider requires command: list[str]")
        if not all(isinstance(part, str) and part for part in command):
            raise ProviderError("executable provider command must contain non-empty strings")

        payload = {
            "prompt": prompt,
            "system": system or "",
            "model": self.model or "",
            "messages": list(history or []) + [{"role": "user", "content": prompt}],
            "metadata": self.cfg.get("metadata") or {},
        }
        body_str = json.dumps(payload, separators=(",", ":"))
        await self._rate_limiter.acquire()
        async with self._sem:
            t0 = time.perf_counter()
            proc = await asyncio.create_subprocess_exec(
                *command,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(body_str.encode("utf-8")),
                    timeout=self.timeout,
                )
            except asyncio.TimeoutError:
                proc.kill()
                await proc.communicate()
                raise
            elapsed = int((time.perf_counter() - t0) * 1000)

        raw_out = stdout.decode("utf-8", errors="replace")
        raw_err = stderr.decode("utf-8", errors="replace")
        text = raw_out
        response_path = self.cfg.get("response_path")
        if response_path:
            try:
                parsed = json.loads(raw_out)
                text = str(extract_path(str(response_path), parsed) or "")
            except Exception as exc:  # noqa: BLE001
                raise ProviderError(f"failed to extract executable response text: {exc}") from exc
        return ProbeResponse(
            text=text,
            http_status=0 if proc.returncode == 0 else int(proc.returncode or 1),
            request_body=body_str,
            response_body=raw_out + (f"\n[stderr]\n{raw_err}" if raw_err else ""),
            latency_ms=elapsed,
        )

    async def _chat_browser(
        self,
        prompt: str,
        system: str | None,
        history: list[dict[str, str]] | None = None,
    ) -> ProbeResponse:
        """Drive a chat UI via Playwright.

        Required ``llm_config.browser`` shape:

            {
              "url": "https://chat.example.com/...",
              "prompt_selector": "textarea[name='message']",
              "send_selector": "button[type='submit']",
              "response_selector": ".chat-message.assistant.last",
              "ready_wait_selector": ".chat-message.assistant.streaming.done"  # optional
            }

        Auth headers ride on the standard credentials block. ``Cookie``
        becomes a navigated cookie set; everything else is sent as
        request headers via Playwright's ``set_extra_http_headers``.
        Concurrency is the same semaphore-bounded budget as HTTP
        probes — Playwright pages are expensive so users typically
        cap concurrency at 1-2 for browser providers.
        """
        try:
            from playwright.async_api import async_playwright
        except ImportError as exc:  # pragma: no cover - declared in pyproject
            raise ProviderError("browser provider requires the playwright package") from exc

        browser_cfg = self.cfg.get("browser") or {}
        if not isinstance(browser_cfg, dict):
            raise ProviderError("browser provider requires browser config dict")
        url = str(browser_cfg.get("url") or self.endpoint or "")
        prompt_selector = str(browser_cfg.get("prompt_selector") or "")
        send_selector = str(browser_cfg.get("send_selector") or "")
        response_selector = str(browser_cfg.get("response_selector") or "")
        if not (url and prompt_selector and send_selector and response_selector):
            raise ProviderError(
                "browser provider requires url, prompt_selector, send_selector, response_selector"
            )
        ready_selector = browser_cfg.get("ready_wait_selector")

        # Compose the user-visible prompt: include system + history
        # inline since most chat UIs have one input box.
        composed = []
        if system:
            composed.append(f"[system] {system}")
        for msg in history or []:
            composed.append(f"[{msg.get('role','user')}] {msg.get('content','')}")
        composed.append(prompt)
        full_prompt = "\n\n".join(composed)

        # Cookie header → cookie list.
        cookies = []
        cookie_hdr = self.headers.get("Cookie") or self.headers.get("cookie")
        if cookie_hdr:
            for pair in cookie_hdr.split(";"):
                if "=" in pair:
                    name, _, value = pair.partition("=")
                    cookies.append({
                        "name": name.strip(), "value": value.strip(),
                        "url": url,
                    })
        extra_headers = {k: v for k, v in self.headers.items()
                         if k.lower() not in {"cookie", "content-type"}}

        await self._rate_limiter.acquire()
        async with self._sem:
            t0 = time.perf_counter()
            response_text = ""
            status_code = 200
            try:
                async with async_playwright() as p:
                    browser = await p.chromium.launch(headless=True)
                    context = await browser.new_context(extra_http_headers=extra_headers)
                    if cookies:
                        await context.add_cookies(cookies)
                    page = await context.new_page()
                    await page.goto(url, timeout=int(self.timeout * 1000), wait_until="domcontentloaded")
                    # Capture last-known response text by selector
                    # *before* sending so we can diff after the model
                    # replies — this avoids returning a stale message.
                    try:
                        before = await page.locator(response_selector).last.text_content(timeout=2000)
                    except Exception:
                        before = None
                    await page.fill(prompt_selector, full_prompt)
                    await page.click(send_selector)
                    if ready_selector:
                        await page.wait_for_selector(str(ready_selector), timeout=int(self.timeout * 1000))
                    else:
                        # Fallback: wait until the response_selector text changes.
                        await page.wait_for_function(
                            "(args) => { const el = document.querySelectorAll(args[0]); return el.length && el[el.length-1].innerText && el[el.length-1].innerText !== args[1]; }",
                            arg=[response_selector, before or ""],
                            timeout=int(self.timeout * 1000),
                        )
                    response_text = await page.locator(response_selector).last.text_content(timeout=int(self.timeout * 1000)) or ""
                    await context.close()
                    await browser.close()
            except Exception as exc:  # noqa: BLE001
                raise ProviderError(f"browser provider failed: {exc}") from exc
            elapsed = int((time.perf_counter() - t0) * 1000)

        return ProbeResponse(
            text=response_text.strip(),
            http_status=status_code,
            request_body=full_prompt,
            response_body=response_text,
            latency_ms=elapsed,
        )

    async def _chat_websocket(
        self,
        prompt: str,
        system: str | None,
        history: list[dict[str, str]] | None = None,
    ) -> ProbeResponse:
        """Send one chat request to a WebSocket backend."""
        try:
            import websockets
        except ImportError as exc:  # pragma: no cover - dependency is declared
            raise ProviderError("websocket provider requires the websockets package") from exc

        if self.cfg.get("request_template"):
            body = self._build_custom(prompt, system, history)
        else:
            body = self._build_openai(prompt, system, history)
        body_str = json.dumps(body, separators=(",", ":"))
        response_messages: list[str] = []
        max_messages = max(1, int(self.cfg.get("max_messages", 1) or 1))
        await self._rate_limiter.acquire()
        async with self._sem:
            t0 = time.perf_counter()
            try:
                async with websockets.connect(
                    self.endpoint,
                    additional_headers={k: v for k, v in self.headers.items() if k.lower() != "content-type"},
                    open_timeout=self.timeout,
                    close_timeout=min(self.timeout, 5.0),
                    max_size=int(self.cfg.get("max_message_bytes", 4 * 1024 * 1024) or 4 * 1024 * 1024),
                ) as ws:
                    await asyncio.wait_for(ws.send(body_str), timeout=self.timeout)
                    for _ in range(max_messages):
                        msg = await asyncio.wait_for(ws.recv(), timeout=self.timeout)
                        if isinstance(msg, bytes):
                            msg = msg.decode("utf-8", errors="replace")
                        response_messages.append(str(msg))
                        if self.cfg.get("stop_after_first", True):
                            break
            except Exception as exc:  # noqa: BLE001
                raise ProviderError(f"websocket provider failed: {exc}") from exc
            elapsed = int((time.perf_counter() - t0) * 1000)

        raw_text = "\n".join(response_messages)
        text = raw_text
        tool_calls: list[dict[str, Any]] = []
        response_path = self.cfg.get("response_path")
        try:
            parsed = json.loads(raw_text)
        except json.JSONDecodeError:
            parsed = None
        if response_path and parsed is not None:
            text = str(extract_path(str(response_path), parsed) or "")
        elif isinstance(parsed, dict):
            if "choices" in parsed:
                text, _in_tok, _out_tok, tool_calls = self._extract_openai(parsed)
        return ProbeResponse(
            text=text,
            http_status=101,
            request_body=body_str,
            response_body=raw_text,
            latency_ms=elapsed,
            tool_calls=tool_calls,
        )

    async def _chat_sema4(
        self,
        prompt: str,
        system: str | None,
        history: list[dict[str, str]] | None = None,
    ) -> ProbeResponse:
        """Sema4 conversational-agent provider.

        ``self.endpoint`` is the agent base URL (``/agents/{id}``); auth rides on
        ``self.headers``. The agent has no single-shot invoke — a turn is:
          1. POST {base}/conversations {"name": ...}            -> conversation id
          2. POST {base}/conversations/{id}/messages {"content": prompt}
          3. poll GET {base}/conversations/{id}/messages until the role=="agent"
             message is complete; concatenate its text-kind content blocks.
        A fresh conversation per turn keeps red-team probes independent (no
        cross-prompt context bleed). ``system`` is prepended to the prompt since
        the API takes no separate system field."""
        base = self.endpoint.rstrip("/")
        hdrs = dict(self.headers)
        hdrs.setdefault("Content-Type", "application/json")
        hdrs.setdefault("Accept", "application/json")
        user_text = f"{system}\n\n{prompt}" if system else prompt
        req_body = json.dumps({"content": user_text}, separators=(",", ":"))
        poll_interval = float(self.cfg.get("poll_interval_s", 1.5) or 1.5)
        # These agents are slow (tens of seconds/turn, more on adversarial
        # prompts), so the generic 30s probe timeout trips empty-message httpx
        # ReadTimeouts. Give the HTTP calls and the completion poll a generous,
        # separately-tunable ceiling.
        agent_timeout = float(self.cfg.get("agent_timeout_s", 180) or 180)
        text, status, last_body = "", 0, ""
        await self._rate_limiter.acquire()
        async with self._sem:
            client = await self._get()
            t0 = time.perf_counter()
            try:
                cr = await client.post(
                    f"{base}/conversations", headers=hdrs, timeout=agent_timeout,
                    content=json.dumps({"name": f"pencheff-{uuid.uuid4().hex[:12]}"}),
                )
                cr.raise_for_status()
                cid = cr.json()["id"]
                mr = await client.post(
                    f"{base}/conversations/{cid}/messages", headers=hdrs,
                    content=req_body, timeout=agent_timeout,
                )
                mr.raise_for_status()
                status, last_body = mr.status_code, mr.text
                deadline = t0 + agent_timeout
                while time.perf_counter() < deadline:
                    gr = await client.get(
                        f"{base}/conversations/{cid}/messages",
                        headers=hdrs, timeout=agent_timeout,
                    )
                    status, last_body = gr.status_code, gr.text
                    agent_msgs = [m for m in (gr.json() or {}).get("data", []) if m.get("role") == "agent"]
                    if agent_msgs and agent_msgs[-1].get("complete"):
                        text = "".join(
                            b.get("text", "") for b in agent_msgs[-1].get("content", [])
                            if isinstance(b, dict) and b.get("kind") == "text"
                        )
                        break
                    await asyncio.sleep(poll_interval)
            except Exception as exc:  # noqa: BLE001
                raise ProviderError(
                    f"sema4_agent provider failed: {type(exc).__name__}: {exc}"
                ) from exc
            elapsed = int((time.perf_counter() - t0) * 1000)
        return ProbeResponse(
            text=text,
            http_status=status,
            request_body=req_body,
            response_body=last_body[:8000],
            latency_ms=elapsed,
        )

    def _cache_key(
        self,
        prompt: str,
        system: str | None,
        history: list[dict[str, str]] | None = None,
    ) -> str:
        return json.dumps(
            {
                "provider": self.provider,
                "endpoint": self.endpoint,
                "model": self.model,
                "system": system or "",
                "history": history or [],
                "prompt": prompt,
                "request_template": self.cfg.get("request_template"),
                "response_path": self.cfg.get("response_path"),
                "command": self.cfg.get("command"),
            },
            sort_keys=True,
            default=str,
        )

    def _cache_get(self, key: str) -> ProbeResponse | None:
        if not self.cache_enabled or self.cache_size <= 0:
            return None
        hit = self._cache.get(key)
        if hit is None:
            return None
        self._cache.move_to_end(key)
        return ProbeResponse(
            text=hit.text,
            http_status=hit.http_status,
            request_body=hit.request_body,
            response_body=hit.response_body,
            latency_ms=0,
            input_tokens=hit.input_tokens,
            output_tokens=hit.output_tokens,
            cached=True,
            tool_calls=list(hit.tool_calls),
        )

    def _cache_put(self, key: str, resp: ProbeResponse) -> None:
        if not self.cache_enabled or self.cache_size <= 0 or resp.cached:
            return
        self._cache[key] = resp
        self._cache.move_to_end(key)
        while len(self._cache) > self.cache_size:
            self._cache.popitem(last=False)

    def _record_budget(self, resp: ProbeResponse) -> None:
        if self.budget is not None:
            self.budget.record(resp)

    # ── Chat ───────────────────────────────────────────────────────

    async def chat(
        self,
        prompt: str,
        system: str | None = None,
        history: list[dict[str, str]] | None = None,
    ) -> ProbeResponse:
        """Send one chat turn. ``system`` overrides the configured
        system_baseline if both are set; passing None falls back to
        the baseline."""
        effective_system = system if system is not None else self.system_baseline
        key = self._cache_key(prompt, effective_system, history)
        cached = self._cache_get(key)
        if cached is not None:
            return cached
        if self.budget is not None:
            self.budget.check_before_call()
        # Override per-call when cloud-auth providers need dynamic
        # signing / token refresh per request.
        per_call_headers: dict[str, str] | None = None
        if self.provider == "openai-chat":
            body = self._build_openai(prompt, effective_system, history)
            extractor = self._extract_openai
        elif self.provider == "custom":
            body = self._build_custom(prompt, effective_system, history)
            extractor = self._extract_custom
        elif self.provider == "bedrock":
            body, response_path = self._build_bedrock(prompt, effective_system, history)
            # Reuse the generic JSONPath extractor by stashing the
            # response_path on cfg so _extract_custom resolves it.
            self.cfg["response_path"] = response_path
            extractor = self._extract_custom
            per_call_headers = self._sign_bedrock(body)
        elif self.provider == "vertex":
            body, response_path = self._build_vertex(prompt, effective_system, history)
            self.cfg["response_path"] = response_path
            extractor = self._extract_custom
            per_call_headers = self._auth_vertex()
        elif self.provider == "azure-openai":
            body, response_path = self._build_azure_openai(prompt, effective_system, history)
            self.cfg["response_path"] = response_path
            extractor = self._extract_custom
            per_call_headers = self._auth_azure()
        elif self.provider == "executable":
            resp = await self._chat_executable(prompt, effective_system, history)
            self._cache_put(key, resp)
            self._record_budget(resp)
            return resp
        elif self.provider == "websocket":
            resp = await self._chat_websocket(prompt, effective_system, history)
            self._cache_put(key, resp)
            self._record_budget(resp)
            return resp
        elif self.provider == "browser":
            resp = await self._chat_browser(prompt, effective_system, history)
            self._cache_put(key, resp)
            self._record_budget(resp)
            return resp
        elif self.provider == "sema4_agent":
            resp = await self._chat_sema4(prompt, effective_system, history)
            self._cache_put(key, resp)
            self._record_budget(resp)
            return resp
        else:
            # Unknown provider — last-chance plugin lookup.
            from .plugins import discover_plugins, get_provider
            discover_plugins()
            cls = get_provider(self.provider)
            if cls is not None:
                resp = await cls(self.cfg, self.endpoint, self.headers).chat(prompt, effective_system, history)  # type: ignore[misc]
                self._cache_put(key, resp)
                self._record_budget(resp)
                return resp
            raise ProviderError(f"unknown provider {self.provider!r}")

        body_str = json.dumps(body, separators=(",", ":"))
        # Cloud-auth providers compute headers once per call (Bedrock
        # SigV4 includes a body hash; Vertex/Azure refresh the bearer
        # token if it expired). For all other providers,
        # ``per_call_headers`` is None and we fall back to the
        # session-wide self.headers.
        request_headers = per_call_headers if per_call_headers is not None else self.headers
        last_error: httpx.HTTPError | None = None
        resp: httpx.Response | None = None
        elapsed = 0
        for attempt in range(self.retries + 1):
            await self._rate_limiter.acquire()
            async with self._sem:
                client = await self._get()
                t0 = time.perf_counter()
                try:
                    resp = await client.post(
                        self.endpoint, content=body_str, headers=request_headers
                    )
                except httpx.HTTPError as e:
                    last_error = e
                    resp = None
                elapsed = int((time.perf_counter() - t0) * 1000)
            if resp is not None and resp.status_code not in {429, 500, 502, 503, 504}:
                break
            if attempt < self.retries:
                # On 429, prefer the upstream Retry-After hint over our
                # exponential backoff — the provider knows when its
                # window resets, we don't. Stall the *shared* limiter
                # so concurrent in-flight retries from other modules
                # also wait, otherwise the next probe race-fires
                # immediately and triggers another 429.
                wait_s = self.backoff_s * (2 ** attempt)
                if resp is not None and resp.status_code == 429:
                    hint = resp.headers.get("retry-after") or resp.headers.get("Retry-After")
                    if hint:
                        try:
                            wait_s = max(wait_s, float(hint))
                        except (TypeError, ValueError):
                            # HTTP-date format isn't worth the parse cost
                            # for our use case; fall back to backoff.
                            pass
                    # Cap so a malformed/oversized hint can't stall the
                    # entire scan past the per-stage timeout.
                    wait_s = min(wait_s, 60.0)
                    self._rate_limiter.stall_until(time.perf_counter() + wait_s)
                await asyncio.sleep(wait_s)
        if resp is None:
            try:
                raise last_error or httpx.TransportError("unknown transport error")
            except httpx.HTTPError as e:
                raise ProviderError(f"transport error: {type(e).__name__}: {e}") from e

        # Capture body even on non-2xx — error responses still carry
        # useful evidence for the report.
        raw_text = resp.text
        try:
            parsed = resp.json()
        except (json.JSONDecodeError, ValueError):
            parsed = None

        is_sse = "text/event-stream" in resp.headers.get("content-type", "").lower()
        if resp.is_success and is_sse:
            text, in_tok, out_tok, tool_calls = self._extract_streaming(raw_text)
        elif resp.is_success and parsed is not None:
            try:
                text, in_tok, out_tok, tool_calls = extractor(parsed)
            except Exception as exc:  # noqa: BLE001
                raise ProviderError(
                    f"failed to extract response text: {exc}"
                ) from exc
        else:
            # Non-2xx, or 2xx with non-JSON body. Either way, return
            # an empty ``text`` so the verdict function falls
            # through to AMBIGUOUS — these aren't compromise signals.
            text, in_tok, out_tok, tool_calls = "", None, None, []

        out = ProbeResponse(
            text=text,
            http_status=resp.status_code,
            request_body=body_str,
            response_body=raw_text,
            latency_ms=elapsed,
            input_tokens=in_tok,
            output_tokens=out_tok,
            tool_calls=tool_calls,
        )
        self._cache_put(key, out)
        self._record_budget(out)
        return out

    async def chat_turns(self, turns: list[str], system: str | None = None) -> ProbeResponse:
        """Send a multi-turn attack, carrying assistant replies as history."""
        if not turns:
            return await self.chat("", system=system)
        history: list[dict[str, str]] = []
        last: ProbeResponse | None = None
        for idx, turn in enumerate(turns):
            last = await self.chat(turn, system=system, history=history)
            if idx < len(turns) - 1:
                history.append({"role": "user", "content": turn})
                history.append({"role": "assistant", "content": last.text})
        assert last is not None
        return last
