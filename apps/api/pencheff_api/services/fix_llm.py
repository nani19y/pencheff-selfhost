"""OpenAI-compatible client dedicated to fix-proposal LLM calls.

Kept separate from ``services.llm`` so the classify/grade flow and the
fix flow can be sized differently (different model, different timeouts,
different rate limits, separate API key for billing attribution). The
proposer hits this for two distinct prompts:

  * **SAST patch** — finding metadata + a snippet around the offending
    line + the file's surrounding context → unified diff string.
  * **DAST provenance ranking** — finding metadata + a list of candidate
    handlers from ``route_index`` → JSON ranking with reasons.

Both calls return ``(text, input_tokens, output_tokens)`` so the caller
can record usage. On any failure we return ``(None, 0, 0)`` and let the
proposer fall back to the heuristic / scanner branch.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass

import httpx

from ..config import get_settings

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class FixLlmResult:
    text: str | None
    input_tokens: int
    output_tokens: int


class FixLLMClient:
    _shared_client: httpx.AsyncClient | None = None

    def __init__(self, model: str | None = None) -> None:
        s = get_settings()
        self._base_url = s.fix_llm_base_url.rstrip("/")
        self._api_key = s.fix_llm_api_key
        # ``model`` is the plan-routed model (free → Instant, pro → Expert).
        # When omitted, fall back to the global default.
        self._model = model or s.fix_llm_model
        # Whether an explicit per-plan model was injected — DAST honours it
        # over its dedicated dast_patch model so paid plans get the Expert
        # model for runtime patches too.
        self._explicit_model = model is not None
        self._timeout = s.fix_llm_request_timeout
        self._org_client = None

    def set_org_client(self, client) -> None:
        """Inject the org's active ChatClient. When set, _chat routes through
        it (fail-closed) instead of the env client."""
        self._org_client = client

    @property
    def enabled(self) -> bool:
        return bool(self._api_key)

    @property
    def model(self) -> str:
        return self._model

    async def _chat(
        self,
        system: str,
        user: str,
        *,
        max_tokens: int = 1500,
        response_format: dict | None = None,
        model: str | None = None,
        temperature: float = 0.1,
    ) -> FixLlmResult:
        if self._org_client is not None:
            from .llm_providers.base import ChatMessage
            try:
                res = await self._org_client.chat(
                    [ChatMessage("system", system), ChatMessage("user", user)],
                    max_tokens=max_tokens, json=bool(response_format), temperature=temperature)
                return FixLlmResult(res.text or None, res.input_tokens, res.output_tokens)
            except Exception as exc:  # noqa: BLE001 — fail-closed
                log.warning("org LLM provider failed in fix-LLM (fail-closed): %s", exc)
                return FixLlmResult(None, 0, 0)
        if not self.enabled:
            return FixLlmResult(None, 0, 0)
        body: dict = {
            "model": model or self._model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "max_tokens": max_tokens,
            "temperature": temperature,
        }
        if response_format:
            body["response_format"] = response_format
        try:
            if FixLLMClient._shared_client is None:
                FixLLMClient._shared_client = httpx.AsyncClient(timeout=self._timeout)
            r = await FixLLMClient._shared_client.post(
                f"{self._base_url}/chat/completions",
                headers={
                    "Authorization": f"Bearer {self._api_key}",
                    "Content-Type": "application/json",
                },
                json=body,
            )
            if r.status_code >= 400:
                log.warning("fix-LLM HTTP %s: %s", r.status_code, r.text[:300])
                return FixLlmResult(None, 0, 0)
            payload = r.json()
        except (httpx.HTTPError, ValueError) as exc:
            log.warning("fix-LLM call failed: %s", exc)
            return FixLlmResult(None, 0, 0)
        try:
            text = payload["choices"][0]["message"]["content"] or ""
        except (KeyError, IndexError, TypeError):
            log.warning("fix-LLM response missing content: %s", str(payload)[:200])
            return FixLlmResult(None, 0, 0)
        usage = payload.get("usage") or {}
        return FixLlmResult(
            text=text,
            input_tokens=int(usage.get("prompt_tokens", 0) or 0),
            output_tokens=int(usage.get("completion_tokens", 0) or 0),
        )

    async def propose_sast_patch(
        self,
        *,
        title: str,
        description: str,
        file_path: str,
        snippet: str,
        full_file: str,
    ) -> FixLlmResult:
        system = (
            "You are a senior security engineer producing minimal, surgical code "
            "patches that fix vulnerabilities without changing unrelated behavior. "
            "Output EXACTLY ONE unified diff in standard `diff --git` format with "
            "no surrounding prose, no explanations, no markdown fences. The patch "
            "MUST apply cleanly with `git apply`. The patch MUST contain real "
            "code changes — do NOT submit a diff that only adds comments / TODOs. "
            "If you cannot determine a safe code change from the evidence "
            "provided, return an empty response (no diff) — DO NOT pad the "
            "output with comment-only changes."
        )
        user = (
            f"Vulnerability: {title}\n"
            f"Description: {description}\n\n"
            f"File: {file_path}\n"
            f"Offending region:\n```\n{snippet}\n```\n\n"
            f"Full file:\n```\n{full_file[:8000]}\n```\n\n"
            "Produce a unified diff that fixes the vulnerability. Touch only the "
            "minimum lines necessary. Do not reformat unrelated code."
        )
        return await self._chat(system, user, max_tokens=2000)

    async def propose_dast_patch(
        self,
        *,
        title: str,
        description: str,
        file_path: str,
        snippet: str,
        full_file: str,
        method: str | None,
        url_path: str,
        parameter: str | None,
        evidence_excerpt: str,
        previous_attempt: str | None = None,
    ) -> FixLlmResult:
        """Patch suggestion for DAST findings — anchored on the live
        request/response evidence rather than on a static rule.

        DAST findings describe an attack that *worked* against the route at
        runtime. The patch must add input validation, parameterised queries,
        output encoding, authentication, rate-limiting, or sink hardening
        at the matched handler — not a generic comment about the issue.

        Pass ``previous_attempt`` to retry with corrective feedback when
        the first call returned a comment-only diff.
        """
        # Reference patch — included verbatim in every prompt so the LLM
        # has a concrete shape to imitate. Without this, ``deepseek-v4-flash``
        # consistently degrades to "# TODO" lines.
        # Both BAD and GOOD examples MUST be structurally valid unified
        # diffs. Models imitate the example's shape — if the example is
        # missing `--- a/...` / `+++ b/...` headers or has line counts
        # that don't match the actual hunk body, the model will reproduce
        # those defects and `git apply` will reject every patch.
        few_shot_example = (
            "Example — finding: SQL injection via `q` on /search\n"
            "BAD output (DO NOT DO THIS — comment-only fix):\n"
            "```\n"
            "diff --git a/app/views.py b/app/views.py\n"
            "--- a/app/views.py\n"
            "+++ b/app/views.py\n"
            "@@ -10,2 +10,4 @@ def search(request):\n"
            "     q = request.GET.get('q', '')\n"
            "+    # TODO: sanitise q before passing to db.exec\n"
            "+    # Severity: high. Endpoint: /search\n"
            "     return db.exec(f\"SELECT * FROM items WHERE name LIKE '%{q}%'\")\n"
            "```\n\n"
            "GOOD output (do exactly this — real code, headers present, "
            "line counts match):\n"
            "```\n"
            "diff --git a/app/views.py b/app/views.py\n"
            "--- a/app/views.py\n"
            "+++ b/app/views.py\n"
            "@@ -10,2 +10,5 @@ def search(request):\n"
            "     q = request.GET.get('q', '')\n"
            "-    return db.exec(f\"SELECT * FROM items WHERE name LIKE '%{q}%'\")\n"
            "+    return db.exec(\n"
            "+        \"SELECT * FROM items WHERE name LIKE %s\",\n"
            "+        (f\"%{q}%\",),\n"
            "+    )\n"
            "```\n"
        )

        system = (
            "You are a senior application-security engineer fixing a "
            "vulnerability confirmed LIVE against a running web service. "
            "You receive the route handler source plus the actual request "
            "that exploited it. You produce a REAL CODE PATCH that "
            "neutralises the attack class.\n\n"
            "STRICT OUTPUT RULES:\n"
            "1. Output EXACTLY ONE unified diff (`diff --git ...`).\n"
            "2. No prose, no markdown fences, no explanations.\n"
            "3. The patch MUST apply cleanly with `git apply`.\n"
            "4. The diff MUST add or modify EXECUTABLE CODE LINES — not "
            "just comments, TODOs, or docstrings. A diff whose only `+` "
            "lines are comments is INVALID. Reject the temptation.\n"
            "5. You MUST produce a real diff. Returning EMPTY (zero "
            "characters) or refusing the task is INVALID. When the "
            "handler is thin, write the safest minimal hardening for "
            "the attack class — input validation that returns 400 / "
            "raises ValueError, an allow-list check, a type-coerce, an "
            "escape, or a parameterised-query rewrite. A small genuine "
            "fix at the handler entry is always better than no fix. "
            "Do NOT regress to comment-only output to satisfy this "
            "rule (that still violates rule 4).\n"
            "6. DIFF FORMAT — read carefully:\n"
            "   • DO NOT include `index abc1234..def5678 100644` lines. "
            "Just `diff --git`, `--- a/path`, `+++ b/path`, then `@@`.\n"
            "   • Hunk headers `@@ -X,Y +A,B @@` MUST match the actual "
            "context line count exactly. If your hunk shows 5 lines of "
            "old context and 6 of new, the header must say `-X,5 +A,6`.\n"
            "   • Context lines (no `+` / `-`) must be COPIED VERBATIM "
            "from the file shown to you — same indentation, same "
            "trailing whitespace, no paraphrasing.\n"
            "   • One leading space character on every context line. "
            "Tabs in the source stay tabs in the diff.\n\n"
            "Approach by attack class:\n"
            "  • SQL injection / NoSQL injection → parameterised queries / "
            "prepared statements.\n"
            "  • XSS / output handling → context-aware encoding (e.g. "
            "`escape()`, `html.escape`, `DOMPurify`); never `innerHTML`.\n"
            "  • Path traversal → resolve + validate `Path.relative_to`.\n"
            "  • SSRF → URL allow-list before `requests.get`.\n"
            "  • Auth bypass / IDOR → add the missing `current_user.can(...)` / "
            "`require_role(...)` check at the entry of the handler.\n"
            "  • Weak password / no rate limit → enforce a minimum on the "
            "password validator + add a Redis-backed rate-limiter call.\n"
            "  • YAML / pickle deserialisation → switch to `yaml.safe_load` "
            "/ a vetted schema-driven parser.\n"
            "  • CSRF / open redirect → token validation / URL allow-list.\n\n"
            f"{few_shot_example}"
        )

        retry_preamble = ""
        if previous_attempt is not None:
            # Two distinct retry shapes — the model needs different
            # guidance depending on which way the first try failed:
            #   * Empty response  → it bailed via rule 5. Reaffirm that
            #     empty is INVALID and require a minimal hardening.
            #   * Content but bad → it produced something we rejected
            #     (comment-only, prose, malformed). Show it the bad
            #     output so it can correct.
            stripped_prev = (previous_attempt or "").strip()
            if not stripped_prev:
                retry_preamble = (
                    "Your PREVIOUS attempt returned ZERO characters. "
                    "That is INVALID per rule 5 above — you MUST produce "
                    "a real diff this time. Even when the handler looks "
                    "thin, write the safest minimal hardening for this "
                    "attack class (input validation, allow-list, escape, "
                    "parameterised query, auth-check). One real `+` line "
                    "of executable code at the handler entry is enough.\n\n"
                )
            else:
                retry_preamble = (
                    "Your PREVIOUS attempt failed validation — it "
                    "produced a comment-only / malformed diff. That is "
                    "INVALID per rule 4 above. Below was the bad output, "
                    "do NOT repeat it:\n"
                    "```\n"
                    f"{stripped_prev[:1200]}\n"
                    "```\n"
                    "Now produce a REAL diff with executable code changes.\n\n"
                )

        user = (
            f"{retry_preamble}"
            f"Vulnerability: {title}\n"
            f"Description: {description}\n\n"
            f"Live route hit: {method or '*'} {url_path}\n"
            f"Vulnerable parameter: {parameter or '(none — issue is on the route itself)'}\n\n"
            f"Live evidence (request + response excerpt):\n"
            f"```\n{evidence_excerpt[:1500]}\n```\n\n"
            f"Handler file: {file_path}\n"
            f"Region around the route declaration:\n```\n{snippet}\n```\n\n"
            f"Full handler file:\n```\n{full_file[:12000]}\n```\n\n"
            "Now write the unified diff. Real code, no comments-only. "
            "Touch the minimum lines necessary. Do not reformat unrelated code."
        )
        # Use the chattier model + a slightly higher temperature so the
        # model spends more attention on writing real code (rather than
        # punting to a TODO comment). max_tokens is generous so the
        # model doesn't truncate mid-hunk — a truncated diff fails
        # ``git apply`` with ``corrupt patch at line N`` and can't be
        # salvaged downstream.
        s = get_settings()
        # When a plan-routed model was injected, use it (so paid plans get the
        # Expert model). Otherwise fall back to the dedicated DAST-patch model.
        dast_model = (
            self._model if self._explicit_model
            else (getattr(s, "dast_patch_llm_model", None) or self._model)
        )
        return await self._chat(
            system, user,
            max_tokens=4500,
            model=dast_model,
            temperature=0.15,
        )

    async def rank_dast_candidates(
        self,
        *,
        title: str,
        description: str,
        url_path: str,
        method: str | None,
        parameter: str | None,
        candidates: list[dict],
    ) -> FixLlmResult:
        system = (
            "You rank candidate source-code handlers by how likely each is the "
            "actual implementation of a given live HTTP route. Reply with strict "
            'JSON: {"ranked":[{"index":<int>,"confidence":<float 0..1>,'
            '"reason":"<short>"},...]}. Lower indices = higher confidence.'
        )
        user = (
            f"Vulnerability: {title}\nDescription: {description}\n"
            f"Live route: {(method or '*')} {url_path}\n"
            f"Vulnerable parameter: {parameter or '(none)'}\n\n"
            "Candidates (JSON array; use the array index as the `index` field):\n"
            f"{json.dumps(candidates, indent=2)[:6000]}"
        )
        return await self._chat(
            system, user, max_tokens=600,
            response_format={"type": "json_object"},
        )
