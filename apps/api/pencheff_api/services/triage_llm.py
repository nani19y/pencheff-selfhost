"""DeepSeek-backed AI Triage 2.0 — per-finding exploitability walkthrough.

This is *the* Pro-tier feature: take a finding plus its live evidence
(DAST request/response, SAST code snippet, SCA dependency context) and
produce a structured walkthrough that explains:

  * **walkthrough**     — markdown narrative the dev can read in 30s.
  * **blast_radius**    — what happens if this gets exploited (DB dumped?
                          SSRF to cloud metadata? data-only access?).
  * **exploit_scenario**— concrete step-by-step attack path the LLM is
                          willing to assert is feasible given the evidence.
  * **fix_outline**     — high-level remediation plan in prose. The
                          deterministic patch is the fix-proposer's job;
                          this is the *narrative* of the fix.
  * **confidence**      — low / medium / high — the LLM's self-rated
                          confidence in the walkthrough's accuracy. Helps
                          reviewers know when to trust the output vs
                          dig in themselves.

The model defaults to ``deepseek-chat`` via the OpenAI-compatible
DeepSeek API (``api.deepseek.com/v1``). The client reuses the
``fix_llm_*`` settings so a single API key covers both the fix proposer
and triage — operators don't manage two billing relationships.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any

import httpx

from ..config import get_settings


log = logging.getLogger(__name__)


# ── Result type ─────────────────────────────────────────────────────


@dataclass(frozen=True)
class TriageResult:
    walkthrough: str
    blast_radius: str
    exploit_scenario: str
    fix_outline: str
    confidence: str             # "low" | "medium" | "high"
    model: str
    input_tokens: int
    output_tokens: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "walkthrough": self.walkthrough,
            "blast_radius": self.blast_radius,
            "exploit_scenario": self.exploit_scenario,
            "fix_outline": self.fix_outline,
            "confidence": self.confidence,
            "model": self.model,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
        }


# ── Client ──────────────────────────────────────────────────────────


_SYSTEM_PROMPT = (
    "You are a senior offensive-security engineer triaging vulnerabilities "
    "for a development team. Produce concrete, actionable, accurate "
    "walkthroughs that help engineers understand WHY a finding is "
    "exploitable and HOW to fix it. You are speaking to a working dev — be "
    "specific, cite the evidence in the prompt, do not pad with generic "
    "OWASP boilerplate. If the evidence is insufficient, say so honestly "
    "and lower your confidence.\n\n"
    "Reply with strict JSON of this exact shape:\n"
    "{\n"
    '  "walkthrough":      "<markdown narrative, ≤300 words>",\n'
    '  "blast_radius":     "<one-paragraph impact summary>",\n'
    '  "exploit_scenario": "<numbered attack steps, each one short>",\n'
    '  "fix_outline":      "<prose remediation plan, no diffs>",\n'
    '  "confidence":       "low" | "medium" | "high"\n'
    "}\n"
    "No prose before or after the JSON. Do not wrap in code fences."
)


class TriageLLMClient:
    """DeepSeek (OpenAI-compatible) client for the triage walkthrough."""

    def __init__(self) -> None:
        s = get_settings()
        self._base_url = s.fix_llm_base_url.rstrip("/")
        self._api_key = s.fix_llm_api_key
        # The fix model is tuned for surgical patching; the triage prompt
        # benefits from a chattier sibling. ``deepseek-chat`` covers both
        # cases on the DeepSeek API at the same price tier.
        self._model = (
            getattr(s, "triage_llm_model", None)
            or s.fix_llm_model
            or "deepseek-chat"
        )
        self._timeout = s.fix_llm_request_timeout
        self._org_client = None

    def set_org_client(self, client) -> None:
        """Inject the org's active ChatClient. When set, the triage call routes
        through it (JSON mode, fail-closed) instead of the env client."""
        self._org_client = client

    @property
    def enabled(self) -> bool:
        return bool(self._api_key)

    @property
    def model(self) -> str:
        return self._model

    async def triage_finding(
        self,
        *,
        title: str,
        severity: str,
        category: str,
        endpoint: str | None,
        parameter: str | None,
        description: str | None,
        evidence_excerpt: str,
        cvss_score: float | None,
        reachability: str | None,
        epss: float | None,
        kev: bool,
        cwe_id: str | None,
        owasp_category: str | None,
        code_snippet: str | None = None,
        max_tokens: int = 1500,
    ) -> TriageResult | None:
        """Generate the walkthrough. Returns ``None`` on any LLM failure
        (caller decides whether to surface a 502 or a "try again later")."""
        if self._org_client is not None:
            # Org has an active provider — route through it (JSON mode).
            # Fail-closed: any error returns None; never falls back to env key.
            try:
                # Build the same messages the env path builds below.
                _parts: list[str] = []
                _parts.append(f"Finding: {title}")
                _parts.append(f"Severity: {severity}  |  Category: {category}")
                if owasp_category:
                    _parts.append(f"OWASP: {owasp_category}")
                if cwe_id:
                    _parts.append(f"CWE: {cwe_id}")
                if cvss_score is not None:
                    _parts.append(f"CVSS: {cvss_score}")
                if reachability:
                    _parts.append(f"Reachability: {reachability}")
                if kev:
                    _parts.append("KEV-listed: YES — CISA confirms in-the-wild exploitation.")
                if epss is not None:
                    _parts.append(f"EPSS: {epss:.4f}")
                if endpoint:
                    _parts.append(f"Endpoint: {endpoint}")
                if parameter:
                    _parts.append(f"Parameter: {parameter}")
                if description:
                    _parts.append(f"\nDescription:\n{description.strip()[:1500]}")
                if evidence_excerpt:
                    _parts.append(f"\nLive evidence (DAST request/response or "
                                  f"static-analysis trace):\n{evidence_excerpt[:3000]}")
                if code_snippet:
                    _parts.append(f"\nCode snippet:\n```\n{code_snippet[:2000]}\n```")
                _parts.append(
                    "\nProduce the JSON walkthrough now. Cite specific tokens "
                    "from the evidence above. If the evidence is too thin to "
                    "make a confident claim, set confidence='low' and say so in "
                    "the walkthrough."
                )
                from .llm_providers.base import ChatMessage
                _messages = [
                    ChatMessage(role="system", content=_SYSTEM_PROMPT),
                    ChatMessage(role="user", content="\n".join(_parts)),
                ]
                res = await self._org_client.chat(
                    _messages, json=True, max_tokens=max_tokens, temperature=0.2
                )
                return _parse_triage_json(
                    res.text or "",
                    model=getattr(self._org_client, "model", self._model),
                    input_tokens=getattr(res, "input_tokens", 0) or 0,
                    output_tokens=getattr(res, "output_tokens", 0) or 0,
                )
            except Exception as exc:  # noqa: BLE001
                log.warning("triage-LLM org-client call failed: %s", exc)
                return None

        if not self.enabled:
            return None

        # ── Build the user prompt ─────────────────────────────────
        # Order matters: most-specific signal first (the live evidence)
        # so the model anchors on it before the metadata surrounding.
        parts: list[str] = []
        parts.append(f"Finding: {title}")
        parts.append(f"Severity: {severity}  |  Category: {category}")
        if owasp_category:
            parts.append(f"OWASP: {owasp_category}")
        if cwe_id:
            parts.append(f"CWE: {cwe_id}")
        if cvss_score is not None:
            parts.append(f"CVSS: {cvss_score}")
        if reachability:
            parts.append(f"Reachability: {reachability}")
        if kev:
            parts.append("KEV-listed: YES — CISA confirms in-the-wild exploitation.")
        if epss is not None:
            parts.append(f"EPSS: {epss:.4f}")
        if endpoint:
            parts.append(f"Endpoint: {endpoint}")
        if parameter:
            parts.append(f"Parameter: {parameter}")
        if description:
            parts.append(f"\nDescription:\n{description.strip()[:1500]}")
        if evidence_excerpt:
            parts.append(f"\nLive evidence (DAST request/response or "
                         f"static-analysis trace):\n{evidence_excerpt[:3000]}")
        if code_snippet:
            parts.append(f"\nCode snippet:\n```\n{code_snippet[:2000]}\n```")
        parts.append(
            "\nProduce the JSON walkthrough now. Cite specific tokens "
            "from the evidence above. If the evidence is too thin to "
            "make a confident claim, set confidence='low' and say so in "
            "the walkthrough."
        )
        user_msg = "\n".join(parts)

        body = {
            "model": self._model,
            "messages": [
                {"role": "system", "content": _SYSTEM_PROMPT},
                {"role": "user", "content": user_msg},
            ],
            "max_tokens": max_tokens,
            "temperature": 0.2,
            "response_format": {"type": "json_object"},
        }

        try:
            async with httpx.AsyncClient(timeout=self._timeout) as c:
                r = await c.post(
                    f"{self._base_url}/chat/completions",
                    headers={
                        "Authorization": f"Bearer {self._api_key}",
                        "Content-Type": "application/json",
                    },
                    json=body,
                )
            if r.status_code >= 400:
                log.warning("triage-LLM HTTP %s: %s", r.status_code, r.text[:300])
                return None
            payload = r.json()
        except (httpx.HTTPError, ValueError) as exc:
            log.warning("triage-LLM call failed: %s", exc)
            return None

        try:
            text = payload["choices"][0]["message"]["content"] or ""
            usage = payload.get("usage") or {}
        except (KeyError, IndexError, TypeError):
            log.warning("triage-LLM response shape unexpected: %s", str(payload)[:200])
            return None

        return _parse_triage_json(text, model=self._model,
                                  input_tokens=int(usage.get("prompt_tokens", 0) or 0),
                                  output_tokens=int(usage.get("completion_tokens", 0) or 0))


# ── JSON parsing ────────────────────────────────────────────────────


_REQUIRED_FIELDS = (
    "walkthrough", "blast_radius", "exploit_scenario", "fix_outline",
    "confidence",
)
_VALID_CONFIDENCE = {"low", "medium", "high"}


def _parse_triage_json(
    text: str, *, model: str, input_tokens: int, output_tokens: int,
) -> TriageResult | None:
    """Parse the LLM's JSON, validate the required fields, normalise
    confidence. Returns ``None`` if the response is malformed — caller
    treats that as a soft failure (user can retry)."""
    raw = text.strip()
    # Strip a defensive code fence in case the model ignored the
    # "no fences" instruction.
    if raw.startswith("```"):
        raw = raw.strip("`")
        if raw.startswith("json"):
            raw = raw[len("json"):]
        raw = raw.strip()
    try:
        obj = json.loads(raw)
    except json.JSONDecodeError:
        log.warning("triage-LLM: JSON parse failed: %s", raw[:200])
        return None
    if not isinstance(obj, dict):
        return None
    for k in _REQUIRED_FIELDS:
        if k not in obj or not isinstance(obj[k], str):
            log.warning("triage-LLM: missing/bad field %s in response", k)
            return None
    confidence = obj["confidence"].strip().lower()
    if confidence not in _VALID_CONFIDENCE:
        confidence = "low"
    return TriageResult(
        walkthrough=obj["walkthrough"].strip(),
        blast_radius=obj["blast_radius"].strip(),
        exploit_scenario=obj["exploit_scenario"].strip(),
        fix_outline=obj["fix_outline"].strip(),
        confidence=confidence,
        model=model,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
    )
