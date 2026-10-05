"""LLM client — false-positive triage and grade attestation.

The scan runner invokes this after raw findings are persisted. Two tasks
are delegated to the LLM:

  1. ``classify_findings`` — given the structured findings, return which
     ones are likely false positives with a short reason. The caller
     marks those findings as suppressed so the grader ignores them.

  2. ``grade_assessment`` — given the kept findings + target metadata,
     return an audit-style letter grade and a one-paragraph rationale
     suitable for display to auditors.

Both calls degrade gracefully: on any HTTP error, timeout, missing API
key, or malformed response, we return ``None`` and the caller falls
back to the existing heuristic grader. An LLM hiccup must never break a
scan.

The default configuration targets Together.ai's MiniMax M2.7 FP4 endpoint.
Any OpenAI-compatible chat-completions endpoint works — override via
``LLM_BASE_URL``, ``LLM_MODEL``, and ``LLM_API_KEY``.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from typing import Any, Iterable

import httpx

from ..config import get_settings

_log = logging.getLogger("pencheff.llm")

_GRADES = {"A", "B", "C", "D", "F"}


@dataclass(frozen=True)
class FindingInput:
    """Minimal fields the LLM needs to reason about a finding."""

    id: str  # local DB id — used as the correlation key
    title: str
    severity: str
    category: str
    endpoint: str | None
    parameter: str | None
    description: str | None
    evidence_excerpt: str | None
    cvss_score: float | None


@dataclass(frozen=True)
class FindingVerdict:
    is_false_positive: bool
    confidence: float  # 0..1
    reason: str


@dataclass(frozen=True)
class GradeVerdict:
    grade: str
    score: int  # 0..100
    rationale: str


class LLMClient:
    # Cooldown after the upstream signals rate-limit (HTTP 429). During this
    # window ``_chat`` returns ``None`` immediately so the scan doesn't spam
    # the provider with batch calls that are all going to fail.
    _RATE_LIMIT_COOLDOWN = 300.0  # seconds

    def __init__(self) -> None:
        s = get_settings()
        self._base_url = s.llm_base_url.rstrip("/")
        self._api_key = s.llm_api_key
        self._model = s.llm_model
        self._timeout = s.llm_request_timeout
        self._referer = s.llm_http_referer
        self._title = s.llm_app_title
        self._explicit_label = (s.llm_model_label or "").strip()
        self._enabled = bool(s.llm_enabled and s.llm_api_key)
        self._blocked_until: float = 0.0
        self._org_client = None  # set per-request via set_org_client(); BYO override

    def set_org_client(self, client) -> None:
        """Inject the org's active ChatClient (from resolve_chat_client). When
        set, _chat routes through it (fail-closed) instead of the env client."""
        self._org_client = client

    @property
    def enabled(self) -> bool:
        return self._enabled and not self.rate_limited

    @property
    def rate_limited(self) -> bool:
        import time as _t

        return _t.time() < self._blocked_until

    @property
    def label(self) -> str:
        """Short display name for UI attribution, e.g. ``"MiniMax M2.7"``."""
        if self._explicit_label:
            return self._explicit_label
        # Use everything after the last "/" and before any ":" suffix.
        model = self._model.rsplit("/", 1)[-1].split(":", 1)[0]
        # If the slug has mixed case already (e.g. "MiniMax-M2.7") preserve
        # it — only titlecase when the author shipped an all-lowercase slug.
        humanised = model.replace("-", " ")
        if not any(c.isupper() for c in humanised):
            humanised = humanised.title()
        return humanised or model

    # ---------------------------------------------------------------- chat
    def _chat(self, system: str, user: str) -> str | None:
        """Send one chat-completion request; return assistant text or None."""
        if self._org_client is not None:
            from .llm_providers.base import ChatMessage, run_sync
            try:
                res = run_sync(self._org_client.chat(
                    [ChatMessage("system", system), ChatMessage("user", user)],
                    temperature=0.1, max_tokens=2048))
                return res.text or None
            except Exception as exc:  # noqa: BLE001 — fail-closed, no env fallback
                _log.warning("org LLM provider failed (fail-closed): %s", exc)
                return None
        if not self._enabled:
            return None
        if self.rate_limited:
            return None
        payload = {
            "model": self._model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": 0.1,
            "max_tokens": 2048,
        }
        headers = {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
        }
        # OpenRouter recommends (but does not require) app attribution.
        if self._referer:
            headers["HTTP-Referer"] = self._referer
        if self._title:
            headers["X-Title"] = self._title
        try:
            r = httpx.post(
                f"{self._base_url}/chat/completions",
                json=payload,
                headers=headers,
                timeout=self._timeout,
            )
        except httpx.HTTPError as exc:
            _log.warning("LLM request failed: %s", exc)
            return None

        if r.status_code == 429:
            # Upstream rate-limited. Back off for the remainder of this
            # scan so the grader uses its heuristic fallback instead of
            # hammering the endpoint on every subsequent batch.
            import time as _t

            self._blocked_until = _t.time() + self._RATE_LIMIT_COOLDOWN
            _log.info(
                "LLM rate-limited (HTTP 429); skipping further calls for %ds",
                int(self._RATE_LIMIT_COOLDOWN),
            )
            return None
        if r.status_code >= 400:
            _log.warning("LLM returned %s: %s", r.status_code, r.text[:400])
            return None

        try:
            data = r.json()
            choices = data.get("choices") or []
            if not choices:
                return None
            msg = choices[0].get("message") or {}
            content = msg.get("content")
            if isinstance(content, str):
                return content
            if isinstance(content, list):
                # Some providers return content as a list of parts.
                parts = [p.get("text", "") for p in content if isinstance(p, dict)]
                return "".join(parts) or None
        except (ValueError, KeyError, TypeError) as exc:
            _log.warning("LLM response malformed: %s", exc)
        return None

    # ------------------------------------------------------ false-positive
    def classify_findings(
        self, findings: Iterable[FindingInput]
    ) -> dict[str, FindingVerdict]:
        """Return ``{finding_id: verdict}``. Missing ids are left untouched."""
        if not self._enabled and self._org_client is None:
            return {}

        s = get_settings()
        batch_size = max(1, int(s.llm_batch_size))
        items = list(findings)
        verdicts: dict[str, FindingVerdict] = {}

        for i in range(0, len(items), batch_size):
            if self.rate_limited:
                # Provider is cooling down — any further batches would
                # short-circuit with ``None`` and waste time.
                break
            chunk = items[i : i + batch_size]
            verdicts.update(self._classify_batch(chunk))
        return verdicts

    def _classify_batch(
        self, chunk: list[FindingInput]
    ) -> dict[str, FindingVerdict]:
        system = (
            "You are an elite application-security reviewer. Your job is "
            "to classify automated scanner findings as GENUINE "
            "vulnerabilities or FALSE POSITIVES. Be precise — false "
            "positives are findings that cannot be demonstrated as "
            "exploitable given the evidence; do NOT use the FP label for "
            "real misconfigurations just because they are common.\n\n"
            "ALWAYS flag these as false positive (is_false_positive=true, "
            "confidence>=0.85):\n"
            "  • \"Admin Path Accessible\" / sensitive-path findings where "
            "the evidence is ONLY an HTTP 2xx status with no response "
            "body content, or where the response body contains the "
            "strings \"404\", \"Not Found\", \"Page Not Found\", "
            "\"page does not exist\", or \"error\" (this is the classic "
            "Single-Page App trap: servers serve index.html with HTTP 200 "
            "for every path, so 200 does NOT imply the path exists).\n"
            "  • Missing security headers on responses whose URL ENDS in "
            "a static-asset extension: ``.css``, ``.js``, ``.mjs``, "
            "``.png``, ``.jpg``, ``.jpeg``, ``.gif``, ``.svg``, "
            "``.webp``, ``.ico``, ``.woff``, ``.woff2``, ``.ttf``, "
            "``.eot``, ``.map``. The endpoint must literally end in one "
            "of these — do NOT extrapolate to HTML pages.\n"
            "  • Cookie flag issues on cookies that are not session "
            "tokens (analytics, preference, consent cookies).\n"
            "  • Banner / server-version disclosures with no exploitable "
            "context.\n"
            "  • SSL/TLS findings for the assessment machine's own "
            "localhost services.\n"
            "  • \"Open redirect\" findings where the redirect payload "
            "is simply echoed into a query parameter with no "
            "``Location`` header change or client-side navigation.\n\n"
            "DO NOT flag these as false positive — they are genuine "
            "site-wide misconfigurations that affect every page the "
            "browser later loads, including authenticated routes:\n"
            "  • Missing Content-Security-Policy on HTML responses.\n"
            "  • Missing X-Frame-Options / clickjacking protection on "
            "HTML responses.\n"
            "  • Missing HSTS / Strict-Transport-Security on the apex "
            "or any HTTPS endpoint that serves HTML.\n"
            "  • Missing Referrer-Policy / Permissions-Policy / "
            "X-Content-Type-Options on HTML responses.\n"
            "  • Any of the above on the application's homepage, "
            "marketing site, login page, dashboard, or API root — these "
            "are NOT static assets even when they look 'just like a "
            "marketing page'.\n\n"
            "Keep as genuine (is_false_positive=false) when the evidence "
            "shows concrete exploitability: reflected payload execution, "
            "error messages leaking SQL/LDAP internals, SSRF returning "
            "cloud-metadata, auth bypass responses, directory listings, "
            "admin JSON/HTML actually being served, etc.\n\n"
            "For STATIC-ANALYSIS / source-code findings (bandit, semgrep, "
            "gosec, etc.) the evidence is the code snippet — judge from it:\n"
            "  • bandit B608 (\"hardcoded SQL expression\") is a FALSE "
            "POSITIVE when the query uses parameter binding (``?``, ``%s``, "
            "``:name`` placeholders whose VALUES are passed via a separate "
            "params/args argument) and the only string concatenation is "
            "STATIC SQL structure — column lists, table names, a WHERE clause "
            "joined from fixed predicate strings, or a run of ``?`` "
            "placeholders. It is GENUINE only when an attacker-controllable "
            "VALUE is interpolated directly into the SQL string "
            "(f-string / ``.format`` / ``%`` / ``+`` putting a variable value "
            "inside the query text).\n"
            "  • Other code findings are FALSE POSITIVES when the snippet "
            "shows the flagged input is a constant / trusted / not "
            "attacker-reachable, or the code is a dev/test-only path.\n"
            "  • CRITICAL RULE: if the snippet is insufficient to PROVE the "
            "code is safe, keep it GENUINE (is_false_positive=false). Never "
            "guess a finding safe — only flag a false positive when the "
            "evidence positively demonstrates safety.\n\n"
            "Respond ONLY with a valid JSON array; no prose, no markdown."
        )

        findings_json = [
            {
                "id": f.id,
                "title": f.title,
                "severity": f.severity,
                "category": f.category,
                "endpoint": f.endpoint,
                "parameter": f.parameter,
                "description": (f.description or "")[:800],
                "cvss_score": f.cvss_score,
                "evidence_excerpt": (f.evidence_excerpt or "")[:600],
            }
            for f in chunk
        ]

        user = (
            "For each of the following findings, decide whether it is a "
            "false positive. Return a JSON array where every element has "
            "the shape:\n\n"
            "{"
            '"id": "<finding-id>", '
            '"is_false_positive": true|false, '
            '"confidence": <0.0-1.0>, '
            '"reason": "<one-sentence justification>"'
            "}\n\n"
            "Findings:\n"
            + json.dumps(findings_json, ensure_ascii=False)
        )

        text = self._chat(system, user)
        if not text:
            return {}

        parsed = _parse_json_array(text)
        if not parsed:
            _log.warning("could not parse classification response: %s", text[:200])
            return {}

        out: dict[str, FindingVerdict] = {}
        for entry in parsed:
            if not isinstance(entry, dict):
                continue
            fid = entry.get("id")
            if not isinstance(fid, str):
                continue
            try:
                confidence = float(entry.get("confidence", 0.0))
            except (TypeError, ValueError):
                confidence = 0.0
            out[fid] = FindingVerdict(
                is_false_positive=bool(entry.get("is_false_positive", False)),
                confidence=max(0.0, min(1.0, confidence)),
                reason=str(entry.get("reason", ""))[:500],
            )
        return out

    # --------------------------------------------------------------- grade
    def grade_assessment(
        self,
        *,
        target_url: str,
        kept_findings: list[FindingInput],
        severity_counts: dict[str, int],
    ) -> GradeVerdict | None:
        if not self._enabled and self._org_client is None:
            return None

        compact = [
            {
                "severity": f.severity,
                "title": f.title,
                "category": f.category,
                "endpoint": f.endpoint,
                "cvss_score": f.cvss_score,
            }
            for f in kept_findings[:80]  # cap prompt size
        ]

        system = (
            "You are the chief assessor of a boutique application-security "
            "firm. Produce an executive letter grade for this assessment "
            "using the rubric of a formal SOC 2 attestation. Be strict: "
            "an application with even one unmitigated critical issue "
            "cannot receive an A; one with multiple unmitigated highs "
            "cannot receive a B. An assessment with no real findings "
            "earns an A. Respond ONLY with valid JSON."
        )
        user = (
            "Return a JSON object with exactly these keys:\n"
            "  grade    - one of A, B, C, D, F\n"
            '  score    - integer 0-100 ("100 = pristine, 0 = breached")\n'
            "  rationale- 2-4 sentence executive summary suitable for an "
            "audit report\n\n"
            f"Target: {target_url}\n"
            f"Severity counts (after false-positive triage): {json.dumps(severity_counts)}\n"
            f"Findings (up to 80 highest-priority kept):\n"
            f"{json.dumps(compact, ensure_ascii=False)}"
        )

        text = self._chat(system, user)
        if not text:
            return None

        obj = _parse_json_object(text)
        if not obj:
            _log.warning("could not parse grade response: %s", text[:200])
            return None

        grade = str(obj.get("grade", "")).strip().upper()
        if grade not in _GRADES:
            return None
        try:
            score = max(0, min(100, int(obj.get("score", 0))))
        except (TypeError, ValueError):
            return None
        rationale = str(obj.get("rationale", "")).strip()
        return GradeVerdict(grade=grade, score=score, rationale=rationale[:1200])



# ---------------------------------------------------------------- parsing


def _strip_code_fences(text: str) -> str:
    """LLMs often wrap JSON in ```json ... ```; pull it out."""
    m = re.search(r"```(?:json)?\s*(.*?)```", text, re.DOTALL | re.IGNORECASE)
    return m.group(1).strip() if m else text.strip()


def _parse_json_array(text: str) -> list[Any] | None:
    candidate = _strip_code_fences(text)
    try:
        data = json.loads(candidate)
        return data if isinstance(data, list) else None
    except (ValueError, TypeError):
        pass
    # Fallback: locate the first [...] block.
    start = candidate.find("[")
    end = candidate.rfind("]")
    if start != -1 and end != -1 and end > start:
        try:
            data = json.loads(candidate[start : end + 1])
            return data if isinstance(data, list) else None
        except (ValueError, TypeError):
            return None
    return None


def _parse_json_object(text: str) -> dict[str, Any] | None:
    candidate = _strip_code_fences(text)
    try:
        data = json.loads(candidate)
        return data if isinstance(data, dict) else None
    except (ValueError, TypeError):
        pass
    start = candidate.find("{")
    end = candidate.rfind("}")
    if start != -1 and end != -1 and end > start:
        try:
            data = json.loads(candidate[start : end + 1])
            return data if isinstance(data, dict) else None
        except (ValueError, TypeError):
            return None
    return None


_client_singleton: LLMClient | None = None


def get_client() -> LLMClient:
    global _client_singleton
    if _client_singleton is None:
        _client_singleton = LLMClient()
    return _client_singleton
