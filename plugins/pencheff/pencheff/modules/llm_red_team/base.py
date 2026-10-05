"""Shared base class for the per-OWASP-LLM-category red team modules.

Subclasses set ``owasp_category``, ``payload_file``, ``techniques``,
and inherit the run loop, which:

  1. Loads a YAML payload library scoped to this module's category.
  2. Filters by ``config.techniques`` (caller restriction) and
     ``config.max_payloads`` (profile-driven cap, round-robin across
     techniques so quick profiles don't starve any technique).
  3. Dispatches each payload through ``LlmProbe`` with bounded
     concurrency and a per-call timeout.
  4. Aggregates results by ``technique`` (NOT by individual payload)
     so the eventual report shows "8/12 direct-injection variants
     succeeded" as one Finding with ≤5 evidence entries, not 8
     near-duplicate clones.
"""
from __future__ import annotations

import json
import logging
import os
import re
import threading
import time
from collections import defaultdict
from dataclasses import asdict, is_dataclass
from importlib.resources import files
from pathlib import Path
from typing import Any

import yaml

from pencheff.config import Severity
from pencheff.core.findings import Evidence, Finding
from pencheff.core.http_client import PencheffHTTPClient
from pencheff.core.session import PentestSession
from pencheff.modules.base import BaseTestModule

from .addon_plugins import addon_cases
from .attacker import AttackerLlm
from .embedder import Embedder
from .engine import (
    LlmProbe,
    ProbeResponse,
    ProviderError,
    TestCase,
    Verdict,
    evaluate,
    evaluate_with_reason,
)
from .factuality import FactualityGrader
from .goat import run_goat_attack
from .hydra import run_hydra_attack
from .iterative import _ALL_ATTACKER_MODES, apply_iterative_attacks, run_pair_attack
from .tap import run_tap_attack
from .judge import LlmJudge, run_self_judge
from .multiturn import run_multi_turn
from .strategies import apply_composite_strategies, apply_languages, apply_strategies
from .synthesis import synthesize_cases_from_discovery, synthesize_with_llm
from .variables import apply_variables

log = logging.getLogger(__name__)


def _ensure_bearer_scheme(headers: dict[str, str]) -> None:
    """Add the ``Bearer`` scheme to a schemeless Authorization value in place.

    A bare token (no "Bearer "/"Basic " prefix) is the #1 cause of a 401 against
    OpenAI-compatible endpoints (Groq/OpenRouter/…): the operator pasted just the
    key. Values that already carry a scheme contain a space, so leave those alone.
    """
    auth = (headers.get("Authorization") or "").strip()
    if auth and " " not in auth:
        headers["Authorization"] = f"Bearer {auth}"


# Severity ranking for "max severity in a group" aggregation.
_SEV_RANK: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}

# Cap on evidence rows attached to a single Finding. The first 5
# successful payloads ride along verbatim (sanitized to 512 chars);
# anything beyond that is summarized as a count in the Finding's
# description so reports stay scannable.
_EVIDENCE_CAP = 5

# Cap on response snippet length per Evidence row. Probes that elicit
# the full system prompt or a multi-paragraph PII regurgitation
# shouldn't end up in the report verbatim — that defeats the
# "evidence captures sanitized snippets" promise.
_RESPONSE_SNIPPET_CAP = 512

_PII_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE), "[REDACTED_EMAIL]"),
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "[REDACTED_SSN]"),
    (re.compile(r"\b(?:\d[ -]*?){13,19}\b"), "[REDACTED_CARD]"),
    (re.compile(r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"), "[REDACTED_PHONE]"),
    (re.compile(r"\b(?:sk|pk|rk|xox[baprs])-[-A-Za-z0-9_]{12,}\b"), "[REDACTED_SECRET]"),
]


def redact_evidence_text(text: str | None, *, limit: int | None = None) -> str:
    """Redact obvious secrets/PII before evidence reaches reports."""
    out = str(text or "")
    for pattern, replacement in _PII_PATTERNS:
        out = pattern.sub(replacement, out)
    if limit is not None:
        out = out[:limit]
    return out


# ── Local transcript dumper (opt-in via env var) ────────────────────
#
# The hosted SaaS path stores Findings only — REFUSED and AMBIGUOUS
# verdicts are silently discarded, response bodies are redacted and
# capped at 512 chars, and there is no per-probe table. That makes it
# impossible to answer the question *"what did the model actually say
# to each probe, and why did the engine decide what it did?"*
#
# Setting ``PENCHEFF_LLM_DUMP_TRANSCRIPTS=<dir>`` flips on a JSONL
# dumper that writes one line per probe (VULNERABLE, REFUSED,
# AMBIGUOUS, *and* failures) to ``<dir>/probes.jsonl`` with the full
# unredacted request + response, the verdict, and a human-readable
# verdict reason. Local-only — no DB / API / hosted code path is
# touched.
_DUMP_LOCK = threading.Lock()
_DUMP_PATH_CACHE: dict[str, Path] = {}


def _dump_path() -> Path | None:
    raw = os.environ.get("PENCHEFF_LLM_DUMP_TRANSCRIPTS")
    if not raw:
        return None
    cached = _DUMP_PATH_CACHE.get(raw)
    if cached is not None:
        return cached
    base = Path(raw).expanduser()
    base.mkdir(parents=True, exist_ok=True)
    target = base / "probes.jsonl"
    _DUMP_PATH_CACHE[raw] = target
    return target


def _testcase_to_dict(tc: TestCase) -> dict[str, Any]:
    if is_dataclass(tc):
        return asdict(tc)
    return {
        "id": getattr(tc, "id", None),
        "category": getattr(tc, "category", None),
        "technique": getattr(tc, "technique", None),
        "title": getattr(tc, "title", None),
        "severity": str(getattr(tc, "severity", "")),
        "prompt": getattr(tc, "prompt", None),
        "turns": list(getattr(tc, "turns", []) or []),
        "system": getattr(tc, "system", None),
        "success_indicators": list(getattr(tc, "success_indicators", []) or []),
        "refusal_patterns": list(getattr(tc, "refusal_patterns", []) or []),
        "description": getattr(tc, "description", ""),
    }


def _response_to_dict(resp: ProbeResponse | None) -> dict[str, Any] | None:
    if resp is None:
        return None
    return {
        "text": resp.text,
        "http_status": resp.http_status,
        "request_body": resp.request_body,
        "response_body": resp.response_body,
        "latency_ms": resp.latency_ms,
        "input_tokens": resp.input_tokens,
        "output_tokens": resp.output_tokens,
        "cached": resp.cached,
        "tool_calls": resp.tool_calls,
    }


def _condense(text: str | None, *, limit: int) -> str:
    """Collapse whitespace and truncate so a single probe fits on
    one log line in the UI."""
    if not text:
        return ""
    flat = " ".join(str(text).split())
    if len(flat) > limit:
        flat = flat[: limit - 1] + "…"
    return flat


def _dump_transcript(
    tc: TestCase,
    resp: ProbeResponse | None,
    verdict: Verdict,
    reason: str,
    *,
    endpoint: str | None = None,
    error: str | None = None,
    promotion: dict[str, Any] | None = None,
) -> None:
    """Append one JSONL line per probe (when env var set) AND emit a
    compact ``llm_redteam_progress: probe …`` log line for the API
    runner's forwarder to pick up — so users see input/output of
    every LLM call live in the assessment log, not just buried in a
    file.

    ``reason`` is the human-readable explanation of why the verdict
    came out the way it did (which regex fired, judge label, etc.).
    ``promotion`` carries any embedding / judge / factuality result
    that upgraded an AMBIGUOUS verdict to VULNERABLE.
    """
    verdict_str = verdict.value if isinstance(verdict, Verdict) else str(verdict)
    # ── Compact single-line summary for the UI's assessment log ──────
    # Format:
    #   probe LLM01/direct_injection [vulnerable] 836ms in=12 out=8
    #     · req: "Ignore all previous…"
    #     · resp: "Sure, the password is…"
    #     · why: vulnerable: success_indicator matched /CANARY/
    # Each truncation is generous enough to be diagnostic but tight
    # enough that the assessment log stays readable.
    prompt_text = "\n---\n".join(tc.turns) if tc.turns else (tc.prompt or "")
    resp_text = resp.text if resp is not None else ""
    latency = resp.latency_ms if resp is not None else 0
    in_tok = (resp.input_tokens if resp is not None else None) or 0
    out_tok = (resp.output_tokens if resp is not None else None) or 0
    status = resp.http_status if resp is not None else 0
    summary = (
        f"llm_redteam_progress: probe {tc.category}/{tc.technique} "
        f"[{verdict_str}] {latency}ms http={status} in={in_tok} out={out_tok} "
        f"· req: \"{_condense(prompt_text, limit=180)}\" "
        f"· resp: \"{_condense(resp_text, limit=180)}\" "
        f"· why: {_condense(reason, limit=140)}"
    )
    if error:
        summary += f" · error: {_condense(error, limit=120)}"
    log.info(summary)

    # ── Full unredacted JSONL record (still gated on env var) ────────
    path = _dump_path()
    if path is None:
        return
    record = {
        "ts": time.time(),
        "endpoint": endpoint,
        "test_case": _testcase_to_dict(tc),
        "response": _response_to_dict(resp),
        "verdict": verdict_str,
        "verdict_reason": reason,
        "promotion": promotion,
        "error": error,
    }
    line = json.dumps(record, default=str, ensure_ascii=False)
    # The dispatcher runs many _one() coroutines concurrently; serialise
    # writes so two coroutines on the same thread or worker don't
    # interleave bytes.
    with _DUMP_LOCK:
        with path.open("a", encoding="utf-8") as fh:
            fh.write(line)
            fh.write("\n")


def _load_payloads(file_name: str) -> list[TestCase]:
    """Load and validate one YAML file from ``payloads/``.

    Each entry must declare at minimum ``id``, ``category``,
    ``technique``, ``title``, ``severity``, and ``prompt``. Missing
    fields raise loudly — payload typos are bugs we want caught at
    module import time, not at scan time."""
    base = files("pencheff.modules.llm_red_team").joinpath("payloads", file_name)
    text = base.read_text(encoding="utf-8")
    raw = yaml.safe_load(text) or []
    if not isinstance(raw, list):
        raise ValueError(f"{file_name}: expected a YAML list at the top level")
    out: list[TestCase] = []
    for entry in raw:
        if not isinstance(entry, dict):
            raise ValueError(f"{file_name}: every entry must be a mapping")
        try:
            sev = Severity(str(entry["severity"]).lower())
        except (KeyError, ValueError) as e:
            raise ValueError(
                f"{file_name}: entry {entry.get('id')!r} has invalid severity"
            ) from e
        out.append(TestCase(
            id=str(entry["id"]),
            category=str(entry["category"]),
            technique=str(entry["technique"]),
            title=str(entry["title"]),
            severity=sev,
            prompt=str(entry["prompt"]),
            turns=[str(x) for x in list(entry.get("turns") or [])],
            system=entry.get("system"),
            success_indicators=list(entry.get("success_indicators") or []),
            refusal_patterns=list(entry.get("refusal_patterns") or []),
            success_embeddings=[str(x) for x in list(entry.get("success_embeddings") or [])],
            description=str(entry.get("description", "")),
            remediation=str(entry.get("remediation", "")),
            cwe=entry.get("cwe"),
            metadata=dict(entry.get("metadata") or {}),
        ))
    return out


def _round_robin_cap(
    cases: list[TestCase], cap: int | None
) -> list[TestCase]:
    """Cap the case list at ``cap`` total, round-robining across
    techniques so we never exhaust the budget on a single technique
    and leave others untested. Order within each technique is
    preserved (YAML order = author's curated priority)."""
    if cap is None or cap <= 0 or cap >= len(cases):
        return list(cases)
    by_tech: dict[str, list[TestCase]] = defaultdict(list)
    for c in cases:
        by_tech[c.technique].append(c)
    selected: list[TestCase] = []
    while len(selected) < cap and any(by_tech.values()):
        for tech, lst in list(by_tech.items()):
            if not lst:
                by_tech.pop(tech, None)
                continue
            selected.append(lst.pop(0))
            if len(selected) >= cap:
                break
    return selected


class LlmRedTeamModule(BaseTestModule):
    """Subclass for one OWASP LLM Top 10 category."""

    # Override in subclasses.
    payload_file: str = ""
    owasp_category: str = ""

    def _extra_cases(self, llm_config: dict[str, Any]) -> list[TestCase]:
        """Dynamic payloads supplied by subclasses.

        Static OWASP modules return no extras. Custom policy/intent
        modules use this hook to turn llm_config red-team settings into
        first-class TestCase objects.
        """
        return []

    async def run(
        self,
        session: PentestSession,
        http: PencheffHTTPClient | None,
        targets: list[str] | None = None,
        config: dict[str, Any] | None = None,
    ) -> list[Finding]:
        # ``llm_redteam_progress: …`` lines are picked up by the API
        # scan_runner's logging handler and surfaced in the SaaS UI's
        # assessment log so users can see *which* OWASP-LLM module is
        # currently running. Keep the prefix stable — the handler
        # filters on it.
        log.info("llm_redteam_progress: module_start %s", self.owasp_category or self.__class__.__name__)
        cfg = dict(config or {})
        techniques_filter: list[str] | None = cfg.get("techniques")
        max_payloads: int | None = cfg.get("max_payloads")

        llm_config = session.llm_config or {}
        if not llm_config:
            raise RuntimeError(
                "LLM red-team modules require session.llm_config; "
                "call create_session(..., llm_config=...) first."
            )
        self._last_llm_config = llm_config

        # Decrypted credential headers ride on the credential store
        # under the "default" set. CredentialSet stores them on the
        # ``custom_headers`` attribute (despite the public schema
        # exposing them as ``headers`` — the mapping happens in
        # CredentialStore.add_from_dict). Normalise the MaskedSecret
        # values to plain strings before handing them to the probe.
        headers: dict[str, str] = {}
        creds = session.credentials.get("default")
        if creds is not None:
            cred_headers = (
                getattr(creds, "custom_headers", None)
                or getattr(creds, "headers", None)
            )
            if cred_headers:
                for k, v in cred_headers.items():
                    headers[k] = v.get() if hasattr(v, "get") else str(v)
                _ensure_bearer_scheme(headers)
            # Surface common shorthand fields too so a target created
            # with `token` / `api_key` (the URL-target shape) still
            # gets a usable Authorization header on LLM probes.
            if "Authorization" not in headers and creds.token:
                headers["Authorization"] = f"Bearer {creds.token.get()}"
            if "X-API-Key" not in headers and creds.api_key:
                headers["X-API-Key"] = creds.api_key.get()

        redteam_cfg = llm_config.get("redteam") if isinstance(llm_config, dict) else {}
        redteam_cfg = redteam_cfg if isinstance(redteam_cfg, dict) else {}

        # Instantiate optional attacker / judge before case expansion
        # so attacker-driven synthesis can extend the case list. Both
        # are closed in the finally block regardless of which paths
        # used them.
        judge = LlmJudge.from_llm_config(llm_config)
        # Self-judge default: with no dedicated / external judge configured
        # every AMBIGUOUS verdict would stay AMBIGUOUS and emit no finding.
        # Default to reusing the target model to classify its own output
        # (see run_self_judge). Overridable — a configured judge takes
        # precedence, and ``redteam.self_judge: false`` opts out entirely.
        self_judge_default = judge is None and bool(redteam_cfg.get("self_judge", True))
        attacker = AttackerLlm.from_llm_config(llm_config)
        embedder = Embedder.from_llm_config(llm_config)
        # Factuality grader is only useful for LLM09 modules; constructing
        # it for everyone wastes a judge connection. Build per-module.
        factuality = (
            FactualityGrader.from_llm_config(llm_config, judge=judge)
            if self.owasp_category == "LLM09"
            else None
        )
        max_pair_iterations = int(redteam_cfg.get("pair_iterations", 5) or 5)

        # Filter, transform, and cap the payloads.
        all_cases = _load_payloads(self.payload_file) if self.payload_file else []
        all_cases.extend(self._extra_cases(llm_config))
        # Tier-4 add-on plugin packs (bias / RAG / MCP / coding-agent).
        # Each pack lives in its own YAML; rows are routed to whichever
        # OWASP module their `category` field matches.
        all_cases.extend(addon_cases(llm_config, category=self.owasp_category))
        all_cases.extend([
            c for c in synthesize_cases_from_discovery(llm_config)
            if c.category == self.owasp_category
        ])
        # Attacker-driven synthesis: a single attacker call generates
        # category-tagged TestCases targeted at the discovered profile.
        # Filter to this module's category so each module only ingests
        # the synth cases it should run.
        synth_cfg = redteam_cfg.get("llm_synthesis") or {}
        if attacker is not None and isinstance(synth_cfg, dict) and synth_cfg.get("enabled"):
            profile = synth_cfg.get("profile") or redteam_cfg.get("discovery") or {}
            synth_n = int(synth_cfg.get("n", 5) or 5)
            try:
                synth_cases = await synthesize_with_llm(attacker, profile, n=synth_n)
            except Exception as exc:  # noqa: BLE001 — synth failure must not abort the scan
                log.warning("attacker synthesis failed: %s", exc)
                synth_cases = []
            all_cases.extend(c for c in synth_cases if c.category == self.owasp_category)
        all_cases = apply_variables(all_cases, redteam_cfg.get("variables"))
        all_cases = apply_strategies(all_cases, redteam_cfg.get("strategies"))
        all_cases = apply_composite_strategies(all_cases, redteam_cfg.get("composite_strategies"))
        rounds = int(redteam_cfg.get("iterative_rounds", 3) or 3)
        # Tier-4 always-on iterative coverage. When an attacker LLM is
        # configured, every base case gets TAP / GOAT / Hydra marker
        # variants automatically — they're in addition to whatever
        # ``redteam.iterative`` the caller asked for. Without an
        # attacker the markers are useless (the dispatcher would
        # route them through the plain probe path, duplicating the
        # base case), so we skip them and log a one-time hint.
        user_modes = redteam_cfg.get("iterative")
        if attacker is not None:
            iterative_modes: list[str] | str | None
            if user_modes is None or user_modes is False:
                iterative_modes = list(_ALL_ATTACKER_MODES)  # tap + goat + hydra
            elif isinstance(user_modes, (list, tuple)):
                iterative_modes = list(_ALL_ATTACKER_MODES) + [
                    str(m).lower()
                    for m in user_modes
                    if str(m).lower() not in _ALL_ATTACKER_MODES
                ]
            elif isinstance(user_modes, str) and user_modes.lower() in (
                *_ALL_ATTACKER_MODES, "all", "all-attacker", "all-iterative",
            ):
                iterative_modes = list(_ALL_ATTACKER_MODES)
            else:
                iterative_modes = list(_ALL_ATTACKER_MODES) + [user_modes]
        else:
            iterative_modes = user_modes
            if user_modes:
                log.info(
                    "llm_redteam_progress: iterative_skipped — %r requested but "
                    "no attacker LLM configured; configure redteam.attacker to enable "
                    "TAP / GOAT / Hydra / PAIR coverage",
                    user_modes,
                )
        all_cases = apply_iterative_attacks(all_cases, iterative_modes, rounds=rounds)
        all_cases = apply_languages(all_cases, redteam_cfg.get("languages"))
        # Plaintext-recovery map for the LLM10 encoded-payload fallback.
        # Strategy variants carry an id "<base_id>::<strategy>"; map each
        # base id to its un-encoded prompt so a 4xx on an encoded LLM10
        # probe can retry the plaintext original (see _dispatch).
        base_prompts = {c.id: c.prompt for c in all_cases if "::" not in c.id}
        if techniques_filter:
            allowed = set(techniques_filter)
            all_cases = [
                c for c in all_cases
                if c.technique in allowed or c.technique.split(":", 1)[0] in allowed
            ]
        cases = _round_robin_cap(all_cases, max_payloads)
        if not cases:
            if judge is not None:
                await judge.close()
            if attacker is not None:
                await attacker.close()
            if embedder is not None:
                await embedder.close()
            log.info(
                "llm_redteam_progress: module_done %s — 0 cases (no payloads matched filters)",
                self.owasp_category or self.__class__.__name__,
            )
            return []
        log.info(
            "llm_redteam_progress: module_cases %s — %d test cases queued",
            self.owasp_category or self.__class__.__name__,
            len(cases),
        )

        endpoint = session.target.base_url
        probe = LlmProbe(
            endpoint=endpoint,
            headers=headers,
            llm_config=llm_config,
        )
        try:
            session.discovered.running_module = self.name or self.owasp_category
            results = await self._dispatch(
                probe, cases,
                judge=judge,
                attacker=attacker,
                embedder=embedder,
                factuality=factuality,
                max_pair_iterations=max_pair_iterations,
                endpoint=endpoint,
                base_prompts=base_prompts,
                self_judge=self_judge_default,
            )
        finally:
            if judge is not None:
                await judge.close()
            if attacker is not None:
                await attacker.close()
            if embedder is not None:
                await embedder.close()
            await probe.close()
            session.discovered.running_module = None

        # Verdict breakdown so users can see *what happened* per module
        # without waiting for the final report. Surfaced through the
        # ``llm_redteam_progress:`` prefix that the API runner forwards
        # into the UI's assessment log.
        vuln = sum(1 for _, _, v, _ in results if v == Verdict.VULNERABLE)
        refused = sum(1 for _, _, v, _ in results if v == Verdict.REFUSED)
        ambiguous = sum(1 for _, _, v, _ in results if v == Verdict.AMBIGUOUS)
        errored = sum(1 for _, r, _, e in results if e is not None or r is None)
        findings_out = self._aggregate(results, endpoint=endpoint)
        log.info(
            "llm_redteam_progress: module_done %s — %d findings (vulnerable=%d refused=%d ambiguous=%d errored=%d, %d total cases)",
            self.owasp_category or self.__class__.__name__,
            len(findings_out), vuln, refused, ambiguous, errored, len(results),
        )
        return findings_out

    async def _dispatch(
        self,
        probe: LlmProbe,
        cases: list[TestCase],
        *,
        judge: LlmJudge | None = None,
        attacker: AttackerLlm | None = None,
        embedder: Embedder | None = None,
        factuality: FactualityGrader | None = None,
        max_pair_iterations: int = 5,
        endpoint: str | None = None,
        base_prompts: dict[str, str] | None = None,
        self_judge: bool = False,
    ) -> list[tuple[TestCase, ProbeResponse | None, Verdict, str | None]]:
        """Probe every case in parallel under the concurrency
        semaphore inside LlmProbe. Returns one row per case with the
        verdict; transport / provider errors get a None response and
        an error string."""
        import asyncio

        async def _one(tc: TestCase):
            resp: ProbeResponse | None = None
            err: str | None = None
            try:
                if tc.technique.endswith(":pair") and attacker is not None:
                    # PAIR loop: refine via attacker until VULNERABLE
                    # or budget hit. Even non-converged runs return
                    # the last response so partial-progress evidence
                    # is preserved.
                    pair = await run_pair_attack(
                        probe, tc, attacker,
                        judge=judge,
                        max_iterations=max_pair_iterations,
                    )
                    resp = pair.final
                elif tc.technique.endswith(":tap") and attacker is not None:
                    # Tree-of-Attacks-with-Pruning: branching attacker-driven
                    # search with off-topic pruning at each depth.
                    tap_cfg = redteam_cfg.get("tap") or {}
                    tap = await run_tap_attack(
                        probe, tc, attacker, judge=judge,
                        depth=int(tap_cfg.get("depth", 4)),
                        branching=int(tap_cfg.get("branching", 3)),
                        width=int(tap_cfg.get("width", 10)),
                    )
                    resp = tap.final
                elif tc.technique.endswith(":goat") and attacker is not None:
                    # GOAT: multi-turn attacker that picks a named
                    # technique per turn and switches strategy on
                    # observed refusals.
                    goat_cfg = redteam_cfg.get("goat") or {}
                    goat = await run_goat_attack(
                        probe, tc, attacker, judge=judge,
                        max_turns=int(goat_cfg.get("max_turns", 5)),
                    )
                    resp = goat.final
                elif tc.technique.endswith(":hydra") and attacker is not None:
                    # Hydra: parallel multi-turn fan-out across N
                    # objectives drawn from ``tc.metadata`` or the
                    # success-indicator list.
                    hydra_cfg = redteam_cfg.get("hydra") or {}
                    hydra = await run_hydra_attack(
                        probe, tc, attacker, judge=judge,
                        objectives=hydra_cfg.get("objectives"),
                        max_turns=int(hydra_cfg.get("max_turns", 3)),
                        concurrency=int(hydra_cfg.get("concurrency", 4)),
                    )
                    resp = hydra.final
                elif tc.turns:
                    # Multi-turn: route through run_multi_turn so the
                    # judge can short-circuit a clearly-refusing escalation.
                    mt = await run_multi_turn(probe, tc, judge=judge)
                    resp = mt.final
                else:
                    resp = await probe.chat(tc.prompt, system=tc.system)
            except (ProviderError, asyncio.TimeoutError, Exception) as e:  # noqa: BLE001
                log.warning("payload %s probe failed: %s", tc.id, e)
                err = str(e)[:200]
                resp = None

            # LLM10 encoded-payload fallback. Some providers reject an
            # encoded probe (base64 / hex / ascii-smuggling strategy
            # variant) with an HTTP 4xx before the model ever reasons
            # about it, so every LLM10 variant comes back unusable.
            # Retry ONCE with the plaintext form of the same probe so
            # LLM10 still exercises the target. Bounded to a single retry
            # and scoped to LLM10 — LLM01–09 are untouched.
            if tc.category == "LLM10" and (resp is None or 400 <= resp.http_status < 500):
                plaintext = (base_prompts or {}).get(tc.id.split("::", 1)[0])
                if plaintext and plaintext != tc.prompt:
                    try:
                        resp = await probe.chat(plaintext, system=tc.system)
                        err = None
                        tc.metadata["probe_form"] = "plaintext_fallback"
                        tc.metadata["plaintext_prompt"] = plaintext
                    except (ProviderError, asyncio.TimeoutError, Exception) as e:  # noqa: BLE001
                        log.warning("payload %s plaintext fallback failed: %s", tc.id, e)

            # If an LLM10 probe is STILL a 4xx after the plaintext fallback, the
            # endpoint/adapter rejected the payload outright (agent adapters wrap
            # the prompt and can trip provider limits the bare LLM endpoint
            # doesn't). Do NOT evaluate the raw error body as a model response —
            # that surfaced a bogus "HTTP 401" finding. Mark it inconclusive.
            if (
                tc.category == "LLM10"
                and resp is not None
                and 400 <= getattr(resp, "http_status", 0) < 500
            ):
                err = err or f"endpoint rejected LLM10 probe (HTTP {resp.http_status})"
                resp = None

            if resp is None:
                _dump_transcript(
                    tc, None, Verdict.AMBIGUOUS,
                    f"error: probe transport failed: {err}",
                    endpoint=endpoint, error=err,
                )
                return tc, None, Verdict.AMBIGUOUS, err
            verdict, reason = evaluate_with_reason(tc, resp.text)
            promotion: dict[str, Any] | None = None
            # Embedding-similarity verdict path: when a TestCase has
            # ``success_embeddings`` and an Embedder is configured, a
            # high-cosine match upgrades AMBIGUOUS → VULNERABLE. This
            # catches semantic refusal-bypasses that don't trip any
            # regex success indicator.
            if (
                verdict == Verdict.AMBIGUOUS
                and embedder is not None
                and tc.success_embeddings
            ):
                em_match = await embedder.match(resp.text, tc.success_embeddings)
                if em_match.matched:
                    verdict = Verdict.VULNERABLE
                    reason = f"vulnerable: embedding similarity matched anchor (was {reason})"
                    promotion = {"kind": "embedding", "matched": True}
                else:
                    promotion = {"kind": "embedding", "matched": False}
            if verdict == Verdict.AMBIGUOUS and judge is not None:
                judged = await judge.judge(tc, resp.text)
                if judged is not None:
                    prev = verdict
                    verdict = judged.verdict
                    reason = (
                        f"{verdict.value}: judge upgraded {prev.value} → {verdict.value} "
                        f"(judge={getattr(judged, 'label', None)!r})"
                    )
                    promotion = {
                        "kind": "judge",
                        "verdict": verdict.value,
                        "label": getattr(judged, "label", None),
                        "confidence": getattr(judged, "confidence", None),
                    }
            elif verdict == Verdict.AMBIGUOUS and self_judge and resp.text.strip():
                # No dedicated / external judge configured → default to
                # self-judge (target model classifies its own output)
                # instead of leaving the verdict AMBIGUOUS. The classify
                # call rides the same probe (rate limit + budget apply)
                # and is never itself judged, so there is no recursion.
                judged = await run_self_judge(probe, tc, resp.text)
                if judged is not None:
                    prev = verdict
                    verdict = judged.verdict
                    reason = (
                        f"{verdict.value}: self-judge classified {prev.value} → "
                        f"{verdict.value} (target model, conf={judged.confidence:.2f})"
                    )
                    promotion = {
                        "kind": "self_judge",
                        "verdict": verdict.value,
                        "confidence": judged.confidence,
                    }
            # Factuality grading happens after the verdict has had a
            # chance to settle via regex / embeddings / judge. A
            # contradiction upgrades AMBIGUOUS → VULNERABLE; it does
            # NOT downgrade an already-VULNERABLE verdict (refusal
            # primacy is still preserved earlier).
            if (
                verdict == Verdict.AMBIGUOUS
                and factuality is not None
            ):
                contradicted, fact_reason = await factuality.grade(resp.text)
                if contradicted:
                    verdict = Verdict.VULNERABLE
                    reason = f"vulnerable: factuality contradiction ({fact_reason})"
                    promotion = {"kind": "factuality", "reason": fact_reason}
            _dump_transcript(
                tc, resp, verdict, reason,
                endpoint=endpoint, promotion=promotion,
            )
            return tc, resp, verdict, None

        return await asyncio.gather(*(_one(tc) for tc in cases))

    def _aggregate(
        self,
        results: list[tuple[TestCase, ProbeResponse | None, Verdict, str | None]],
        *,
        endpoint: str,
    ) -> list[Finding]:
        """Group VULNERABLE results by (category, technique). One
        Finding per technique with up to ``_EVIDENCE_CAP`` evidence
        rows and a count of any extras."""
        by_group: dict[tuple[str, str], list[tuple[TestCase, ProbeResponse]]] = defaultdict(list)
        for tc, resp, verdict, _err in results:
            if verdict != Verdict.VULNERABLE or resp is None:
                continue
            by_group[(tc.category, tc.technique)].append((tc, resp))

        findings: list[Finding] = []
        for (category, technique), hits in by_group.items():
            # Pick title/severity/remediation from the highest-severity
            # hit so the Finding inherits the worst case in the group.
            hits.sort(key=lambda h: _SEV_RANK[h[0].severity], reverse=True)
            anchor_tc, _anchor_resp = hits[0]
            total = sum(1 for _ in results if _[0].category == category and _[0].technique == technique)
            attacked = total
            succeeded = len(hits)

            evidence: list[Evidence] = []
            for tc, resp in hits[:_EVIDENCE_CAP]:
                snippet = redact_evidence_text(resp.text, limit=_RESPONSE_SNIPPET_CAP)
                request_body = redact_evidence_text(
                    tc.metadata.get("plaintext_prompt")
                    or ("\n---\n".join(tc.turns) if tc.turns else tc.prompt),
                    limit=500,
                )
                evidence.append(Evidence(
                    request_method="POST",
                    request_url=endpoint,
                    request_headers={},
                    # Truncate the prompt — payloads can include long
                    # tag / encoding setups that aren't useful in the
                    # report. Full prompt is retrievable from the
                    # YAML library by id.
                    request_body=request_body,
                    response_status=resp.http_status,
                    response_headers={},
                    response_body_snippet=snippet,
                    description=(
                        f"Payload {tc.id} ({tc.technique}) — model produced output matching success indicators."
                        + (" [plaintext fallback: encoded form was rejected with HTTP 4xx]"
                           if tc.metadata.get("probe_form") == "plaintext_fallback" else "")
                    ),
                ))
            extra = succeeded - len(evidence)
            if extra > 0:
                evidence[0].description += (
                    f" (+{extra} additional successful payload(s) suppressed for brevity)"
                )

            findings.append(Finding(
                title=f"{anchor_tc.title} ({succeeded}/{attacked} payloads)",
                severity=anchor_tc.severity,
                category=f"llm_{technique}",
                owasp_category=category,
                description=(
                    f"{anchor_tc.description}\n\n"
                    f"Pencheff's LLM red-team engine sent {attacked} payload(s) "
                    f"in the '{technique}' technique against the configured "
                    f"endpoint. {succeeded} elicited responses that matched "
                    f"the technique's success indicators while NOT matching "
                    f"any refusal pattern, so the model behaviour is "
                    f"considered exploited under the engine's verdict rules."
                ),
                remediation=anchor_tc.remediation,
                endpoint=endpoint,
                parameter=None,
                evidence=evidence,
                cwe_id=anchor_tc.cwe,
            ))
        findings.extend(self._threshold_findings(results, endpoint=endpoint))
        findings.extend(self._transport_health_findings(results, endpoint=endpoint))
        return findings

    def _transport_health_findings(
        self,
        results: list[tuple[TestCase, ProbeResponse | None, Verdict, str | None]],
        *,
        endpoint: str,
    ) -> list[Finding]:
        """Emit a high-priority finding when most/all probes failed at
        the HTTP layer.

        Without this, a target that 401s every request looks identical
        in the report to a target that bulletproof-refuses every
        request: zero findings, Grade A. That's a credibility-destroying
        outcome — the operator needs to be told the scan was effectively
        a no-op."""
        if not results:
            return []
        total = len(results)
        non_2xx: list[tuple[TestCase, ProbeResponse]] = []
        empty_text: list[tuple[TestCase, ProbeResponse]] = []
        transport_errors: list[tuple[TestCase, str]] = []
        status_counter: dict[int, int] = {}
        for tc, resp, _verdict, err in results:
            if resp is None:
                if err:
                    transport_errors.append((tc, err))
                continue
            status_counter[resp.http_status] = status_counter.get(resp.http_status, 0) + 1
            # http_status == 0 is the executable-provider's "exit ≠ 0" tag
            if resp.http_status >= 400 or resp.http_status == 0:
                non_2xx.append((tc, resp))
            elif not resp.text.strip():
                empty_text.append((tc, resp))

        failed = len(non_2xx) + len(transport_errors)
        threshold = max(1, total // 2)  # ≥50% failure → finding
        out: list[Finding] = []
        if failed >= threshold:
            # Pick the most common status code for the title; if it's
            # auth-shaped (401/403) bump severity to CRITICAL so a
            # misconfigured scan can't slip past as INFO.
            top_status = max(status_counter.items(), key=lambda kv: kv[1], default=(0, 0))
            sev = (
                Severity.CRITICAL if top_status[0] in {401, 403}
                else Severity.HIGH if top_status[0] in {404, 429}
                else Severity.MEDIUM
            )
            ev_rows: list[Evidence] = []
            for tc, resp in non_2xx[:_EVIDENCE_CAP]:
                ev_rows.append(Evidence(
                    request_method="POST",
                    request_url=endpoint,
                    request_body=redact_evidence_text(tc.prompt, limit=200),
                    response_status=resp.http_status,
                    response_body_snippet=redact_evidence_text(resp.response_body, limit=400),
                    description=f"Payload {tc.id} → HTTP {resp.http_status}",
                ))
            for tc, err in transport_errors[:max(1, _EVIDENCE_CAP - len(ev_rows))]:
                ev_rows.append(Evidence(
                    request_method="POST",
                    request_url=endpoint,
                    request_body=redact_evidence_text(tc.prompt, limit=200),
                    description=f"Payload {tc.id} transport error: {err[:200]}",
                ))
            status_breakdown = ", ".join(
                f"{count}× HTTP {code}" for code, count in sorted(status_counter.items())
            )
            remediation_hint = {
                401: "Verify the Authorization header includes the 'Bearer ' prefix and the API key is valid + not rotated. For OpenRouter, also include `HTTP-Referer` and `X-Title` headers.",
                403: "The API key is recognised but lacks permission. Check tier/quota, model access lists, and whether the model id is gated.",
                404: "The endpoint URL or model id is wrong. Confirm the target is the chat-completions endpoint (not a model info page) and the model id matches the provider's catalog.",
                429: "Rate-limited. Lower max_rpm / concurrency, or upgrade the provider tier. OpenRouter free models are typically capped at 20 RPM.",
            }.get(top_status[0], "Verify the endpoint URL, model id, and auth headers via curl before re-running the scan.")
            out.append(Finding(
                # Stable title — `_aggregate` runs per module so the
                # FindingsDB dedup key (endpoint|parameter|category|title)
                # collapses 10 module-level emissions into one.
                title=f"LLM endpoint unreachable / unauthorised (HTTP {top_status[0]})",
                severity=sev,
                category="llm_endpoint_unreachable",
                owasp_category="LLM10",
                description=(
                    f"Pencheff's LLM red-team engine sent {total} probes against the "
                    f"configured endpoint. {failed} of them ({100 * failed // total}%) failed "
                    f"at the transport / HTTP layer ({status_breakdown}; transport errors: "
                    f"{len(transport_errors)}). When the endpoint cannot be reached, the "
                    f"engine cannot grade the model's safety behaviour — this scan's "
                    f"otherwise-clean report should NOT be interpreted as evidence the model "
                    f"is safe."
                ),
                remediation=remediation_hint,
                endpoint=endpoint,
                parameter=None,
                evidence=ev_rows,
                cwe_id="CWE-287" if top_status[0] in {401, 403} else "CWE-693",
            ))
        elif empty_text and len(empty_text) >= total // 4:
            # Soft warning: 2xx but empty content. Catches misconfigured
            # response_path or providers that silently truncate.
            out.append(Finding(
                title="LLM probes returned empty response text",
                severity=Severity.LOW,
                category="llm_empty_response",
                owasp_category="LLM10",
                description=(
                    "A meaningful share of probes returned 2xx with empty extracted "
                    "text. This usually means the response_path is wrong (custom "
                    "provider), the upstream truncated mid-stream, or the model "
                    "emitted only tool_calls / refusal-only output. Verdict for "
                    "these probes degrades to AMBIGUOUS and emits no finding — "
                    "investigate before trusting the report."
                ),
                remediation="Verify response_path; confirm streaming is consumed; "
                "test the endpoint with a known-compliant prompt.",
                endpoint=endpoint,
                evidence=[Evidence(
                    request_method="POST", request_url=endpoint,
                    request_body=redact_evidence_text(empty_text[0][0].prompt, limit=200),
                    response_status=empty_text[0][1].http_status,
                    description=f"{len(empty_text)} probes returned empty text.",
                )],
            ))
        return out

    def _threshold_findings(
        self,
        results: list[tuple[TestCase, ProbeResponse | None, Verdict, str | None]],
        *,
        endpoint: str,
    ) -> list[Finding]:
        cfg = getattr(self, "_last_llm_config", None) or {}
        raw = cfg.get("thresholds") or (cfg.get("redteam") or {}).get("thresholds")
        if not isinstance(raw, dict):
            return []
        max_latency_ms = raw.get("max_latency_ms")
        max_tokens_per_call = raw.get("max_tokens_per_call")
        findings: list[Finding] = []

        latency_hits = [
            (tc, resp) for tc, resp, _verdict, _err in results
            if resp is not None
            and max_latency_ms is not None
            and resp.latency_ms > int(max_latency_ms)
        ]
        if latency_hits:
            worst_tc, worst_resp = max(latency_hits, key=lambda row: row[1].latency_ms)
            findings.append(Finding(
                title=f"LLM latency threshold exceeded ({len(latency_hits)} payloads)",
                severity=Severity.LOW,
                category="llm_threshold_latency",
                owasp_category="LLM10",
                description=(
                    f"{len(latency_hits)} payload(s) exceeded max_latency_ms={max_latency_ms}. "
                    f"Worst case was {worst_resp.latency_ms}ms for payload {worst_tc.id}."
                ),
                remediation="Add request timeouts, streaming cutoffs, rate limits, and shorter output caps for expensive prompts.",
                endpoint=endpoint,
                evidence=[Evidence(
                    request_method="POST",
                    request_url=endpoint,
                    request_body=redact_evidence_text(worst_tc.prompt, limit=500),
                    response_status=worst_resp.http_status,
                    response_body_snippet=redact_evidence_text(worst_resp.text, limit=_RESPONSE_SNIPPET_CAP),
                    description=f"Latency {worst_resp.latency_ms}ms exceeded threshold {max_latency_ms}ms.",
                )],
                cwe_id="CWE-400",
            ))

        token_hits = []
        if max_tokens_per_call is not None:
            limit = int(max_tokens_per_call)
            for tc, resp, _verdict, _err in results:
                if resp is None:
                    continue
                total = int(resp.input_tokens or 0) + int(resp.output_tokens or 0)
                if total > limit:
                    token_hits.append((tc, resp, total))
        if token_hits:
            worst_tc, worst_resp, worst_total = max(token_hits, key=lambda row: row[2])
            findings.append(Finding(
                title=f"LLM token threshold exceeded ({len(token_hits)} payloads)",
                severity=Severity.LOW,
                category="llm_threshold_tokens",
                owasp_category="LLM10",
                description=(
                    f"{len(token_hits)} payload(s) exceeded max_tokens_per_call={max_tokens_per_call}. "
                    f"Worst case used {worst_total} tokens for payload {worst_tc.id}."
                ),
                remediation="Set stricter max_tokens, truncate inputs, and reject recursive or expansion-heavy prompts.",
                endpoint=endpoint,
                evidence=[Evidence(
                    request_method="POST",
                    request_url=endpoint,
                    request_body=redact_evidence_text(worst_tc.prompt, limit=500),
                    response_status=worst_resp.http_status,
                    response_body_snippet=redact_evidence_text(worst_resp.text, limit=_RESPONSE_SNIPPET_CAP),
                    description=f"Token count {worst_total} exceeded threshold {max_tokens_per_call}.",
                )],
                cwe_id="CWE-400",
            ))
        return findings

    def get_techniques(self) -> list[str]:
        # Defer to the YAML — the list is whatever techniques the
        # payload library declares.
        try:
            cases = _load_payloads(self.payload_file)
        except Exception:
            return []
        seen: list[str] = []
        for c in cases:
            if c.technique not in seen:
                seen.append(c.technique)
        return seen


def severity_max(*levels: Severity) -> Severity:
    return max(levels, key=lambda s: _SEV_RANK[s])


# Re-export Path for tests that need to locate payload files.
PAYLOADS_DIR: Path = Path(__file__).parent / "payloads"
