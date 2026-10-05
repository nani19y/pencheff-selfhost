"""AI false-positive triage for repo (SAST) findings.

Mirrors the DAST triage (services/scan_runner.py `_llm_triage`) for repo scans:
after a repo scan persists its findings, the LLM classifies each one and
verified false positives are suppressed in Pencheff's DB (RepoFinding.suppressed
+ suppress_reason/suppress_notes) — the customer's code is never modified.

Why this exists: scanners like bandit are heuristic and over-flag safe code
(e.g. B608 "hardcoded SQL" on PARAMETERIZED queries where the concatenated part
is query structure and user values are bound via ``?``/params). The agentic
fixer can't "fix" already-safe code, so those findings recur every scan. This
classifies them and drops the confirmed false positives from the count.

Severity policy: auto-suppress info/low/MEDIUM false positives at high
confidence (B608-style FPs are typically medium); high/critical are kept visible
but annotated, so a human reviews them even if the model thinks they're FPs.

LLM selection: prefer the org's BYO provider; else the Pencheff classify LLM
(LLM_API_KEY); else fall back to the configured fix-LLM provider — many
deployments only set the fix/agent keys, not LLM_API_KEY, and triage should
still work there. Fail-closed + best-effort: never raises into the scan.
"""
from __future__ import annotations

import asyncio
import logging

from sqlalchemy import select

from ..config import get_settings
from ..db.base import SessionLocal
from ..db.models import RepoFinding
from .ai_gate import org_has_ai
from .llm import FindingInput, LLMClient
from .llm_providers.openai_compat import OpenAICompatClient
from .llm_providers.resolver import resolve_chat_client

log = logging.getLogger("pencheff.repo_fp_triage")

_SUPPRESS_CONFIDENCE = 0.85
# B608-style false positives are typically MEDIUM, so the ceiling includes it.
# High/critical are kept visible (annotated) even if flagged FP — human review.
_AUTO_SUPPRESS_SEVERITIES = frozenset({"info", "low", "medium"})


def _should_suppress(severity: str | None, verdict) -> bool:
    """Auto-suppress only verified, high-confidence false positives at
    info/low/medium severity. Pure → unit-testable."""
    return bool(
        verdict is not None
        and verdict.is_false_positive
        and verdict.confidence >= _SUPPRESS_CONFIDENCE
        and (severity or "medium").lower() in _AUTO_SUPPRESS_SEVERITIES
    )


def _to_finding_input(r: RepoFinding) -> FindingInput:
    return FindingInput(
        id=r.id,
        title=r.title,
        severity=(r.severity or "medium"),
        category=(f"{r.scanner}:{r.rule_id}" if r.rule_id else (r.scanner or "")),
        endpoint=r.file_path,
        parameter=(f"line {r.line_start}" if r.line_start else None),
        description=r.description,
        evidence_excerpt=r.code_snippet,
        cvss_score=None,
    )


def _build_classify_client(org_client) -> LLMClient | None:
    """A classify-ready LLMClient, or None if no LLM is reachable. Fresh
    instance (not the process singleton) so the BYO/fallback injection never
    leaks across calls."""
    client = LLMClient()
    if org_client is not None:
        client.set_org_client(org_client)
        return client
    if client.enabled:  # Pencheff classify LLM (LLM_API_KEY) configured
        return client
    # Fallback: route classification through the configured fix-LLM provider
    # (deployments often set only the fix/agent keys, not LLM_API_KEY).
    s = get_settings()
    if s.fix_llm_api_key:
        client.set_org_client(OpenAICompatClient(
            provider="openai_compatible", model=s.fix_llm_model,
            base_url=s.fix_llm_base_url, api_key=s.fix_llm_api_key))
        return client
    return None


async def triage_repo_findings(repo_scan_id: str, org_id: str) -> dict:
    """Classify a scan's findings and suppress verified false positives.
    Best-effort: returns a small status dict, never raises."""
    try:
        async with SessionLocal() as db:
            ai_on = await org_has_ai(db, org_id)
            org_client = await resolve_chat_client(org_id, db)
        if not ai_on and org_client is None:
            return {"skipped": "ai_disabled"}
        client = _build_classify_client(org_client)
        if client is None:
            return {"skipped": "no_llm"}

        async with SessionLocal() as db:
            rows = (await db.execute(
                select(RepoFinding).where(
                    RepoFinding.repo_scan_id == repo_scan_id,
                    RepoFinding.suppressed.is_(False),
                )
            )).scalars().all()
            if not rows:
                return {"triaged": 0, "suppressed": 0}

            inputs = [_to_finding_input(r) for r in rows]
            # classify_findings is blocking (httpx) → offload off the loop.
            verdicts = await asyncio.to_thread(client.classify_findings, inputs)
            if not verdicts:
                return {"triaged": len(rows), "suppressed": 0}

            suppressed = 0
            for r in rows:
                v = verdicts.get(r.id)
                if not v or not v.is_false_positive or v.confidence < _SUPPRESS_CONFIDENCE:
                    continue
                note = (f"[{client.label} · confidence {v.confidence:.0%}] {v.reason}")[:2000]
                if _should_suppress(r.severity, v):
                    r.suppressed = True
                    r.suppress_reason = "ai_false_positive"
                    r.suppress_notes = note
                    suppressed += 1
                else:
                    # High/critical: keep visible, but record the FP assessment.
                    r.suppress_notes = (
                        "Triage flagged likely false positive but kept visible "
                        f"(severity {r.severity}). {note}")[:2000]
            await db.commit()
            log.info("repo FP-triage scan=%s: %d findings, %d suppressed",
                     repo_scan_id, len(rows), suppressed)
            return {"triaged": len(rows), "suppressed": suppressed}
    except Exception as exc:  # noqa: BLE001 — never break the scan
        log.warning("repo FP-triage failed for scan %s: %s", repo_scan_id, exc)
        return {"skipped": "error"}
