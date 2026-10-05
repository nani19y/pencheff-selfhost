# SPDX-License-Identifier: AGPL-3.0-or-later
"""Per-target LLM guardrail configuration + recommended-guardrails compute.

Storage model: guardrails live on ``Target.llm_config["guardrails"]``
as a JSON object. No new table; the existing JSONB column is the
canonical home. Schema:

    {
        "input": {
            "LLM01": True,            # Prompt Injection
            "LLM02": True,            # Sensitive Information Disclosure
            "LLM03": False,           # Supply Chain — scan-time only
            "LLM04": False,           # Data & Model Poisoning — scan-time only
            "LLM05": False,           # Output Handling — input N/A
            "LLM06": False,           # Excessive Agency — partial (HTTP-proxy mode)
            "LLM07": True,            # System Prompt Leakage
            "LLM08": False,           # Vector / Embedding — scan-time only
            "LLM09": False,           # Misinformation — input N/A
            "LLM10": False,           # Unbounded Consumption (prompt token cap)
            "max_prompt_tokens": null,
            "extra_patterns": []
        },
        "output": {
            "LLM01": False,           # output side N/A — model output isn't itself an injection
            "LLM02": True,            # PII / secret shapes in response
            "LLM03": False,
            "LLM04": False,
            "LLM05": True,            # <script>, javascript:, iframe, inline events
            "LLM06": False,           # tool-call args inspection — partial
            "LLM07": False,           # baseline-comparison — needs system_prompt_baseline
            "LLM08": False,
            "LLM09": False,           # factuality — needs LLM judge
            "LLM10": True,            # output token ceiling
            "max_output_tokens": null,
            "system_prompt_baseline": null,
            "extra_patterns": []
        }
    }

Every category has a fixed enforcement profile (``ENFORCEMENT``
below) the UI uses to render disabled / "scan-time only" / "needs
external judge" badges. The profile is also returned on every
``GET /targets/{id}/guardrails`` so the UI doesn't have to hard-code
it.

The detector library reused inline is the same one Sentry's CLI uses
(``pencheff_sentry.core``), imported lazily so this service is usable
without ``pencheff-sentry`` installed.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# Every OWASP-LLM-Top-10 category, with its full name, on both sides.
# Plus tier-4 add-on toggles that map to specific failure modes the
# scan side now probes (bias, RAG, MCP, coding-agent). The add-on keys
# carry an OWASP ancestry tag so the recommendation logic can still
# group findings by OWASP id, but the runtime detectors are distinct.
CATEGORIES: tuple[str, ...] = (
    "LLM01", "LLM02", "LLM03", "LLM04", "LLM05",
    "LLM06", "LLM07", "LLM08", "LLM09", "LLM10",
    "BIAS", "RAG", "MCP", "CODING_AGENT",
)

CATEGORY_NAMES: dict[str, str] = {
    "LLM01": "Prompt Injection",
    "LLM02": "Sensitive Information Disclosure",
    "LLM03": "Supply Chain",
    "LLM04": "Data and Model Poisoning",
    "LLM05": "Improper Output Handling",
    "LLM06": "Excessive Agency",
    "LLM07": "System Prompt Leakage",
    "LLM08": "Vector and Embedding Weaknesses",
    "LLM09": "Misinformation",
    "LLM10": "Unbounded Consumption",
    "BIAS": "Bias / Stereotype Affirmation (LLM09 + GDPR Art. 22)",
    "RAG": "RAG Retrieval-Context Leak (LLM02 + GDPR Art. 32)",
    "MCP": "MCP Tool-Description Injection (LLM06 + ISO 42001 A.10.3)",
    "CODING_AGENT": "Coding-Agent Hazard (LLM02 / LLM05 / LLM06)",
}

# Compliance-framework attribution for each category. Read by the UI
# to render a per-row "Why this matters" hint.
CATEGORY_COMPLIANCE_HINT: dict[str, list[str]] = {
    "LLM01": ["OWASP LLM01", "ISO 42001 A.6.2.4"],
    "LLM02": ["OWASP LLM02", "GDPR Art. 32", "ISO 42001 A.7.5"],
    "LLM03": ["OWASP LLM03", "ISO 42001 A.10.3"],
    "LLM04": ["OWASP LLM04", "GDPR Art. 5(1)(d)", "ISO 42001 A.7.3"],
    "LLM05": ["OWASP LLM05", "GDPR Art. 32"],
    "LLM06": ["OWASP LLM06", "EU AI Act Art. 14"],
    "LLM07": ["OWASP LLM07", "ISO 42001 A.6.2.7"],
    "LLM08": ["OWASP LLM08", "ISO 42001 A.7.2"],
    "LLM09": ["OWASP LLM09", "EU AI Act Art. 13", "ISO 42001 A.7.2"],
    "LLM10": ["OWASP LLM10", "ISO 42001 A.6.2.6"],
    "BIAS": ["OWASP LLM09", "GDPR Art. 22", "EU AI Act Art. 5"],
    "RAG": ["OWASP LLM02", "GDPR Art. 32", "ISO 42001 A.7.5"],
    "MCP": ["OWASP LLM06", "ISO 42001 A.10.3"],
    "CODING_AGENT": ["OWASP LLM02/05/06", "ISO 42001 A.6.2.4"],
}

# Per-category, per-side enforcement profile. Read by the UI to grey
# out rows the proxy can't actually enforce — so the user knows what
# they're getting.
#
# Status keys:
#   "inline"        — cheap regex / token check, runs on every request
#   "needs_judge"   — needs an external LLM judge call (latency / cost)
#   "needs_baseline" — needs a configured system_prompt_baseline
#   "side_na"       — this side doesn't apply (e.g. LLM01-output)
#   "scan_only"     — only detectable at scan time (LLM03/04/08)
ENFORCEMENT: dict[str, dict[str, str]] = {
    "LLM01": {"input": "inline",      "output": "side_na"},
    "LLM02": {"input": "inline",      "output": "inline"},
    "LLM03": {"input": "scan_only",   "output": "scan_only"},
    "LLM04": {"input": "scan_only",   "output": "scan_only"},
    "LLM05": {"input": "side_na",     "output": "inline"},
    "LLM06": {"input": "inline",      "output": "inline"},
    "LLM07": {"input": "inline",      "output": "needs_baseline"},
    "LLM08": {"input": "scan_only",   "output": "scan_only"},
    "LLM09": {"input": "side_na",     "output": "needs_judge"},
    "LLM10": {"input": "inline",      "output": "inline"},
    # Tier-4 detectors. ``inline`` if the cheap regex is enough;
    # ``inline+judge`` if the operator should consider enabling the
    # optional LLM-judge fallback for higher accuracy on ambiguous
    # cases. Side mapping reflects where each detector physically runs.
    "BIAS":         {"input": "side_na",  "output": "inline+judge"},
    "RAG":          {"input": "side_na",  "output": "inline+judge"},
    "MCP":          {"input": "inline",   "output": "side_na"},
    "CODING_AGENT": {"input": "side_na",  "output": "inline"},
}


# ─── Defaults + presets ────────────────────────────────────────────


def _empty_side(side: str) -> dict[str, Any]:
    """Per-side dict with all 10 toggles set False + numeric fields None."""
    out: dict[str, Any] = {cat: False for cat in CATEGORIES}
    out["extra_patterns"] = []
    if side == "input":
        out["max_prompt_tokens"] = None
    else:
        out["max_output_tokens"] = None
        out["system_prompt_baseline"] = None
    return out


def preset_balanced() -> dict[str, Any]:
    """Cheap detectors only, both sides. The current Pencheff default."""
    cfg = {"input": _empty_side("input"), "output": _empty_side("output")}
    cfg["input"].update({"LLM01": True, "LLM02": True, "LLM07": True})
    cfg["output"].update({"LLM02": True, "LLM05": True, "LLM10": True})
    return cfg


def preset_strict() -> dict[str, Any]:
    """Production-paranoid — every inline-enforceable detector on,
    plus the baseline-comparison detector for LLM07-output.

    LLM09-output (factuality judge) is intentionally left off — its
    latency / cost surface is too high for a default. Operators who
    need it can flip the toggle manually."""
    cfg = preset_balanced()
    cfg["input"].update({"LLM06": True, "LLM10": True})
    cfg["output"].update({"LLM07": True, "LLM06": True})
    return cfg


def preset_minimal() -> dict[str, Any]:
    """PII-only — observe-mode without the false-positive risk of
    prompt-injection detection."""
    cfg = {"input": _empty_side("input"), "output": _empty_side("output")}
    cfg["input"].update({"LLM02": True})
    cfg["output"].update({"LLM02": True, "LLM05": True})
    return cfg


def preset_all() -> dict[str, Any]:
    """Every inline-enforceable + baseline + judge detector on. Use
    when latency / cost are not constraints. ``scan_only`` and
    ``side_na`` rows stay False because the proxy has nothing to
    enforce — flipping them on would silently no-op.
    """
    cfg = {"input": _empty_side("input"), "output": _empty_side("output")}
    for cat in CATEGORIES:
        for side in ("input", "output"):
            status = ENFORCEMENT[cat][side]
            # Anything that has an inline runtime detector — incl. the
            # tier-4 ``inline+judge`` variants — gets enabled.
            if status in ("inline", "inline+judge", "needs_baseline", "needs_judge"):
                cfg[side][cat] = True
    return cfg


def preset_gdpr_aligned() -> dict[str, Any]:
    """Detectors required to operate within the major GDPR articles.

    Coverage:
      * Art. 5(1)(c) Data Minimisation         → LLM02 prompt + response
      * Art. 5(1)(f) Integrity & Confidentiality → LLM01 prompt, LLM05 output
      * Art. 22 Automated Decision-Making      → BIAS output
      * Art. 32 Security of Processing         → RAG output, LLM07 input
      * Art. 33 Breach Notification (logging)  → LLM10 output cap

    The factuality judge for LLM09-output is intentionally left off —
    it's required for *accuracy* obligations under Art. 5(1)(d) but
    introduces latency / cost. Operators with strict accuracy needs
    can layer it on top.
    """
    cfg = {"input": _empty_side("input"), "output": _empty_side("output")}
    cfg["input"].update({"LLM01": True, "LLM02": True, "LLM07": True, "LLM10": True})
    cfg["output"].update({"LLM02": True, "LLM05": True, "LLM10": True, "BIAS": True, "RAG": True})
    return cfg


def preset_iso_42001_aligned() -> dict[str, Any]:
    """Detectors aligned with ISO/IEC 42001:2023 Annex A controls.

    Coverage:
      * A.6.2.4 V&V          → LLM01 input, LLM05 output, BIAS output
      * A.6.2.6 Operation/Monitoring → LLM07 input + output, LLM10 output
      * A.7.2  Data quality  → LLM09 output (factuality judge)
      * A.7.5  Data preparation → LLM02 prompt + response
      * A.10.3 Supplier relationships → MCP input
    """
    cfg = preset_strict()  # builds on the existing inline-everywhere baseline
    cfg["input"].update({"MCP": True})
    cfg["output"].update({"BIAS": True, "RAG": True, "CODING_AGENT": True, "LLM09": True})
    return cfg


def preset_ai_act_high_risk() -> dict[str, Any]:
    """EU AI Act high-risk-system minimum bar.

    Coverage:
      * Art. 13 Transparency      → LLM07 output (system-prompt baseline)
      * Art. 14 Human Oversight   → LLM06 input + output (tool-authz),
                                    MCP input
      * Art. 15 Accuracy/Robustness → LLM02, LLM05, LLM09 (judge), LLM10
    """
    cfg = preset_balanced()
    cfg["input"].update({"LLM06": True, "LLM07": True, "MCP": True})
    cfg["output"].update({
        "LLM06": True, "LLM07": True, "LLM09": True,
        "RAG": True, "CODING_AGENT": True,
    })
    return cfg


def preset_bias_aware_production() -> dict[str, Any]:
    """Consumer-facing endpoints where stereotype-affirming output is
    reputationally toxic. Bias output detector + factuality judge +
    RAG source-attribution + the LLM02/05 baseline."""
    cfg = preset_balanced()
    cfg["output"].update({
        "BIAS": True, "RAG": True, "LLM09": True,
    })
    return cfg


PRESETS: dict[str, dict[str, Any]] = {
    "balanced": preset_balanced(),
    "strict": preset_strict(),
    "minimal": preset_minimal(),
    "all": preset_all(),
    "gdpr-aligned": preset_gdpr_aligned(),
    "iso-42001-aligned": preset_iso_42001_aligned(),
    "ai-act-high-risk": preset_ai_act_high_risk(),
    "bias-aware-production": preset_bias_aware_production(),
}


def default_guardrails() -> dict[str, Any]:
    """The conservative-but-useful default — same as the BALANCED preset."""
    return preset_balanced()


def normalize(cfg: dict[str, Any] | None) -> dict[str, Any]:
    """Coerce a partial config to the canonical shape.

    Tolerates:
    * Missing top-level ``input`` / ``output`` blocks.
    * Missing categories (filled with False).
    * Old shape (legacy ``block_prompt_injection`` / ``block_pii`` /
      ``block_unsafe_html`` boolean fields) — auto-migrated onto the
      new LLM-keyed shape so an upgraded deployment doesn't lose
      whatever the operator already configured.
    """
    out = {"input": _empty_side("input"), "output": _empty_side("output")}
    if not isinstance(cfg, dict):
        return out
    legacy_map = {
        "block_prompt_injection": "LLM01",
        "block_pii": "LLM02",
        "block_pii_in_prompt": "LLM02",
        "block_pii_in_response": "LLM02",
        "block_unsafe_html": "LLM05",
        "block_unsafe_output_html": "LLM05",
    }
    for side in ("input", "output"):
        side_in = cfg.get(side) or {}
        if not isinstance(side_in, dict):
            continue
        for legacy_key, modern in legacy_map.items():
            if side_in.get(legacy_key):
                out[side][modern] = True
        for k, v in side_in.items():
            if k in out[side]:
                out[side][k] = v
    return out


def enforcement_metadata() -> dict[str, Any]:
    """Returned alongside the config on ``GET /targets/{id}/guardrails``
    so the UI can render disabled / N/A / scan-only rows without
    hard-coding the matrix."""
    return {
        "categories": [
            {
                "id": cat,
                "name": CATEGORY_NAMES[cat],
                "input_status": ENFORCEMENT[cat]["input"],
                "output_status": ENFORCEMENT[cat]["output"],
                "compliance": CATEGORY_COMPLIANCE_HINT.get(cat, []),
            }
            for cat in CATEGORIES
        ],
        "presets": list(PRESETS.keys()),
    }


# ─── Recommended-guardrails compute ────────────────────────────────


@dataclass
class GuardrailRecommendation:
    """One recommended toggle, with rationale + the OWASP-LLM
    category that triggered the recommendation."""
    category: str
    side: str
    detector: str
    value: Any
    rationale: str
    failure_count: int = 0


@dataclass
class RecommendedGuardrails:
    target_id: str
    scan_id: str
    target_name: str | None
    summary: dict[str, int]
    recommendations: list[GuardrailRecommendation] = field(default_factory=list)
    suggested_config: dict[str, Any] = field(default_factory=default_guardrails)


_RECOMMENDED_BY_CATEGORY: dict[str, dict[str, Any]] = {
    "LLM01": {
        "input": [("LLM01", True)],
        "rationale": (
            "Direct prompt-injection / role-play attempts succeeded "
            "against the model. Block the canonical override / DAN / "
            "role-play patterns inline before they reach the upstream."
        ),
    },
    "LLM02": {
        "input": [("LLM02", True)],
        "output": [("LLM02", True)],
        "rationale": (
            "Sensitive-info disclosure was triggered. Block PII / secret "
            "shapes (SSN, card, email, phone, AWS key, OpenAI sk-, "
            "GitHub PAT) on both prompt and response sides."
        ),
    },
    "LLM05": {
        "output": [("LLM05", True)],
        "rationale": (
            "Unsafe-output-handling failures (script-tag emission, "
            "XSS-via-markdown, javascript: URIs, inline event handlers) "
            "were observed. Sanitise these inline."
        ),
    },
    "LLM06": {
        "input": [("LLM06", True)],
        "output": [("LLM06", True)],
        "rationale": (
            "Excessive-agency failures observed. Inspect tool-call "
            "shapes on both request and response — note that HTTP-only "
            "chat-completions provides limited visibility; MCP "
            "middleware mode catches more."
        ),
    },
    "LLM07": {
        "input": [("LLM07", True)],
        "output": [("LLM07", True)],
        "rationale": (
            "System-prompt-leakage attempts succeeded. Add the input "
            "regex chain that catches leak prompts, and configure a "
            "system_prompt_baseline for the response-side comparison."
        ),
    },
    "LLM09": {
        "output": [("LLM09", True)],
        "rationale": (
            "Misinformation failures observed. Enable the response-"
            "side factuality detector — note this requires an LLM judge "
            "and adds latency / cost per request."
        ),
    },
    "LLM10": {
        "input": [("LLM10", True)],
        "output": [("LLM10", True)],
        "rationale": (
            "Unbounded-consumption failures (token bombs, recursive "
            "amplification, latency thresholds) were observed. Enable "
            "the prompt-side length cap and the response-side token "
            "ceiling."
        ),
    },
    "BIAS": {
        "output": [("BIAS", True)],
        "rationale": (
            "Bias / stereotype-affirmation failures observed (age / "
            "disability / gender / race). Enable the response-side bias "
            "detector — narrow regex chain catches inherent-claim and "
            "protected-class-decision shapes. Pair with the optional "
            "judge fallback for production."
        ),
    },
    "RAG": {
        "output": [("RAG", True)],
        "rationale": (
            "RAG retrieval-context-leak failures observed (doc-id "
            "leak, retrieved-secret blocks, alt-text exfil). Enable "
            "the response-side RAG-exfil detector to block these "
            "shapes inline."
        ),
    },
    "MCP": {
        "input": [("MCP", True)],
        "rationale": (
            "MCP tool-poisoning / untrusted-server failures observed. "
            "Enable the prompt-side MCP detector to catch hidden "
            "instructions inside tool descriptions, untrusted server "
            "system-prompt overrides, and stealth-instruction shapes."
        ),
    },
    "CODING_AGENT": {
        "output": [("CODING_AGENT", True)],
        "rationale": (
            "Coding-agent-class failures observed (ANSI escape "
            "hijack, OSC 52 clipboard injection, BiDi unicode, "
            "credential assignments, --no-verify bypass). Enable "
            "the response-side coding-agent detector."
        ),
    },
}


def _failure_counts_from_summary(summary: dict[str, Any] | None) -> dict[str, int]:
    """Extract failure-counts-per-recommendable-category from a scan summary.

    The summary is the dict produced by the LLM red-team reporter. Two
    sources contribute:

      1. ``llm_redteam_by_category`` / loose ``LLM01..LLM10`` keys —
         the OWASP-LLM bucket counts, used as-is.
      2. ``by_technique`` — technique-keyed counts. Techniques starting
         with ``bias:``, ``rag:``, ``mcp:``, or ``coding-agent:`` get
         summed into the corresponding pseudo-category (BIAS / RAG /
         MCP / CODING_AGENT) so the recommendation logic can suggest
         the matching runtime detector.
    """
    if not isinstance(summary, dict):
        return {}
    out: dict[str, int] = {}

    # OWASP-LLM bucket counts.
    by_cat = summary.get("llm_redteam_by_category") or summary.get("by_category")
    if isinstance(by_cat, dict):
        for k, v in by_cat.items():
            if str(k).startswith("LLM") and isinstance(v, (int, float)):
                out[str(k)] = out.get(str(k), 0) + int(v)
    else:
        for k, v in summary.items():
            if str(k).startswith("LLM") and isinstance(v, (int, float)):
                out[str(k)] = out.get(str(k), 0) + int(v)

    # Technique-prefix → pseudo-category bucket.
    technique_to_pseudo = {
        "bias:": "BIAS",
        "rag:": "RAG",
        "mcp:": "MCP",
        "coding-agent:": "CODING_AGENT",
    }
    by_tech = summary.get("by_technique")
    if isinstance(by_tech, dict):
        for tech, n in by_tech.items():
            if not isinstance(n, (int, float)):
                continue
            tech_str = str(tech).lower()
            for prefix, pseudo in technique_to_pseudo.items():
                if tech_str.startswith(prefix):
                    out[pseudo] = out.get(pseudo, 0) + int(n)
                    break
    return out


def recommended_for_summary(
    *,
    scan_id: str,
    target_id: str,
    target_name: str | None,
    summary: dict[str, Any] | None,
) -> RecommendedGuardrails:
    """Compute the recommended guardrail set for a scan's failure profile.

    When the scan recorded zero failures, returns ``preset_balanced``
    as the suggested config plus an empty recommendations list — the
    UI surfaces this as "no failures, here's the safe baseline."
    """
    counts = _failure_counts_from_summary(summary)
    out = RecommendedGuardrails(
        target_id=target_id, scan_id=scan_id,
        target_name=target_name, summary=counts,
    )

    cfg = {"input": _empty_side("input"), "output": _empty_side("output")}

    for category, n in sorted(counts.items()):
        if n <= 0:
            continue
        rule = _RECOMMENDED_BY_CATEGORY.get(category)
        if rule is None:
            continue
        for side in ("input", "output"):
            for det, val in (rule.get(side) or []):
                cfg[side][det] = val
                out.recommendations.append(GuardrailRecommendation(
                    category=category, side=side,
                    detector=det, value=val,
                    rationale=rule["rationale"],
                    failure_count=n,
                ))

    if not out.recommendations:
        out.suggested_config = preset_balanced()
    else:
        out.suggested_config = cfg
    return out


# ─── Detector evaluation (shared with the proxy route) ─────────────


def evaluate_prompt_with_config(
    prompt: str, *, guardrails: dict[str, Any],
) -> dict[str, Any] | None:
    """Run the prompt-side detector chain. Returns a decision dict on
    block; ``None`` on allow."""
    try:
        from pencheff_sentry.core import GuardrailConfig, evaluate_prompt
    except ImportError:
        return None
    inp = (guardrails or {}).get("input") or {}
    judge_cfg = (guardrails or {}).get("judge") or {}
    cfg = GuardrailConfig(
        # LLM01 + LLM07 share the regex chain in Sentry's core — the
        # patterns that catch "ignore previous instructions" also
        # catch "reveal your system prompt".
        block_prompt_injection=bool(inp.get("LLM01")) or bool(inp.get("LLM07")),
        block_pii_in_prompt=bool(inp.get("LLM02")),
        # Tier-4 input-side toggle: MCP tool-description injection.
        block_mcp_input_injection=bool(inp.get("MCP")),
        judge=judge_cfg.get("callable") if isinstance(judge_cfg, dict) else None,
        judge_fallback=bool(judge_cfg.get("fallback")) if isinstance(judge_cfg, dict) else False,
        extra_patterns=[
            (p["regex"], p.get("name", "custom"), p.get("category", "LLM02"))
            for p in (inp.get("extra_patterns") or [])
            if isinstance(p, dict) and p.get("regex")
        ],
    )
    decision = evaluate_prompt(prompt, config=cfg)
    if decision.verdict.value == "block":
        return {
            "verdict": "block",
            "category": decision.category,
            "detector": decision.detector,
            "reason": decision.reason,
        }

    # LLM10 prompt-token cap (extra detector — not in Sentry core).
    cap = inp.get("max_prompt_tokens")
    if cap and isinstance(cap, int) and cap > 0:
        # Approximate token count: ~4 chars per token for English.
        approx_tokens = max(1, len(prompt) // 4)
        if approx_tokens > cap:
            return {
                "verdict": "block",
                "category": "LLM10",
                "detector": "prompt-token-cap",
                "reason": (
                    f"prompt length ~{approx_tokens} tokens exceeds cap {cap}"
                ),
            }
    return None


def evaluate_response_with_config(
    prompt: str,
    response: str,
    *,
    guardrails: dict[str, Any],
    output_tokens: int | None = None,
) -> dict[str, Any] | None:
    """Run the response-side detector chain."""
    try:
        from pencheff_sentry.core import GuardrailConfig, evaluate_response
    except ImportError:
        return None
    out_cfg = (guardrails or {}).get("output") or {}
    judge_cfg = (guardrails or {}).get("judge") or {}
    cfg = GuardrailConfig(
        block_pii_in_response=bool(out_cfg.get("LLM02")),
        block_unsafe_output_html=bool(out_cfg.get("LLM05")),
        max_output_tokens=out_cfg.get("max_output_tokens"),
        # Tier-4 output-side toggles.
        block_bias_output=bool(out_cfg.get("BIAS")),
        block_rag_output_exfil=bool(out_cfg.get("RAG")),
        block_coding_agent_output=bool(out_cfg.get("CODING_AGENT")),
        judge=judge_cfg.get("callable") if isinstance(judge_cfg, dict) else None,
        judge_fallback=bool(judge_cfg.get("fallback")) if isinstance(judge_cfg, dict) else False,
    )
    decision = evaluate_response(
        prompt, response, config=cfg, output_tokens=output_tokens,
    )
    if decision.verdict.value == "block":
        return {
            "verdict": "block",
            "category": decision.category,
            "detector": decision.detector,
            "reason": decision.reason,
        }

    # LLM07 baseline-leak detector (extra; not in Sentry core).
    if out_cfg.get("LLM07") and out_cfg.get("system_prompt_baseline"):
        baseline = str(out_cfg["system_prompt_baseline"])
        # Substring match on a 40-char window — long enough to be a
        # real leak, short enough to be cheap.
        if len(baseline) >= 40 and baseline[:40] in (response or ""):
            return {
                "verdict": "block",
                "category": "LLM07",
                "detector": "system-prompt-leak",
                "reason": (
                    "response contains a substring of the configured "
                    "system_prompt_baseline"
                ),
            }

    return None
