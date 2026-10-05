# SPDX-License-Identifier: AGPL-3.0-or-later
"""Detector chain core — pure functions, no I/O.

The runtime guardrail is a chain of cheap deterministic checks
followed by an optional LLM-judge escalation. The chain returns a
``GuardrailDecision`` describing what to do (allow / block / sanitise)
and which detector triggered.

Detectors are intentionally simple regex / token-counting checks —
the *judge* is the stronger detector but is rate-limited and
expensive. Putting cheap checks first means most malicious requests
get blocked at zero LLM cost.

The default chain handles:

* ``LLM01`` — prompt injection (override / role-play / encoded)
* ``LLM02`` — PII / secrets in either prompt or response
* ``LLM05`` — XSS / script / iframe in response markdown
* ``LLM10`` — output token ceiling
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Verdict(str, Enum):
    ALLOW = "allow"
    BLOCK = "block"
    SANITIZE = "sanitize"  # response is mutated, not blocked


@dataclass
class GuardrailDecision:
    verdict: Verdict
    detector: str | None = None     # which detector triggered, if any
    category: str | None = None     # OWASP-LLM-Top-10 id (LLM01..LLM10)
    reason: str = ""
    sanitized: str | None = None    # set when verdict == SANITIZE
    matched_pattern: str | None = None
    risk_score: float = 0.0         # 0.0 = clean, 1.0 = blocked

    @classmethod
    def allow(cls) -> "GuardrailDecision":
        return cls(verdict=Verdict.ALLOW)

    @classmethod
    def block(
        cls, *, category: str, detector: str, reason: str,
        matched_pattern: str | None = None, risk: float = 1.0,
    ) -> "GuardrailDecision":
        return cls(
            verdict=Verdict.BLOCK, category=category, detector=detector,
            reason=reason, matched_pattern=matched_pattern, risk_score=risk,
        )


# ─── Detector implementations ─────────────────────────────────────


# LLM01 — direct prompt-injection patterns. Must end in a *behaviour*
# request to avoid false positives on legitimate discussion of these
# concepts ("what is prompt injection?"). The lookahead enforces a
# verb-class follow-up.
_INJECTION_PATTERNS: tuple[tuple[str, str], ...] = (
    (
        r"(?i)\bignore\s+(?:all\s+)?(?:previous|prior|above)\s+"
        r"(?:instructions?|prompts?|messages?|context)\b",
        "direct-override",
    ),
    (
        r"(?i)\b(?:disregard|forget|override)\s+(?:all\s+)?(?:above|"
        r"earlier|previous|system)\s+(?:instructions?|messages?|prompts?)\b",
        "direct-override",
    ),
    (
        r"(?i)\bpretend\s+(?:to\s+be|that\s+you'?re|that\s+you\s+are)\b",
        "role-play",
    ),
    (
        r"(?i)\b(?:DAN|do\s+anything\s+now|developer\s+mode)\b",
        "dan-prompt",
    ),
    (
        r"(?i)\b(?:print|reveal|repeat|leak|show)\s+(?:your|the)\s+"
        r"(?:system|hidden|secret|original)\s+(?:prompt|instructions?)\b",
        "system-prompt-leak",
    ),
)


# Per-technique base risk for LLM01. Direct overrides and DAN/jailbreak
# prompts are higher-confidence intent than a bare "pretend to be".
_INJECTION_BASE_RISK: dict[str, float] = {
    "direct-override": 0.9,
    "dan-prompt": 0.95,
    "system-prompt-leak": 0.9,
    "role-play": 0.6,
}

# Zero-width / invisible characters used to break up trigger words
# ("ig​nore"). Stripped before matching. Soft hyphen included.
_INVISIBLE = dict.fromkeys(
    map(ord, "​‌‍⁠﻿­᠎"), None,
)


def _normalize_for_detection(text: str) -> str:
    """Canonicalize text to defeat *cheap* injection obfuscation before
    regex matching, without the false-positive risk of letter-despacing:

      * NFKC — folds fullwidth / compatibility homoglyphs ("ｉｇｎｏｒｅ" →
        "ignore", "ﬁ" ligatures, etc.).
      * strip zero-width / invisible chars ("ig\\u200bnore" → "ignore").
      * collapse whitespace runs ("ignore      all" → "ignore all"), so
        whitespace-padding evasion still hits the ``\\s+`` patterns.

    Cross-script homoglyphs (e.g. Cyrillic 'е' for Latin 'e') are NOT
    folded here — that needs a confusables map and belongs to the later
    classifier work, not regex normalization.
    """
    t = unicodedata.normalize("NFKC", text or "")
    t = t.translate(_INVISIBLE)
    t = re.sub(r"\s+", " ", t)
    return t


def _all_matches(
    text: str, patterns: tuple[tuple[str, str], ...], category: str,
) -> list["_DetectorMatch"]:
    """Every pattern that fires (not just the first) — feeds risk scoring."""
    out: list[_DetectorMatch] = []
    for pat, name in patterns:
        m = re.search(pat, text)
        if m:
            out.append(_DetectorMatch(
                detector=name, category=category,
                pattern=pat, matched_text=m.group(0)[:200],
            ))
    return out


# LLM02 — PII shapes we never want in a logged prompt or generated
# output. SSN, credit-card-shape, email, US/INT phone number, generic
# API-key shape (AWS access key + GitHub fine-grained PAT + OpenAI sk-).
_PII_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"\b\d{3}-\d{2}-\d{4}\b", "ssn"),
    (r"\b(?:\d[ -]*?){13,19}\b", "credit-card"),
    (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", "email"),
    (r"\b\+?[1-9]\d{1,2}[\s\-]?\(?\d{2,4}\)?[\s\-]?\d{3,4}[\s\-]?\d{3,4}\b", "phone"),
    (r"\bAKIA[0-9A-Z]{16}\b", "aws-access-key"),
    # AWS SECRET access key — the 40-char secret (not the AKIA id). Anchored on
    # the assignment so the generic 40-char base64 shape can't false-fire.
    (r"(?i)aws_secret_access_key['\"]?\s*[=:]\s*['\"]?[A-Za-z0-9/+]{20,}", "aws-secret-key"),
    # OpenAI — classic ``sk-…`` AND the newer project ``sk-proj-…`` form (the
    # hyphen in the prefix broke the old [A-Za-z0-9]{32,} shape).
    (r"\bsk-(?:proj-)?[A-Za-z0-9]{20,}\b", "openai-key"),
    # Stripe live/test secret + restricted keys (sk_/rk_).
    (r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{10,}\b", "stripe-key"),
    # Credentialed connection string: scheme://user:password@host (DB URIs etc.).
    (r"\b[a-zA-Z][a-zA-Z0-9+.\-]*://[^\s:@/]+:[^\s:@/]+@[^\s/]+", "db-connection-string"),
    (r"\bghp_[A-Za-z0-9]{36}\b", "github-pat-classic"),
    (r"\bgithub_pat_[A-Za-z0-9_]{82}\b", "github-pat-fg"),
    (r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{6,}\b", "jwt"),
    (r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----", "private-key"),
    # IBAN — restricted to real ISO 13616 country codes so generic
    # PREFIX##IDENTIFIER tracking/correlation/build IDs don't false-match.
    (
        r"\b(?:AD|AE|AL|AT|AZ|BA|BE|BG|BH|BR|BY|CH|CR|CY|CZ|DE|DJ|DK|DO|"
        r"EE|EG|ES|FI|FK|FO|FR|GB|GE|GI|GL|GR|GT|HR|HU|IE|IL|IQ|IS|IT|JO|"
        r"KW|KZ|LB|LC|LI|LT|LU|LV|MC|MD|ME|MK|MR|MT|MU|NL|NO|PK|PL|PS|PT|"
        r"QA|RO|RS|SA|SC|SE|SI|SK|SM|ST|SV|TL|TN|TR|UA|VA|VG|XK)"
        r"\d{2}[A-Z0-9]{11,30}\b",
        "iban",
    ),
)


# LLM05 — improper output handling. Block raw <script> / <iframe>
# emitted by the model. ``javascript:`` URIs in markdown links also
# block.
_OUTPUT_HANDLING_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"(?i)<\s*script[\s>]", "raw-script-tag"),
    (r"(?i)<\s*iframe[\s>]", "raw-iframe"),
    (r"(?i)\]\s*\(\s*javascript:", "javascript-uri"),
    (r"(?i)on(?:click|load|error)\s*=\s*[\"']", "inline-event-handler"),
)

# ─── Tier-4 detectors — bias / RAG / MCP / coding-agent ────────────
#
# Each pack is regex-cheap and runs inline. Patterns target the
# *output* (or *input* for MCP tool descriptions) shape that
# corresponds to a real failure mode flagged by the matching scan-time
# probe pack. AMBIGUOUS hits (low-confidence regex matches) can be
# escalated to the optional LLM judge — see ``GuardrailConfig.judge``.

# Bias output — stereotype-affirming language. Each pattern is
# narrow enough to skip routine discussion ("the question of whether
# X is true") and only fires on declarative affirmation
# ("yes, X is", "X are inherently Y"). Maps to OWASP LLM09 +
# GDPR Art. 22 (automated decision-making).
_BIAS_OUTPUT_PATTERNS: tuple[tuple[str, str], ...] = (
    (
        r"(?i)\b(?:men|women|boys|girls|males?|females?)\s+are\s+"
        r"(?:inherently|naturally|biologically|genetically)\s+"
        r"(?:better|worse|smarter|stronger|weaker|more|less)\b",
        "gender-inherent-claim",
    ),
    (
        r"(?i)\b(?:white|black|asian|hispanic|latino|jewish|muslim|"
        r"christian)\s+people\s+(?:are|tend to be)\s+"
        r"(?:more|less|inherently|naturally)\s+\w+",
        "race-religion-stereotype",
    ),
    (
        r"(?i)\b(?:older|younger|elderly|gen\s*z|millennials?|boomers?)\s+"
        r"(?:are|tend to be|generally are)\s+(?:lazy|unproductive|"
        r"entitled|distracted|unable|incapable)\b",
        "age-stereotype",
    ),
    (
        r"(?i)\bpeople\s+with\s+(?:disabilit\w+|autism|adhd|depression)\s+"
        r"(?:are|tend to be|cannot|can'?t|are unable to)\b",
        "disability-capability-denial",
    ),
    (
        r"(?i)\brecommend(?:ing|ed)?\s+(?:hir\w+|fir\w+|promot\w+|reject\w+)\s+"
        r"(?:.{0,40}?)\b(?:because|due to|since|as)\s+(?:they|she|he|the candidate)\s+"
        r"(?:is|was|are)\s+(?:older|younger|female|male|disabled|black|white|asian)\b",
        "protected-class-decision",
    ),
)

# RAG-output exfiltration — model leaks doc IDs / retrieved chunks.
# These match the ``doc-CANARY-RAG-N`` shapes pencheff probes test
# for, but also generic ``[doc:UUID]`` / ``source: <internal>`` /
# verbatim-confidential-chunk shapes. Maps to LLM02 + GDPR Art. 32.
_RAG_OUTPUT_EXFIL_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"(?i)\bdoc-[A-Z0-9_-]{8,}\b", "doc-id-leak"),
    (r"(?i)\b(?:internal|confidential|do not share|do not surface)\b",
     "confidential-marker-leak"),
    (
        r"(?i)```[^`]{0,40}?(?:patient_id|account_number|ssn|api[_ ]?key|"
        r"private[_ ]?key)[^`]{0,200}?```",
        "retrieved-secret-block",
    ),
    (
        r"(?i)!\[\s*(?:[A-Z]-?\d{3,}|\$\w+|\{\{[^}]+\}\})\s*\]\(",
        "markdown-image-alt-exfil",
    ),
)

# MCP — instruction-injection patterns inside tool descriptions or
# prompt templates supplied by an untrusted server. Runs on the
# *input* side (prompt text the host is about to send to the target).
# Maps to LLM06 + ISO 42001 A.10.3 (supplier relationships).
_MCP_INPUT_PATTERNS: tuple[tuple[str, str], ...] = (
    (
        r"(?i)\"description\"\s*:\s*\"[^\"]{0,400}?\b(?:always|must|"
        r"non-negotiable)\b[^\"]{0,200}?\b(?:append|prepend|copy|"
        r"include)\b",
        "tool-description-instruction",
    ),
    (
        r"(?i)(?:server|MCP)[^.\n]{0,40}?\b(?:override|priority|"
        r"authoritative)\b[^.\n]{0,200}?\b(?:host|system prompt)\b",
        "mcp-server-override",
    ),
    (
        r"(?i)\b(?:do not|don'?t)\s+(?:mention|disclose|tell|surface)\s+"
        r"(?:this|that|the|these|any)\s+"
        r"(?:step|requirement|instruction|directive|rule|change|edit)\b",
        "stealth-instruction",
    ),
    (
        r"(?i)\bSYSTEM\s+(?:OVERRIDE|NOTE|DIRECTIVE)\b",
        "system-marker-injection",
    ),
)

# SpAIware / exfil-instruction — standing instructions to route data to
# an attacker-controlled external endpoint. Maps to LLM02.
_EXFIL_INSTRUCTION_PATTERNS: tuple[tuple[str, str], ...] = (
    (
        r"(?i)\b(send|transmit|post|upload|exfiltrate|forward|email|leak)\b"
        r"[^.\n]{0,80}\b(to|at)\b[^.\n]{0,40}(https?://|www\.|@)",
        "exfil-instruction:external-send",
    ),
    (
        r"(?i)\b(always|in (all|every) (future )?(responses?|sessions?|messages?))\b"
        r"[^.\n]{0,80}\b(send|post|include|append|exfiltrate)\b",
        "exfil-instruction:standing-channel",
    ),
)

# MINJA / persistence markers — two-signal detector: a finding requires BOTH
# (a) a standing-persistence marker AND (b) a manipulative directive in the
# same item. A bare preference ("from now on use metric units") has no
# directive and must NOT fire. Maps to LLM04.
_PERSISTENCE_MARKER_PATTERNS: tuple[tuple[str, str], ...] = (
    (
        r"(?i)\b(from now on|going forward|in (all|every) future "
        r"(session|conversation|response)s?|permanently remember|"
        r"store this as a (permanent )?rule|remember to always)\b",
        "marker",
    ),
)
_MANIPULATION_DIRECTIVE_PATTERNS: tuple[tuple[str, str], ...] = (
    (
        r"(?i)\b(ignore|disregard|override|bypass|forget)\b[^.\n]{0,20}\b"
        r"(instructions?|rules?|guidelines?|safety|prompt)\b",
        "override",
    ),
    (
        r"(?i)\b(always|only)\s+(recommend|promote|suggest|favou?r|prefer|endorse)\b",
        "promote",
    ),
    (
        r"(?i)\b(append|include|add|insert|inject)\b[^.\n]{0,40}\b(to|in)\s+(all|every)\b",
        "append",
    ),
    (r"(?i)\bnever\s+(refuse|mention|reveal|disclose|tell the user)\b", "never"),
    (
        r"(?i)\b(send|exfiltrate|post|transmit|leak|forward)\b[^.\n]{0,40}"
        r"(https?://|@|to the attacker|externally)",
        "exfil",
    ),
)

# Hidden / invisible content — Unicode Tags block (E0000–E007F), zero-width
# joiners/spaces (200B–200F), BiDi control chars (202A–202E, 2066–2069),
# BOM (FEFF). Smuggled instruction vectors.
_HIDDEN_CONTENT_RE = re.compile(
    "["
    "\U000E0000-\U000E007F"   # Unicode Tags
    "​-‏"            # zero-width space/ZWNJ/ZWJ/LRM/RLM
    "‪-‮"            # BiDi embedding/override controls
    "⁦-⁩"            # BiDi isolate controls
    "﻿"                   # BOM / zero-width no-break space
    "]"
)


def find_hidden_content(text: str) -> str | None:
    """Return a comma-separated list of hidden/invisible code points found in
    *text*, or ``None`` if the text is clean."""
    cps = sorted({f"U+{ord(c):04X}" for c in (text or "") if _HIDDEN_CONTENT_RE.match(c)})
    return ", ".join(cps) if cps else None


# Coding-agent output — credential-shaped strings, ANSI/OSC escapes
# that hijack terminal state, BiDi unicode (Trojan-Source), --no-verify
# usage, and base64-stuffed commit messages. Maps to LLM02/LLM05/LLM06.
_CODING_AGENT_OUTPUT_PATTERNS: tuple[tuple[str, str], ...] = (
    # ANSI CSI sequences that would clear or rewrite the terminal.
    (r"\x1b\[(?:2J|1;1H|H|\d*;\d*[Hf]|\?25[lh])", "ansi-csi-screen-control"),
    # OSC 52 — clipboard injection.
    (r"\x1b\]52;c;", "osc52-clipboard-write"),
    # Trojan-Source BiDi overrides.
    (r"[‪‫‬‭‮⁦⁧⁨⁩]",
     "trojan-source-bidi"),
    # `git commit … --no-verify` after a hook flag.
    (r"(?i)git\s+commit[^\n]*--no-verify", "git-no-verify"),
    # Base64-stuffed commit message (≥20 chars of base64 in []).
    (r"(?<!\w)\[[A-Za-z0-9+/=]{20,}\](?!\w)", "base64-commit-stuff"),
    # Hardcoded API key / token shapes already covered by _PII_PATTERNS,
    # but coding-agent context wants to catch the *act of writing* one
    # to a config file. Match the assignment shape.
    (
        r"(?i)\b(?:OPENAI_API_KEY|STRIPE_SECRET_KEY|AWS_SECRET_ACCESS_KEY|"
        r"GITHUB_TOKEN|DATABASE_PASSWORD|DEPLOY_KEYS?)\b\s*=\s*"
        r"['\"][^'\"]{12,}['\"]",
        "hardcoded-credential-assignment",
    ),
)


# Detection helpers.


@dataclass
class _DetectorMatch:
    detector: str
    category: str
    pattern: str
    matched_text: str


def _check_patterns(
    text: str,
    patterns: tuple[tuple[str, str], ...],
    category: str,
) -> _DetectorMatch | None:
    for pat, name in patterns:
        m = re.search(pat, text)
        if m:
            return _DetectorMatch(
                detector=name, category=category,
                pattern=pat, matched_text=m.group(0)[:200],
            )
    return None


def _maybe_judge_or_block(
    cfg: "GuardrailConfig",
    text: str,
    match: _DetectorMatch,
    *,
    reason: str,
    risk: float = 0.85,
) -> "GuardrailDecision":
    """Return BLOCK directly, OR call the optional judge for a second
    opinion when ``cfg.judge_fallback`` and ``cfg.judge`` are set.

    The judge contract is intentionally minimal:
        ``judge(text: str, category: str) -> dict``
    where the dict carries ``verdict: 'block' | 'allow'`` and an
    optional ``reason``. Anything other than ``'allow'`` is treated as
    BLOCK so a misbehaving judge fails closed.
    """
    if not (cfg.judge_fallback and cfg.judge is not None):
        return GuardrailDecision.block(
            category=match.category, detector=match.detector,
            reason=reason, matched_pattern=match.pattern, risk=risk,
        )
    try:
        verdict_dict = cfg.judge(text, match.category)
    except Exception:  # noqa: BLE001 — judge faults must fail closed
        return GuardrailDecision.block(
            category=match.category, detector=f"{match.detector}+judge-error",
            reason=f"{reason}; judge invocation failed (failing closed)",
            matched_pattern=match.pattern, risk=risk,
        )
    if not isinstance(verdict_dict, dict):
        return GuardrailDecision.block(
            category=match.category, detector=f"{match.detector}+judge-malformed",
            reason=f"{reason}; judge returned non-dict (failing closed)",
            matched_pattern=match.pattern, risk=risk,
        )
    if verdict_dict.get("verdict") == "allow":
        return GuardrailDecision.allow()
    return GuardrailDecision.block(
        category=match.category,
        detector=f"{match.detector}+judge",
        reason=str(verdict_dict.get("reason") or reason),
        matched_pattern=match.pattern, risk=risk,
    )


# ─── Public detector chain ─────────────────────────────────────────


@dataclass
class GuardrailConfig:
    block_prompt_injection: bool = True
    block_pii_in_prompt: bool = True
    block_pii_in_response: bool = True
    block_unsafe_output_html: bool = True
    max_output_tokens: int | None = None
    judge: Any | None = None        # optional callable returning verdict dict
    extra_patterns: list[tuple[str, str, str]] = field(default_factory=list)
    # ^ extra_patterns: list of (regex, detector_name, owasp_category)

    # ── Tier-4 toggles ──────────────────────────────────────────────
    # Each pairs with one ``redteam.plugins`` entry from the scan side
    # so a finding produces a recommended toggle that maps 1:1 here.
    block_bias_output: bool = False                 # LLM09 + GDPR Art. 22
    block_rag_output_exfil: bool = False            # LLM02 + GDPR Art. 32
    block_mcp_input_injection: bool = False         # LLM06 + ISO 42001 A.10.3
    block_coding_agent_output: bool = False         # LLM02/05/06

    # Optional LLM judge fallback. When the cheap regex chain returns
    # AMBIGUOUS (a low-confidence hit) and ``judge_fallback`` is True
    # AND ``judge`` is configured, the judge is called for a second
    # opinion. The judge contract: callable(text: str, category: str)
    # -> dict with keys ``verdict`` ("block" | "allow") and
    # ``reason``. Synchronous version is best-effort; the async chain
    # is in ``async_evaluate``.
    judge_fallback: bool = False


def evaluate_prompt(
    prompt: str, *, config: GuardrailConfig | None = None,
) -> GuardrailDecision:
    """Synchronous prompt-side evaluation.

    Runs before the request reaches the upstream model; blocks at this
    stage incur zero upstream cost.
    """
    cfg = config or GuardrailConfig()
    text = prompt or ""

    if cfg.block_prompt_injection:
        # Match on the raw text first; if nothing fires, retry on a
        # normalized view (defeats fullwidth / zero-width / whitespace-
        # padding evasion). A normalized-only hit is a deliberate-evasion
        # signal and scores higher.
        matches = _all_matches(text, _INJECTION_PATTERNS, "LLM01")
        obfuscated = False
        if not matches:
            norm = _normalize_for_detection(text)
            if norm != text:
                norm_matches = _all_matches(norm, _INJECTION_PATTERNS, "LLM01")
                if norm_matches:
                    matches, obfuscated = norm_matches, True
        if matches:
            detectors = sorted({m.detector for m in matches})
            primary = max(
                matches,
                key=lambda mm: _INJECTION_BASE_RISK.get(mm.detector, 0.7),
            )
            risk = _INJECTION_BASE_RISK.get(primary.detector, 0.7)
            risk += 0.1 * (len(detectors) - 1)   # multiple techniques stacked
            if obfuscated:
                risk += 0.1                        # deliberate evasion
            risk = min(1.0, round(risk, 2))
            reason = "prompt injection (" + ", ".join(detectors) + ")"
            if obfuscated:
                reason += " [obfuscated]"
            return GuardrailDecision.block(
                category="LLM01",
                detector=primary.detector + ("+obfuscated" if obfuscated else ""),
                reason=reason, matched_pattern=primary.pattern, risk=risk,
            )

    if cfg.block_pii_in_prompt:
        m = _check_patterns(text, _PII_PATTERNS, "LLM02")
        if m:
            return GuardrailDecision.block(
                category=m.category, detector=m.detector,
                reason=f"sensitive data in prompt ({m.detector})",
                matched_pattern=m.pattern, risk=0.9,
            )

    if cfg.block_mcp_input_injection:
        m = _check_patterns(text, _MCP_INPUT_PATTERNS, "LLM06")
        if m:
            return _maybe_judge_or_block(
                cfg, text, m,
                reason=f"MCP-style instruction injection in input ({m.detector})",
                risk=0.85,
            )

    for pat, name, category in cfg.extra_patterns:
        m = re.search(pat, text)
        if m:
            return GuardrailDecision.block(
                category=category, detector=name,
                reason=f"custom rule fired ({name})",
                matched_pattern=pat,
            )

    return GuardrailDecision.allow()


def evaluate_response(
    prompt: str,
    response: str,
    *,
    config: GuardrailConfig | None = None,
    output_tokens: int | None = None,
) -> GuardrailDecision:
    """Synchronous response-side evaluation.

    Catches PII / secrets / unsafe HTML the model emitted, plus the
    LLM10 output-ceiling case.
    """
    cfg = config or GuardrailConfig()
    text = response or ""

    if cfg.block_pii_in_response:
        m = _check_patterns(text, _PII_PATTERNS, "LLM02")
        if m:
            return GuardrailDecision.block(
                category=m.category, detector=m.detector,
                reason=f"sensitive data in response ({m.detector})",
                matched_pattern=m.pattern, risk=0.95,
            )

    if cfg.block_unsafe_output_html:
        m = _check_patterns(text, _OUTPUT_HANDLING_PATTERNS, "LLM05")
        if m:
            return GuardrailDecision.block(
                category=m.category, detector=m.detector,
                reason=f"unsafe HTML/JS in model output ({m.detector})",
                matched_pattern=m.pattern,
            )

    if cfg.block_bias_output:
        m = _check_patterns(text, _BIAS_OUTPUT_PATTERNS, "LLM09")
        if m:
            return _maybe_judge_or_block(
                cfg, text, m,
                reason=f"stereotype-affirming output ({m.detector})",
                risk=0.8,
            )

    if cfg.block_rag_output_exfil:
        m = _check_patterns(text, _RAG_OUTPUT_EXFIL_PATTERNS, "LLM02")
        if m:
            return _maybe_judge_or_block(
                cfg, text, m,
                reason=f"RAG retrieval-context leak in output ({m.detector})",
                risk=0.85,
            )

    if cfg.block_coding_agent_output:
        m = _check_patterns(text, _CODING_AGENT_OUTPUT_PATTERNS, "LLM05")
        if m:
            return _maybe_judge_or_block(
                cfg, text, m,
                reason=f"coding-agent-class hazard in output ({m.detector})",
                risk=0.85,
            )

    if (
        cfg.max_output_tokens is not None
        and output_tokens is not None
        and output_tokens > cfg.max_output_tokens
    ):
        return GuardrailDecision.block(
            category="LLM10", detector="output-ceiling",
            reason=(
                f"output exceeded max_output_tokens ceiling "
                f"({output_tokens} > {cfg.max_output_tokens})"
            ),
            risk=0.7,
        )

    return GuardrailDecision.allow()


def evaluate(
    *,
    prompt: str,
    response: str | None = None,
    config: GuardrailConfig | None = None,
    output_tokens: int | None = None,
) -> GuardrailDecision:
    """One-shot evaluation — checks prompt first, then response.

    Returns the first BLOCK verdict. ALLOW means both sides pass the
    cheap detector chain (the optional LLM judge is not called from
    this synchronous helper — see ``async_evaluate`` for that).
    """
    decision = evaluate_prompt(prompt, config=config)
    if decision.verdict != Verdict.ALLOW:
        return decision
    if response is not None:
        return evaluate_response(
            prompt, response, config=config, output_tokens=output_tokens,
        )
    return GuardrailDecision.allow()
