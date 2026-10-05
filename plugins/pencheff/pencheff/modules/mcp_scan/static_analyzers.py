# pencheff/modules/mcp_scan/static_analyzers.py
"""Pure static analyzers over an McpManifest. No network; fully unit-testable.

Each analyze_* returns a list[Finding]. run_all_static() aggregates them.
Detection backed by the research catalog in the spec (line-jumping, Unicode-tag
smuggling, excessive agency, etc.).
"""
from __future__ import annotations

import hashlib
import json
import logging
import re

from pencheff.config import Severity
from pencheff.core.findings import Evidence, Finding

from .manifest import McpManifest, McpTool

# Imperative / override / relay phrasing aimed at the model (line jumping,
# tool-description poisoning — Trail of Bits 2025-04-21).
_POISON_PATTERNS = [
    r"(?i)ignore (the |all |any )?(previous|prior|above) (instructions?|context)",
    r"(?i)do not (tell|mention|inform|reveal)[^.]{0,40}\b(user|human)\b",
    r"(?i)\balways (append|prepend|include|add|respond with)\b",
    r"(?i)\byou must\b[^.]{0,60}\b(append|prefix|run|execute|call)\b",
    r"(?i)<\s*(important|system|secret|instructions?)\s*>",
    r"(?i)\bsystem\s*:\s*",
    r"(?i)before (using|calling) (any )?(other )?tools?",
    r"(?i)\b(act as|behave as) (a )?(relay|proxy|message)\b",
]

# Dangerous capability signals in tool names/descriptions (excessive agency).
_DANGEROUS = [
    r"(?i)\b(exec|execute|eval|spawn|subprocess)\b",
    r"(?i)\b(shell|bash|sh|powershell|cmd)\b",
    r"(?i)\b(run[_-]?command|os[_-]?command)\b",
    r"(?i)\b(delete|remove|rm|drop|truncate|wipe)\b",
    r"(?i)\b(write[_-]?file|put[_-]?file|overwrite|chmod|chown)\b",
    r"(?i)\b(payment|transfer|charge|refund|wire|payout)\b",
    r"(?i)\b(sudo|root|privilege)\b",
]

# Unicode Tags block U+E0000–U+E007F + common zero-width / bidi chars.
# Zero-width: U+200B-U+200F, Bidi overrides: U+202A-U+202E,
# Bidi isolates: U+2066-U+2069, BOM/ZWNBSP: U+FEFF
_HIDDEN_RE = re.compile(
    "["
    "\U000E0000-\U000E007F"  # Unicode Tags block
    "​-‏"          # zero-width space, ZWNJ, ZWJ, LRM, RLM
    "‪-‮"          # LRE, RLE, PDF, LRO, RLO (bidi overrides)
    "⁦-⁩"          # LRI, RLI, FSI, PDI (bidi isolates)
    "﻿"                 # BOM / zero-width no-break space
    "]"
)

# Sensitive resource hints.
_SENSITIVE_URI = re.compile(
    r"(?i)(\.env\b|/etc/|id_rsa|\.pem\b|secret|credential|token|password|/\.ssh/|/\.aws/)"
)

# Tool-shadowing patterns: duplicates and privileged names.
_PRIVILEGED_NAMES = {"exec", "shell", "eval", "sudo", "admin", "delete", "rm",
                     "read_file", "write_file", "run_command", "system"}

# Tool-poisoning v2: instruction-override phrasing.
_POISON_PHRASES = [
    r"ignore (?:all |the )?previous", r"do not tell", r"don'?t tell the user",
    r"without (?:asking|confirmation)",
    r"hidden instruction", r"system override", r"disregard (?:the )?(?:above|prior)",
]

# Rug-pull: embedded directive phrasing.
_RUGPULL_PHRASES = [r"embedded directive", r"hidden (?:instruction|directive)",
                    r"do not reveal", r"secretly", r"when no one is watching"]

# ---------------------------------------------------------------------------
# Toxic-flow bucket patterns (moved from agent_probe — single source of truth)
# ---------------------------------------------------------------------------

# Bucket A: untrusted-input / content ingestion
_BUCKET_A = [
    r"\bfetch\b", r"\bhttp\b", r"\burl\b", r"\bbrowse\b", r"\bsearch\b",
    r"\bretrieve\b", r"\buntrusted\b", r"\bweb\b", r"\bissue\b",
    r"\bcomment\b", r"\bread.{0,10}email\b", r"\bingest\b",
]

# Bucket B: private-data access
_BUCKET_B = [
    r"\bprivate\b", r"\bsecret\b", r"\binternal\b", r"\brepo\b",
    r"\bdatabase\b", r"\bfile.{0,5}read\b", r"\bread.{0,5}file\b",
    r"\bcredential\b", r"\bpassword\b", r"\btoken\b",
]

# Bucket C: exfiltration / egress
_BUCKET_C = [
    r"\bsend\b", r"\bpost\b", r"\bemail\b", r"\bwebhook\b",
    r"\bupload\b", r"\bexternal\b", r"\bcreate.{0,10}(pr|issue)\b",
    r"\bpublish\b", r"\begress\b", r"\bexport\b", r"\bwrite.{0,10}external\b",
]


def _tool_matches_bucket(tool: McpTool, patterns: list[str]) -> bool:
    text = f"{tool.name} {tool.description}"
    return any(re.search(p, text, re.IGNORECASE) for p in patterns)


def lethal_trifecta_present(tools: list[McpTool]) -> bool:
    """Return True iff the tool set contains at least one tool in each of the
    three toxic-flow buckets: (A) untrusted-input, (B) private-data, (C) egress.
    """
    has_a = any(_tool_matches_bucket(t, _BUCKET_A) for t in tools)
    has_b = any(_tool_matches_bucket(t, _BUCKET_B) for t in tools)
    has_c = any(_tool_matches_bucket(t, _BUCKET_C) for t in tools)
    return has_a and has_b and has_c


def _texts_of_tool(t) -> str:
    return f"{t.name}\n{t.description}\n{json.dumps(t.input_schema, sort_keys=True)}"


def analyze_tool_poisoning(mf: McpManifest) -> list[Finding]:
    out: list[Finding] = []
    for t in mf.tools:
        hits = [p for p in _POISON_PATTERNS if re.search(p, t.description or "")]
        if hits:
            out.append(Finding(
                title=f"Tool-description poisoning in MCP tool '{t.name}'",
                severity=Severity.HIGH,
                category="mcp_tool_poisoning",
                owasp_category="LLM01",
                description=(
                    f"The MCP tool '{t.name}' carries imperative/override instructions in "
                    f"its description, which is injected into the model's context during "
                    f"tools/list — before any tool is invoked (line jumping). Matched: "
                    f"{', '.join(hits)}."
                ),
                remediation=(
                    "Reject or sanitize tool descriptions containing model-directed "
                    "instructions; treat MCP tool metadata as untrusted input."
                ),
                endpoint=mf.endpoint,
                parameter=t.name,
                cwe_id="CWE-94",
                references=["https://blog.trailofbits.com/2025/04/21/jumping-the-line-how-mcp-servers-can-attack-you-before-you-ever-use-them/"],
                evidence=[Evidence(request_method="MCP", request_url=mf.endpoint,
                                   description=f"tools/list description: {t.description[:500]}")],
                metadata={"technique": "mcp:line-jumping", "tool": t.name},
            ))
    return out


def analyze_hidden_content(mf: McpManifest) -> list[Finding]:
    out: list[Finding] = []

    def scan(label: str, name: str, text: str):
        if text and _HIDDEN_RE.search(text):
            cps = sorted({f"U+{ord(c):04X}" for c in text if _HIDDEN_RE.match(c)})
            out.append(Finding(
                title=f"Hidden/invisible characters in MCP {label} '{name}'",
                severity=Severity.HIGH,
                category="mcp_hidden_content",
                owasp_category="LLM01",
                description=(
                    f"The MCP {label} '{name}' contains non-printing characters "
                    f"({', '.join(cps)}) that render invisibly in UIs but are interpreted "
                    f"by the model — a smuggled prompt-injection vector."
                ),
                remediation=(
                    "Strip Unicode Tags (U+E0000–U+E007F) and zero-width/bidi characters "
                    "from MCP metadata before it reaches the model."
                ),
                endpoint=mf.endpoint,
                parameter=name,
                cwe_id="CWE-176",
                references=["https://embracethered.com/blog/posts/2024/hiding-and-finding-text-with-unicode-tags/"],
                metadata={"technique": "mcp:unicode-tag-smuggling", "codepoints": cps},
            ))

    for t in mf.tools:
        scan("tool", t.name, f"{t.name} {t.description}")
    for r in mf.resources:
        scan("resource", r.name or r.uri, f"{r.name} {r.description}")
    for p in mf.prompts:
        scan("prompt", p.name, f"{p.name} {p.description}")
    return out


def analyze_excessive_agency(mf: McpManifest) -> list[Finding]:
    out: list[Finding] = []
    for t in mf.tools:
        blob = _texts_of_tool(t)
        hits = [p for p in _DANGEROUS if re.search(p, blob)]
        if hits:
            out.append(Finding(
                title=f"Excessive-agency / dangerous capability in MCP tool '{t.name}'",
                severity=Severity.MEDIUM,
                category="mcp_excessive_agency",
                owasp_category="LLM06",
                description=(
                    f"The MCP tool '{t.name}' exposes a high-impact capability "
                    f"(exec/file-write/delete/payment/privilege) that an injected or "
                    f"confused agent could abuse. Matched: {', '.join(hits)}."
                ),
                remediation=(
                    "Scope the tool to least privilege, require explicit human approval "
                    "for destructive actions, and constrain its input schema."
                ),
                endpoint=mf.endpoint,
                parameter=t.name,
                cwe_id="CWE-250",
                metadata={"technique": "mcp:excessive-agency", "tool": t.name},
            ))
    return out


def analyze_schema_weakness(mf: McpManifest) -> list[Finding]:
    out: list[Finding] = []
    for t in mf.tools:
        s = t.input_schema or {}
        weak = bool(s.get("additionalProperties") is True)
        props = s.get("properties") or {}
        # free-form string params with no constraints
        loose = [k for k, v in props.items()
                 if isinstance(v, dict) and v.get("type") == "string"
                 and not any(c in v for c in ("enum", "pattern", "maxLength", "format"))]
        if weak or loose:
            out.append(Finding(
                title=f"Weak input schema on MCP tool '{t.name}'",
                severity=Severity.LOW,
                category="mcp_schema_weakness",
                owasp_category="LLM06",
                description=(
                    f"Tool '{t.name}' accepts unconstrained input"
                    + (" (additionalProperties: true)" if weak else "")
                    + (f"; unconstrained string params: {', '.join(loose)}" if loose else "")
                    + " — widening the injection / abuse surface."
                ),
                remediation=(
                    "Constrain parameters with enum/pattern/maxLength and set "
                    "additionalProperties:false."
                ),
                endpoint=mf.endpoint,
                parameter=t.name,
                cwe_id="CWE-20",
                metadata={"technique": "mcp:weak-schema", "tool": t.name},
            ))
    return out


def analyze_sensitive_resources(mf: McpManifest) -> list[Finding]:
    out: list[Finding] = []
    for r in mf.resources:
        blob = f"{r.uri} {r.name} {r.description}"
        if _SENSITIVE_URI.search(blob):
            out.append(Finding(
                title=f"MCP server exposes sensitive resource '{r.name or r.uri}'",
                severity=Severity.HIGH,
                category="mcp_sensitive_resource",
                owasp_category="LLM02",
                description=(
                    f"The MCP server advertises a resource that appears to expose "
                    f"secrets / credentials / sensitive files: {r.uri}"
                ),
                remediation=(
                    "Remove sensitive files from the server's advertised resources or "
                    "gate them behind explicit authorization."
                ),
                endpoint=mf.endpoint,
                parameter=r.uri,
                cwe_id="CWE-200",
                metadata={"technique": "mcp:sensitive-resource", "uri": r.uri},
            ))
    return out


def analyze_prompt_poisoning(mf: McpManifest) -> list[Finding]:
    out: list[Finding] = []
    for p in mf.prompts:
        hits = [pat for pat in _POISON_PATTERNS if re.search(pat, p.description or "")]
        if hits:
            out.append(Finding(
                title=f"Prompt-template poisoning in MCP prompt '{p.name}'",
                severity=Severity.HIGH,
                category="mcp_prompt_poisoning",
                owasp_category="LLM01",
                description=(
                    f"The MCP prompt template '{p.name}' carries injected/override "
                    f"instructions. Matched: {', '.join(hits)}."
                ),
                remediation=(
                    "Treat server-supplied prompt templates as untrusted; sanitize "
                    "before use."
                ),
                endpoint=mf.endpoint,
                parameter=p.name,
                cwe_id="CWE-94",
                metadata={"technique": "mcp:prompt-poisoning", "prompt": p.name},
            ))
    return out


def analyze_tool_shadowing(mf: McpManifest) -> list[Finding]:
    out: list[Finding] = []
    seen: dict[str, int] = {}
    for t in mf.tools:
        nm = (getattr(t, "name", "") or "").strip()
        if not nm:
            continue
        seen[nm.lower()] = seen.get(nm.lower(), 0) + 1
    for t in mf.tools:
        nm = (getattr(t, "name", "") or "").strip()
        low = nm.lower()
        dup = seen.get(low, 0) > 1
        priv = low in _PRIVILEGED_NAMES
        if dup or priv:
            out.append(Finding(
                title=f"MCP tool name shadowing: '{nm}'",
                severity=Severity.HIGH if dup else Severity.MEDIUM,
                category="mcp_tool_shadowing", owasp_category="LLM06",
                description=(f"Tool '{nm}' "
                            + ("collides with another tool of the same name (shadowing/ambiguity). "
                               if dup else "")
                            + ("shadows a common privileged/builtin name, inviting confused-deputy misuse. "
                               if priv else "")),
                remediation="Use unique, namespaced tool names; avoid privileged builtin names.",
                endpoint=mf.endpoint, parameter=nm, cwe_id="CWE-706",
                metadata={"technique": "mcp:tool-shadowing", "tool": nm},
            ))
    # de-dup duplicate-name findings to one per name
    by_name: dict[str, Finding] = {}
    for f in out:
        by_name.setdefault(f.parameter, f)
    return list(by_name.values())


def _desc_matches(desc: str, patterns: list[str]) -> bool:
    d = (desc or "").lower()
    return any(re.search(p, d) for p in patterns)


def analyze_tool_poisoning_v2(mf: McpManifest) -> list[Finding]:
    out: list[Finding] = []
    for t in mf.tools:
        if _desc_matches(getattr(t, "description", "") or "", _POISON_PHRASES):
            nm = getattr(t, "name", "") or ""
            out.append(Finding(
                title=f"Tool-poisoning phrasing in MCP tool '{nm}'",
                severity=Severity.HIGH, category="mcp_tool_poisoning", owasp_category="LLM01",
                description=(f"Tool '{nm}' description contains instruction-override / "
                             "concealment phrasing that can hijack the calling model "
                             "(tool-poisoning / indirect prompt injection)."),
                remediation="Tool descriptions must be declarative metadata only — no imperative "
                            "instructions to the model. Treat tool descriptions as untrusted.",
                endpoint=mf.endpoint, parameter=nm, cwe_id="CWE-77",
                metadata={"technique": "mcp:tool-poisoning", "tool": nm},
            ))
    return out


def analyze_rug_pull(mf: McpManifest) -> list[Finding]:
    out: list[Finding] = []
    for t in mf.tools:
        if _desc_matches(getattr(t, "description", "") or "", _RUGPULL_PHRASES):
            nm = getattr(t, "name", "") or ""
            out.append(Finding(
                title=f"Rug-pull risk: unpinned instruction content in tool '{nm}'",
                severity=Severity.MEDIUM, category="mcp_rug_pull", owasp_category="LLM03",
                description=(f"Tool '{nm}' carries mutable instruction-like description content. "
                             "An MCP server can silently change tool descriptions after approval "
                             "(rug-pull); pin/verify the tool manifest hash across runs."),
                remediation="Pin and re-verify the tool manifest (baseline hash) on every connect; "
                            "alert on description drift.",
                endpoint=mf.endpoint, parameter=nm, cwe_id="CWE-494",
                metadata={"technique": "mcp:rug-pull", "tool": nm},
            ))
    return out


def analyze_toxic_flow(mf: McpManifest) -> list[Finding]:
    if not (mf.tools and lethal_trifecta_present(mf.tools)):
        return []
    return [Finding(
        title="MCP Toxic-Flow: Confused Deputy / Data Exfiltration Risk",
        severity=Severity.HIGH, category="mcp_toxic_flow", owasp_category="LLM06",
        description=("The tool set combines untrusted-input ingestion, private-data access, and an "
                     "egress capability — the three-bucket precondition for a confused-deputy / "
                     "data-exfiltration attack (MCP toxic-flow)."),
        remediation=("Apply least-privilege: don't expose untrusted-input, private-data, and egress "
                     "tools in one session; gate egress tools behind consent."),
        endpoint=mf.endpoint, cwe_id="CWE-441",
        metadata={"technique": "mcp:toxic-flow"},
    )]


_SECRET_PATTERNS = [
    (r"AKIA[0-9A-Z]{16}", "AWS access key"),
    (r"sk-[A-Za-z0-9]{20,}", "OpenAI-style API key"),
    (r"-----BEGIN [A-Z ]*PRIVATE KEY-----", "private key"),
    (r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", "JWT"),
    (r"(?i)(api[_-]?key|secret|password|token)\s*[:=]\s*['\"][^'\"]{8,}", "inline credential"),
]

_BROAD_SCOPE = [r"any file", r"filesystem.{0,12}root",
                r"\ball files\b.{0,20}\b(read|write|access|delete|modify)\b", r"wildcard",
                r"\ball\b.*\b(access|scope|permission)", r"unrestricted"]


def _scan_secrets(text: str) -> str | None:
    for pat, label in _SECRET_PATTERNS:
        if re.search(pat, text or ""):
            return label
    return None


def analyze_secrets_exposure(mf: McpManifest) -> list[Finding]:
    out: list[Finding] = []
    blobs: list[tuple[str, str]] = []
    for r in mf.resources:
        blobs.append((f"resource '{getattr(r, 'name', '') or r.uri}'",
                      f"{getattr(r, 'description', '') or ''} {getattr(r, 'uri', '') or ''}"))
    for t in mf.tools:
        blobs.append((f"tool '{t.name}' schema", json.dumps(getattr(t, "input_schema", {}) or {})))
    for where, text in blobs:
        label = _scan_secrets(text)
        if label:
            out.append(Finding(
                title=f"Secret exposed in MCP {where}",
                severity=Severity.HIGH, category="mcp_secrets_exposure", owasp_category="LLM02",
                description=f"A {label} appears in {where}. Secrets in the tool/resource surface leak "
                            "to the calling model and any client that enumerates the server.",
                remediation="Remove secrets from descriptions/resources/schemas; resolve credentials "
                            "server-side from a secret store, never in the MCP surface.",
                endpoint=mf.endpoint, cwe_id="CWE-200",
                metadata={"technique": "mcp:secrets-exposure", "where": where},
            ))
    return out


def analyze_over_broad_scope(mf: McpManifest) -> list[Finding]:
    out: list[Finding] = []
    for t in mf.tools:
        text = f"{getattr(t, 'name', '')} {getattr(t, 'description', '') or ''}".lower()
        if any(re.search(p, text) for p in _BROAD_SCOPE):
            out.append(Finding(
                title=f"Over-broad capability on MCP tool '{t.name}'",
                severity=Severity.MEDIUM, category="mcp_over_broad_scope", owasp_category="LLM06",
                description=f"Tool '{t.name}' declares broad/unconstrained access (filesystem root / "
                            "wildcard / all). Over-broad tool scope amplifies confused-deputy impact.",
                remediation="Scope tools to the narrowest path/resource set; avoid wildcard/root access.",
                endpoint=mf.endpoint, parameter=t.name, cwe_id="CWE-269",
                metadata={"technique": "mcp:over-broad-scope", "tool": t.name},
            ))
    return out


def baseline_hash(mf: McpManifest) -> str:
    """Stable, order-independent hash of tool descriptions + schemas, for
    rug-pull drift detection via compare_scans (Plan 3+). JSON serialization
    is collision-proof against attacker-controlled separators in tool fields."""
    items = sorted(
        json.dumps([t.name, t.description, t.input_schema], sort_keys=True)
        for t in mf.tools
    )
    return hashlib.sha256(json.dumps(items).encode("utf-8")).hexdigest()


def run_all_static(mf: McpManifest) -> list[Finding]:
    out: list[Finding] = []
    for fn in (
        analyze_tool_poisoning,
        analyze_hidden_content,
        analyze_excessive_agency,
        analyze_schema_weakness,
        analyze_sensitive_resources,
        analyze_prompt_poisoning,
        analyze_tool_shadowing,
        analyze_tool_poisoning_v2,
        analyze_rug_pull,
        analyze_toxic_flow,
        analyze_secrets_exposure,
        analyze_over_broad_scope,
    ):
        try:
            out.extend(fn(mf))
        except Exception:  # noqa: BLE001 — one analyzer must never abort the static pass
            logging.getLogger(__name__).exception("static analyzer %s raised", fn.__name__)
    return out
