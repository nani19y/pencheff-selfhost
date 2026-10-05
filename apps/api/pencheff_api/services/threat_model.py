"""Engagement-scoped STRIDE / DREAD threat model.

Deterministic — no LLM. The matrix is the same one used by the
``pencheff threatmodel`` CLI; we keep an API-side copy here rather
than importing from the plugin so the FastAPI service does not depend
on the MCP plugin package.

Output shape (stable contract — read by the web UI, the report
generator, and the scan dispatcher's adaptive-profile logic):

    {
      "method": "STRIDE" | "DREAD",
      "generated_at": "<iso-8601>",
      "method_summary": "<short human-friendly explanation>",
      "assets": [{"name": "...", "type": "webapp"}],
      "table": [{                              # STRIDE only
        "asset": "...",
        "category": "Spoofing",
        "threats": ["Stolen session cookie", ...],
        "mitigations": ["MFA", "Mutual TLS", ...]
      }, ...],
      "threats": [{                            # DREAD only
        "asset": "...",
        "category": "Tampering",
        "threat": "Mass assignment",
        "damage": 7, "reproducibility": 8, "exploitability": 7,
        "affected_users": 6, "discoverability": 7,
        "score": 7.0, "priority": "high",
        "mitigations": [...]
      }, ...],
      "category_scores": {"Tampering": 7.4, ...}  # DREAD only
    }
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Iterable

# ─── Matrix (mirrors plugins/pencheff/pencheff/data/stride_dread.json) ───

STRIDE_MATRIX: dict[str, dict[str, list[str]]] = {
    "webapp": {
        "Spoofing": [
            "Stolen session cookie", "Forged JWT", "Open OAuth redirect", "Phishing for SSO",
        ],
        "Tampering": [
            "Mass assignment", "Parameter pollution", "Cache poisoning", "Request smuggling",
        ],
        "Repudiation": [
            "Missing audit log", "Log tampering", "No request correlation IDs",
        ],
        "Information Disclosure": [
            "Verbose errors", "Directory listing", "Backup files exposed", "Source map leaks",
        ],
        "Denial of Service": [
            "Algorithmic complexity", "ReDoS", "Resource exhaustion", "Slowloris",
        ],
        "Elevation of Privilege": [
            "Broken access control", "IDOR", "JWT alg=none",
            "Privilege escalation via mass-assignment",
        ],
    },
    "api": {
        "Spoofing": ["API key in URL", "Unsigned webhooks", "Replay attacks"],
        "Tampering": ["GraphQL field-level abuse", "Mass assignment", "JSON Patch RCE"],
        "Repudiation": ["No mTLS", "Missing rate-limit logs"],
        "Information Disclosure": ["Verbose errors", "Excessive data exposure", "BOLA / IDOR"],
        "Denial of Service": ["Unbounded queries", "GraphQL N+1 / depth attacks"],
        "Elevation of Privilege": [
            "Missing auth on admin endpoints", "Function-level authz bypass",
        ],
    },
    "network": {
        "Spoofing": ["ARP spoofing", "DHCP starvation", "DNS poisoning"],
        "Tampering": ["VLAN hopping", "Routing manipulation"],
        "Repudiation": ["Unlogged firewall denies"],
        "Information Disclosure": [
            "Plaintext protocols (FTP/Telnet)", "SNMP public string",
        ],
        "Denial of Service": ["TCP RST flood", "ICMP flood"],
        "Elevation of Privilege": [
            "Network segmentation bypass",
            "Pivoting through misconfigured router",
        ],
    },
    "cloud": {
        "Spoofing": ["IAM role assumption abuse", "Cross-account confused deputy"],
        "Tampering": ["S3 bucket policy modification", "IaC drift"],
        "Repudiation": ["CloudTrail disabled / suppressed"],
        "Information Disclosure": [
            "Public S3 bucket", "EC2 metadata SSRF", "Snapshot exposure",
        ],
        "Denial of Service": ["Resource exhaustion via cloud quotas"],
        "Elevation of Privilege": [
            "IAM privilege escalation paths (PassRole, AssumeRole, iam:CreateAccessKey)",
        ],
    },
    "mobile": {
        "Spoofing": ["Insecure deep-link handler", "WebView ↔ JS bridge abuse"],
        "Tampering": ["Backup contains secrets", "Insecure WebView", "Tapjacking"],
        "Repudiation": ["No client integrity check"],
        "Information Disclosure": [
            "Hard-coded secrets in APK", "Cleartext logs", "Leaky clipboard",
        ],
        "Denial of Service": ["Battery-drain abuse"],
        "Elevation of Privilege": [
            "Exported activity / service / receiver abuse",
            "Jailbreak/root detection bypass",
        ],
    },
}

# Default DREAD scores per STRIDE category, calibrated to the kinds of
# bugs we routinely see in pentests. Operator-specific edits land on top
# of these (PUT /engagements/{id}/threat-model).
DEFAULT_DREAD: dict[str, dict[str, int]] = {
    "Spoofing":               {"d": 7, "r": 6, "e": 6, "a": 7, "y": 5},
    "Tampering":              {"d": 7, "r": 7, "e": 6, "a": 6, "y": 6},
    "Repudiation":            {"d": 4, "r": 6, "e": 5, "a": 5, "y": 5},
    "Information Disclosure": {"d": 6, "r": 8, "e": 7, "a": 7, "y": 8},
    "Denial of Service":      {"d": 5, "r": 6, "e": 5, "a": 8, "y": 6},
    "Elevation of Privilege": {"d": 9, "r": 6, "e": 6, "a": 7, "y": 5},
}

DEFAULT_MITIGATIONS: dict[str, list[str]] = {
    "Spoofing": ["Strong authentication (MFA)", "Mutual TLS", "Signed tokens (JWT, SAML)"],
    "Tampering": ["Input validation", "Integrity checks (HMAC)", "WAF + content security policy"],
    "Repudiation": ["Audit logging", "Non-repudiation signatures", "Tamper-evident logs"],
    "Information Disclosure": ["TLS everywhere", "Field-level encryption", "Output filtering"],
    "Denial of Service": ["Rate limiting", "Autoscaling", "WAF circuit breakers"],
    "Elevation of Privilege": [
        "Least-privilege RBAC", "Privilege boundaries", "Authorization checks per request",
    ],
}


# ─── Public generator ───────────────────────────────────────────────────


def generate_threat_model(
    *,
    target_url: str | None,
    asset_types: Iterable[str] | None = None,
    method: str = "stride",
    asset_names: Iterable[str] | None = None,
) -> dict[str, Any]:
    """Build a complete threat model.

    Caller hands us either an explicit list of ``asset_types``, a
    ``target_url`` we infer from, or both. If nothing is supplied we
    fall back to a single ``webapp`` asset.

    The output is JSON-serialisable and persisted verbatim on
    ``Engagement.threat_model``.
    """
    method_norm = (method or "stride").lower()
    assets = _build_assets(target_url, asset_types, asset_names)
    base = {
        "method": "DREAD" if method_norm == "dread" else "STRIDE",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "method_summary": _method_summary(method_norm),
        "assets": assets,
    }
    if method_norm == "dread":
        threats: list[dict[str, Any]] = []
        cat_totals: dict[str, list[float]] = {}
        for asset in assets:
            for row in _stride_for_asset(asset):
                category = row["category"]
                d = DEFAULT_DREAD.get(category, {"d": 5, "r": 5, "e": 5, "a": 5, "y": 5})
                for thr in row["threats"]:
                    score = _dread_score(d)
                    threats.append({
                        "asset": asset["name"],
                        "category": category,
                        "threat": thr,
                        "damage": d["d"],
                        "reproducibility": d["r"],
                        "exploitability": d["e"],
                        "affected_users": d["a"],
                        "discoverability": d["y"],
                        "score": score,
                        "priority": _priority(score),
                        "mitigations": list(DEFAULT_MITIGATIONS.get(category, [])),
                    })
                    cat_totals.setdefault(category, []).append(score)
        base["threats"] = threats
        base["category_scores"] = {
            cat: round(sum(s) / len(s), 2) for cat, s in cat_totals.items()
        }
        return base

    base["table"] = [
        row for asset in assets for row in _stride_for_asset(asset)
    ]
    return base


# ─── Adaptive-scan input ────────────────────────────────────────────────


# Maps STRIDE categories to the scan modules that test for them. When a
# threat model is attached to an engagement, the scan dispatcher uses
# this table to push high-DREAD categories' modules to the front of the
# run order so the highest-impact tests fire first.
CATEGORY_MODULE_BIAS: dict[str, list[str]] = {
    "Spoofing": ["scan_auth", "scan_oauth", "scan_mfa_bypass"],
    "Tampering": ["scan_injection", "scan_client_side", "scan_api"],
    "Repudiation": ["scan_authz", "scan_infrastructure"],
    "Information Disclosure": [
        "scan_infrastructure", "scan_api", "scan_advanced", "scan_subdomain_takeover",
    ],
    "Denial of Service": ["scan_advanced", "scan_infrastructure"],
    "Elevation of Privilege": ["scan_authz", "scan_oauth", "scan_business_logic"],
}


def module_priority_bias(threat_model: dict[str, Any] | None) -> list[str]:
    """Return scan modules in the order the threat model says are most
    important. Modules tied to higher-scoring categories come first.

    Always returns a *bias list*, not the full module set — callers
    intersect this with their existing profile module list and reorder
    rather than replace, so a missing module never drops the scan.
    Empty list means "no bias info" (caller should leave its order alone).
    """
    if not threat_model:
        return []

    method = (threat_model.get("method") or "STRIDE").upper()
    if method == "DREAD":
        scores = threat_model.get("category_scores") or {}
    else:
        # STRIDE has no per-category score — use DEFAULT_DREAD as the
        # tie-breaker so a STRIDE-only model still produces a useful bias.
        scores = {
            cat: _dread_score(d) for cat, d in DEFAULT_DREAD.items()
        }

    ranked_categories = sorted(
        scores.keys(), key=lambda c: scores.get(c, 0.0), reverse=True
    )
    out: list[str] = []
    seen: set[str] = set()
    for category in ranked_categories:
        for module in CATEGORY_MODULE_BIAS.get(category, []):
            if module not in seen:
                out.append(module)
                seen.add(module)
    return out


# ─── Internals ──────────────────────────────────────────────────────────


def _build_assets(
    target_url: str | None,
    asset_types: Iterable[str] | None,
    asset_names: Iterable[str] | None,
) -> list[dict[str, str]]:
    types = [t.lower() for t in (asset_types or []) if t]
    names = [n for n in (asset_names or []) if n]

    if names:
        out = [
            {"name": n, "type": (types[i] if i < len(types) else "webapp")}
            for i, n in enumerate(names)
        ]
        return out

    primary = target_url or "target"
    if not types:
        types = [_infer_asset_type(target_url)]
    return [{"name": primary, "type": t} for t in types]


def _infer_asset_type(target_url: str | None) -> str:
    if not target_url:
        return "webapp"
    lowered = target_url.lower()
    if any(x in lowered for x in ("/api", "graphql", "swagger", "openapi")):
        return "api"
    if any(x in lowered for x in (".s3.", ".amazonaws.com", "cloudfront", "blob.core.windows", "googleapis.com")):
        return "cloud"
    return "webapp"


def _stride_for_asset(asset: dict[str, Any]) -> list[dict[str, Any]]:
    matrix = STRIDE_MATRIX.get(asset["type"], STRIDE_MATRIX["webapp"])
    return [
        {
            "asset": asset["name"],
            "category": category,
            "threats": list(threats),
            "mitigations": list(DEFAULT_MITIGATIONS.get(category, [])),
        }
        for category, threats in matrix.items()
    ]


def _dread_score(d: dict[str, int]) -> float:
    return round(
        (d["d"] + d["r"] + d["e"] + d["a"] + d["y"]) / 5.0, 2
    )


def _priority(score: float) -> str:
    if score >= 8:
        return "critical"
    if score >= 6:
        return "high"
    if score >= 4:
        return "medium"
    return "low"


def _method_summary(method: str) -> str:
    if method == "dread":
        return (
            "DREAD: each threat scored on Damage, Reproducibility, "
            "Exploitability, Affected users, Discoverability (1–10). "
            "Average is the priority score."
        )
    return (
        "STRIDE: threats grouped by category (Spoofing, Tampering, "
        "Repudiation, Information Disclosure, Denial of Service, "
        "Elevation of Privilege) per asset."
    )


# ─── Markdown rendering for the report + UI ─────────────────────────────


def render_markdown(model: dict[str, Any]) -> str:
    """Project a threat model dict to a human-friendly Markdown blob.

    Used by:
      * The DOCX / HTML report generator (rendered inline as a section).
      * The web-app fallback (when JS is disabled or the dashboard wants
        a copy-pasteable summary).

    Stays JSON-shape-tolerant — partial models (e.g. ``method`` only)
    render cleanly without raising.
    """
    if not model:
        return ""
    method = (model.get("method") or "STRIDE").upper()
    lines: list[str] = [f"# {method} Threat Model"]
    if model.get("generated_at"):
        lines.append("")
        lines.append(f"_Generated {model['generated_at']}_")
    if model.get("method_summary"):
        lines.append("")
        lines.append(model["method_summary"])

    assets = model.get("assets") or []
    if assets:
        lines.append("")
        lines.append("## Assets")
        for a in assets:
            lines.append(f"- **{a.get('name', '?')}** ({a.get('type', 'webapp')})")

    if method == "DREAD":
        threats = model.get("threats") or []
        if threats:
            lines.append("")
            lines.append("## Top threats")
            lines.append("")
            lines.append("| Asset | Category | Threat | Score | Priority |")
            lines.append("| --- | --- | --- | --- | --- |")
            ranked = sorted(threats, key=lambda t: t.get("score", 0), reverse=True)[:25]
            for t in ranked:
                lines.append(
                    f"| {t.get('asset', '?')} | {t.get('category', '?')} | "
                    f"{t.get('threat', '?')} | {t.get('score', '?')} | "
                    f"{t.get('priority', '?')} |"
                )
        category_scores = model.get("category_scores") or {}
        if category_scores:
            lines.append("")
            lines.append("## Category scores")
            lines.append("")
            for cat, score in sorted(category_scores.items(), key=lambda kv: kv[1], reverse=True):
                lines.append(f"- **{cat}** — {score}")
    else:
        table = model.get("table") or []
        if table:
            lines.append("")
            lines.append("## STRIDE table")
            lines.append("")
            lines.append("| Asset | Category | Threats | Mitigations |")
            lines.append("| --- | --- | --- | --- |")
            for row in table:
                threats = ", ".join(row.get("threats") or [])
                mit = ", ".join(row.get("mitigations") or [])
                lines.append(
                    f"| {row.get('asset', '?')} | {row.get('category', '?')} | "
                    f"{threats} | {mit} |"
                )
    return "\n".join(lines).rstrip() + "\n"
