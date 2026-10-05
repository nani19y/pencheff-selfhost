"""Per-scan compliance rollup across URL / Repo / LLM targets.

Deterministic — no LLM. The control maps live in
``plugins/pencheff/pencheff/config.py`` (mirrored here so the FastAPI
service does not depend on the MCP plugin package). Every Finding /
RepoFinding produced by a scan is fanned out across the requested
frameworks; the service returns a stable shape consumed by:

* ``GET /scans/{id}/compliance`` (URL + LLM scans)
* ``GET /repos/scans/{id}/compliance`` (repo scans)
* the web UI at ``/scans/[id]/compliance`` and
  ``/repos/scans/[id]/compliance``
* the DOCX / Markdown report generators (compliance appendix)

Output shape (stable contract):

    {
      "scan_id": "...",
      "target_kind": "url" | "repo" | "llm",
      "frameworks": ["OWASP Top 10", "PCI-DSS", "NIST 800-53",
                     "SOC 2", "ISO 27001:2022", "HIPAA",
                     "OWASP LLM Top 10", "MITRE ATLAS",
                     "NIST AI RMF", "EU AI Act"],
      "totals": {"findings": 42, "controls_touched": 17},
      "frameworks_summary": {
        "OWASP Top 10": {
          "controls": [
            {"id": "A03: Injection",
             "control": "A03",
             "title": "Injection",
             "finding_count": 5,
             "severity_breakdown": {"critical": 1, "high": 3, "medium": 1, "low": 0, "info": 0},
             "finding_ids": ["...","..."]}
          ],
          "covered": 7, "total": 10
        },
        ...
      },
      "findings": [
        {"id": "...", "title": "SQL injection",
         "severity": "high", "category": "injection",
         "owasp_category": "A03",
         "compliance": {"OWASP Top 10": ["A03: Injection"],
                        "PCI-DSS": ["6.5.1"], ...}}
      ]
    }
"""

from __future__ import annotations

from typing import Iterable, Literal

# ─── Web / cloud / data control maps ────────────────────────────────────

OWASP_TOP_10 = {
    "A01": "Broken Access Control",
    "A02": "Cryptographic Failures",
    "A03": "Injection",
    "A04": "Insecure Design",
    "A05": "Security Misconfiguration",
    "A06": "Vulnerable and Outdated Components",
    "A07": "Identification and Authentication Failures",
    "A08": "Software and Data Integrity Failures",
    "A09": "Security Logging and Monitoring Failures",
    "A10": "Server-Side Request Forgery (SSRF)",
}

# Category → OWASP code (covers DAST + repo-scanner-derived categories).
CATEGORY_TO_OWASP = {
    "injection": "A03",
    "xss": "A03",
    "ssrf": "A10",
    "auth": "A07",
    "mfa_bypass": "A07",
    "oauth": "A07",
    "authz": "A01",
    "file_handling": "A01",
    "mass_assignment": "A01",
    "crypto": "A02",
    "secrets": "A02",
    "misconfiguration": "A05",
    "cloud": "A05",
    "iac": "A05",
    "components": "A06",
    "dependency": "A06",
    "deserialization": "A08",
    "smuggling": "A08",
    "logging": "A09",
    "logic": "A04",
    "open_redirect": "A01",
    "subdomain_takeover": "A01",
    # Phase 3.2 — runtime-traffic API discovery emits ``api_drift``
    # findings when the captured surface diverges from the declared
    # OpenAPI spec. Maps onto Insecure Design (A04) because the root
    # cause is almost always "the spec didn't capture this surface
    # at design time."
    "api_drift": "A04",
}

PCI_DSS_MAP = {
    "injection":          ["6.5.1"],
    "xss":                ["6.5.7"],
    "ssrf":               ["6.5.1"],
    "auth":               ["6.5.10", "8.1", "8.2"],
    "mfa_bypass":         ["8.3"],
    "oauth":              ["6.5.10"],
    "authz":              ["6.5.8", "7.1", "7.2"],
    "file_handling":      ["6.5.1", "6.5.8"],
    "mass_assignment":    ["6.5.1", "6.5.8"],
    "crypto":             ["4.1", "6.5.3"],
    "secrets":            ["3.4", "6.5.3", "8.2.1"],
    "misconfiguration":   ["2.2", "6.2"],
    "cloud":              ["2.2", "6.2"],
    "iac":                ["2.2", "6.2"],
    "components":         ["6.2"],
    "dependency":         ["6.2"],
    "deserialization":    ["6.5.1"],
    "smuggling":          ["6.5.10"],
    "open_redirect":      ["6.5.10"],
    "subdomain_takeover": ["6.5.8"],
    "logging":            ["10.2"],
    "logic":              ["6.5.10"],
}

NIST_MAP = {
    "injection":          ["SI-10", "SI-16"],
    "xss":                ["SI-10"],
    "ssrf":               ["SI-10", "SC-7"],
    "auth":               ["IA-2", "IA-5", "IA-8"],
    "mfa_bypass":         ["IA-2", "IA-11"],
    "oauth":              ["IA-2", "IA-8"],
    "authz":              ["AC-3", "AC-6"],
    "file_handling":      ["AC-3", "SI-10"],
    "mass_assignment":    ["AC-3", "AC-6"],
    "crypto":             ["SC-8", "SC-12", "SC-13"],
    "secrets":            ["IA-5", "SC-12", "SC-28"],
    "misconfiguration":   ["CM-6", "CM-7"],
    "cloud":              ["CM-6", "SC-7"],
    "iac":                ["CM-6", "CM-7"],
    "components":         ["SA-10", "SA-11", "SI-2"],
    "dependency":         ["SA-10", "SI-2"],
    "deserialization":    ["SI-10", "SI-16"],
    "smuggling":          ["SC-7", "SI-10"],
    "open_redirect":      ["SI-10"],
    "subdomain_takeover": ["CM-8", "SC-20"],
    "logging":            ["AU-2", "AU-3", "AU-6"],
    "logic":              ["SI-10"],
}

SOC2_MAP = {
    "injection":          ["CC6.1", "CC6.6"],
    "xss":                ["CC6.1", "CC6.6"],
    "ssrf":               ["CC6.1", "CC6.6"],
    "auth":               ["CC6.1", "CC6.2", "CC6.3"],
    "mfa_bypass":         ["CC6.1", "CC6.2"],
    "oauth":              ["CC6.1", "CC6.3"],
    "authz":              ["CC6.1", "CC6.3"],
    "file_handling":      ["CC6.1", "CC6.6"],
    "mass_assignment":    ["CC6.1", "CC6.3"],
    "crypto":             ["CC6.1", "CC6.7"],
    "secrets":            ["CC6.1", "CC6.7"],
    "misconfiguration":   ["CC6.1", "CC7.1"],
    "cloud":              ["CC6.1", "CC6.6", "A1.1"],
    "iac":                ["CC6.1", "CC7.1"],
    "components":         ["CC7.1", "CC8.1"],
    "dependency":         ["CC7.1", "CC8.1"],
    "deserialization":    ["CC6.1", "CC6.6"],
    "logging":            ["CC7.2", "CC7.3"],
}

ISO27001_MAP = {
    "injection":          ["A.8.24", "A.8.28"],
    "xss":                ["A.8.28"],
    "ssrf":               ["A.8.22", "A.8.28"],
    "auth":               ["A.5.15", "A.8.2", "A.5.16"],
    "mfa_bypass":         ["A.5.17", "A.8.2"],
    "oauth":              ["A.5.15", "A.8.2"],
    "authz":              ["A.5.15", "A.5.18"],
    "file_handling":      ["A.8.28", "A.8.22"],
    "mass_assignment":    ["A.5.18", "A.8.28"],
    "crypto":             ["A.8.24", "A.8.7"],
    "secrets":            ["A.8.24", "A.5.17"],
    "misconfiguration":   ["A.8.8", "A.8.9"],
    "cloud":              ["A.8.23", "A.5.19"],
    "iac":                ["A.8.8", "A.8.9"],
    "components":         ["A.8.8", "A.8.19"],
    "dependency":         ["A.8.8", "A.8.19"],
    "deserialization":    ["A.8.28"],
    "smuggling":          ["A.8.22", "A.8.28"],
    "open_redirect":      ["A.8.22"],
    "subdomain_takeover": ["A.8.22", "A.5.19"],
    "logging":            ["A.8.15", "A.8.16"],
}

HIPAA_MAP = {
    "injection":          ["164.312(a)(2)(iv)", "164.312(c)(1)"],
    "xss":                ["164.312(a)(2)(iv)", "164.312(c)(1)"],
    "ssrf":               ["164.312(c)(1)", "164.312(e)(1)"],
    "auth":               ["164.312(a)(2)(i)", "164.312(d)"],
    "mfa_bypass":         ["164.312(d)", "164.312(a)(2)(i)"],
    "authz":              ["164.312(a)(1)", "164.308(a)(4)"],
    "file_handling":      ["164.312(c)(1)", "164.312(a)(2)(iv)"],
    "mass_assignment":    ["164.312(a)(1)", "164.308(a)(4)"],
    "crypto":             ["164.312(a)(2)(iv)", "164.312(e)(2)(ii)"],
    "secrets":            ["164.312(a)(2)(iv)", "164.312(e)(2)(ii)"],
    "misconfiguration":   ["164.312(a)(1)", "164.308(a)(1)"],
    "cloud":              ["164.312(c)(1)", "164.308(a)(7)"],
    "iac":                ["164.312(a)(1)", "164.308(a)(1)"],
    "components":         ["164.308(a)(8)", "164.308(a)(1)(ii)(B)"],
    "dependency":         ["164.308(a)(8)", "164.308(a)(1)(ii)(B)"],
    "deserialization":    ["164.312(c)(1)", "164.312(a)(2)(iv)"],
    "logging":            ["164.312(b)", "164.308(a)(1)(ii)(D)"],
}

# ─── AI / LLM control maps ──────────────────────────────────────────────

OWASP_LLM_TOP_10 = {
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
}

MITRE_ATLAS_MAP = {
    "LLM01": ["AML.T0051", "AML.T0054"],
    "LLM02": ["AML.T0057", "AML.T0024"],
    "LLM03": ["AML.T0010", "AML.T0016"],
    "LLM04": ["AML.T0020", "AML.T0054"],
    "LLM05": ["AML.T0051", "AML.T0048"],
    "LLM06": ["AML.T0040", "AML.T0054"],
    "LLM07": ["AML.T0057", "AML.T0058"],
    "LLM08": ["AML.T0057", "AML.T0024"],
    "LLM09": ["AML.T0046", "AML.T0054"],
    "LLM10": ["AML.T0029", "AML.T0034"],
}

NIST_AI_RMF_MAP = {
    "LLM01": ["MAP 1.5", "MEASURE 2.7", "MANAGE 2.3"],
    "LLM02": ["MAP 2.3", "MEASURE 2.8", "MANAGE 4.1"],
    "LLM03": ["MAP 3.4", "MEASURE 2.5", "MANAGE 3.2"],
    "LLM04": ["MAP 4.1", "MEASURE 2.6", "MANAGE 2.4"],
    "LLM05": ["MEASURE 2.7", "MANAGE 2.3"],
    "LLM06": ["MAP 3.2", "MEASURE 2.8", "MANAGE 2.3"],
    "LLM07": ["MAP 2.3", "MEASURE 2.8", "MANAGE 4.1"],
    "LLM08": ["MAP 4.1", "MEASURE 2.6", "MANAGE 4.1"],
    "LLM09": ["MEASURE 2.9", "MANAGE 1.3"],
    "LLM10": ["MEASURE 2.12", "MANAGE 2.4"],
}

EU_AI_ACT_MAP = {
    "LLM01": ["Article 15", "Article 55"],
    "LLM02": ["Article 10", "Article 15", "Article 55"],
    "LLM03": ["Article 17", "Article 55"],
    "LLM04": ["Article 10", "Article 15"],
    "LLM05": ["Article 15", "Article 50"],
    "LLM06": ["Article 14", "Article 15"],
    "LLM07": ["Article 13", "Article 15", "Article 55"],
    "LLM08": ["Article 10", "Article 15"],
    "LLM09": ["Article 13", "Article 50"],
    "LLM10": ["Article 15"],
}

# GDPR (Regulation (EU) 2016/679) — see plugins/pencheff/.../config.py
# for the canonical definition. Mirrored here so the API service can
# render the LLM compliance rollup without a runtime dependency on the
# plugin package.
GDPR_LLM_MAP = {
    "LLM01": ["Art. 5(1)(f) Integrity and Confidentiality", "Art. 32 Security of Processing"],
    "LLM02": ["Art. 5(1)(a) Lawfulness, Fairness, Transparency", "Art. 5(1)(c) Data Minimisation", "Art. 9 Special Categories", "Art. 32 Security of Processing", "Art. 33 Breach Notification", "Art. 34 Communication of Breach"],
    "LLM03": ["Art. 28 Processor", "Art. 32 Security of Processing", "Art. 35 DPIA"],
    "LLM04": ["Art. 5(1)(d) Accuracy", "Art. 32 Security of Processing", "Art. 35 DPIA"],
    "LLM05": ["Art. 5(1)(f) Integrity and Confidentiality", "Art. 32 Security of Processing"],
    "LLM06": ["Art. 22 Automated Decision-Making", "Art. 25 Data Protection by Design", "Art. 32 Security of Processing"],
    "LLM07": ["Art. 5(1)(a) Lawfulness, Fairness, Transparency", "Art. 32 Security of Processing"],
    "LLM08": ["Art. 5(1)(c) Data Minimisation", "Art. 32 Security of Processing"],
    "LLM09": ["Art. 5(1)(d) Accuracy", "Art. 22 Automated Decision-Making"],
    "LLM10": ["Art. 32 Security of Processing"],
}

# ISO/IEC 42001:2023 Annex A controls — see plugins/pencheff/.../config.py
# for the canonical definition.
ISO_42001_LLM_MAP = {
    "LLM01": ["A.6.2.4 Verification and Validation", "A.6.2.6 Operation and Monitoring", "A.8.2 System Information for Users"],
    "LLM02": ["A.7.2 Data Quality for AI Systems", "A.7.5 Data Preparation", "A.6.2.6 Operation and Monitoring"],
    "LLM03": ["A.10.3 Supplier Relationships", "A.6.2.7 Technical Documentation"],
    "LLM04": ["A.7.3 Data Acquisition", "A.7.5 Data Preparation", "A.6.2.4 Verification and Validation"],
    "LLM05": ["A.6.2.4 Verification and Validation", "A.6.2.6 Operation and Monitoring", "A.8.4 Communication of Incidents"],
    "LLM06": ["A.6.2.5 Deployment", "A.9.2 Processes for Responsible Use", "A.10.2 Allocating Responsibilities"],
    "LLM07": ["A.6.2.7 Technical Documentation", "A.8.2 System Information for Users"],
    "LLM08": ["A.7.2 Data Quality for AI Systems", "A.6.2.4 Verification and Validation"],
    "LLM09": ["A.7.2 Data Quality for AI Systems", "A.6.2.4 Verification and Validation", "A.8.2 System Information for Users"],
    "LLM10": ["A.6.2.6 Operation and Monitoring", "A.6.2.8 Recording of Event Logs"],
}

# Repo-scanner output → category. RepoFinding rows do not carry a
# ``category`` column so we infer one from the scanner that produced
# the row; rule_id / package metadata refines the choice when present.
SCANNER_TO_CATEGORY = {
    "semgrep":   "injection",     # default — rule_id often refines (xss, crypto, …)
    "codeql":    "injection",
    "osv":       "components",
    "ghsa":      "components",
    "trivy":     "components",
    "trivy_iac": "iac",
    "checkov":   "iac",
    "gitleaks":  "secrets",
    "yara":      "components",    # malware signatures land in supply-chain bucket
    "detect-secrets": "secrets",
}

# Per-target-kind framework selection. URL / Repo / LLM each enable the
# subset that makes sense for the asset class — querystrings can ask for
# "all" to override.
URL_FRAMEWORKS  = ["owasp", "pci-dss", "nist", "soc2", "iso27001", "hipaa"]
REPO_FRAMEWORKS = ["owasp", "pci-dss", "nist", "soc2", "iso27001", "hipaa"]
LLM_FRAMEWORKS  = ["owasp-llm", "mitre-atlas", "nist-ai-rmf", "eu-ai-act", "gdpr-llm", "iso-42001"]

FRAMEWORK_LABELS = {
    "owasp":       "OWASP Top 10",
    "pci-dss":     "PCI-DSS",
    "nist":        "NIST 800-53",
    "soc2":        "SOC 2",
    "iso27001":    "ISO 27001:2022",
    "hipaa":       "HIPAA",
    "owasp-llm":   "OWASP LLM Top 10",
    "mitre-atlas": "MITRE ATLAS",
    "nist-ai-rmf": "NIST AI RMF",
    "eu-ai-act":   "EU AI Act",
    "gdpr-llm":    "GDPR (LLM)",
    "iso-42001":   "ISO/IEC 42001:2023",
}

_FRAMEWORK_MAPS = {
    "pci-dss":     PCI_DSS_MAP,
    "nist":        NIST_MAP,
    "soc2":        SOC2_MAP,
    "iso27001":    ISO27001_MAP,
    "hipaa":       HIPAA_MAP,
    "mitre-atlas": MITRE_ATLAS_MAP,
    "nist-ai-rmf": NIST_AI_RMF_MAP,
    "eu-ai-act":   EU_AI_ACT_MAP,
    "gdpr-llm":    GDPR_LLM_MAP,
    "iso-42001":   ISO_42001_LLM_MAP,
}


def _refine_repo_category(scanner: str, rule_id: str | None) -> str:
    """Best-effort scanner+rule_id → category refinement.

    ``RepoFinding`` does not carry a ``category`` column; the worker
    only writes the scanner that produced the row. For SAST scanners
    (semgrep, codeql) the rule id usually mentions the OWASP class
    (e.g. ``javascript.lang.security.audit.xss.…``) — we look for a few
    well-known tokens and fall back to the scanner default.
    """
    base = SCANNER_TO_CATEGORY.get(scanner.lower(), "misconfiguration")
    if not rule_id:
        return base
    rid = rule_id.lower()
    for token, cat in (
        ("xss", "xss"),
        ("sql", "injection"),
        ("injection", "injection"),
        ("ssrf", "ssrf"),
        ("crypto", "crypto"),
        ("secret", "secrets"),
        ("auth", "auth"),
        ("authz", "authz"),
        ("deserial", "deserialization"),
        ("smuggling", "smuggling"),
        ("open-redirect", "open_redirect"),
        ("redirect", "open_redirect"),
        ("path-trav", "file_handling"),
    ):
        if token in rid:
            return cat
    return base


def _llm_category_from_owasp(owasp_category: str | None) -> str | None:
    """Pluck ``LLM01..LLM10`` out of a Finding's ``owasp_category``.

    The LLM red-team writer stores the category as either
    ``"LLM01"`` or ``"LLM01: Prompt Injection"`` — both forms collapse
    to ``LLM01`` here.
    """
    if not owasp_category:
        return None
    head = owasp_category.split(":", 1)[0].strip().upper()
    return head if head in OWASP_LLM_TOP_10 else None


def _empty_severity_bucket() -> dict[str, int]:
    return {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}


def _bump_severity(bucket: dict[str, int], severity: str | None) -> None:
    sev = (severity or "info").lower()
    if sev not in bucket:
        sev = "info"
    bucket[sev] = bucket[sev] + 1


def _normalize_findings(
    target_kind: Literal["url", "repo", "llm"],
    rows: Iterable,
) -> list[dict]:
    """Collapse a Finding / RepoFinding row into a uniform dict.

    The contract emitted here is what the rest of the rollup consumes —
    every downstream caller sees the same shape regardless of which
    table the row came from.
    """
    out: list[dict] = []
    for r in rows:
        if target_kind == "repo":
            scanner = getattr(r, "scanner", "") or ""
            cat = _refine_repo_category(scanner, getattr(r, "rule_id", None))
            owasp = CATEGORY_TO_OWASP.get(cat)
            owasp_label = (
                f"{owasp}: {OWASP_TOP_10[owasp]}" if owasp in OWASP_TOP_10 else None
            )
            out.append({
                "id": r.id,
                "title": r.title,
                "severity": r.severity,
                "category": cat,
                "owasp_category": owasp_label,
                "scanner": scanner or None,
            })
        else:
            cat = (getattr(r, "category", None) or "misconfiguration").lower()
            owasp_raw = getattr(r, "owasp_category", None)
            out.append({
                "id": r.id,
                "title": r.title,
                "severity": r.severity,
                "category": cat,
                "owasp_category": owasp_raw,
                "scanner": None,
            })
    return out


def _frameworks_for_kind(target_kind: str) -> list[str]:
    if target_kind == "llm":
        return list(LLM_FRAMEWORKS)
    if target_kind == "repo":
        return list(REPO_FRAMEWORKS)
    return list(URL_FRAMEWORKS)


def build_compliance_rollup(
    *,
    scan_id: str,
    target_kind: Literal["url", "repo", "llm"],
    findings: Iterable,
    frameworks: Iterable[str] | None = None,
) -> dict:
    """Compute the per-scan compliance rollup.

    ``findings`` may be either ``Finding`` (URL / LLM) or
    ``RepoFinding`` (repo) ORM rows — the function discriminates on
    ``target_kind`` and normalises both into the same intermediate
    dict shape before fanning out across frameworks.
    """
    fws = list(frameworks) if frameworks else _frameworks_for_kind(target_kind)
    norm = _normalize_findings(target_kind, findings)

    # Per-framework control buckets.
    summary: dict[str, dict] = {}
    for fw in fws:
        summary[FRAMEWORK_LABELS.get(fw, fw)] = {
            "controls": {},  # ctrl_key -> {finding_count, severity_breakdown, finding_ids, control, title}
            "covered": 0,
            "total": 0,
        }

    # Per-finding compliance dict that mirrors the wire shape used in
    # JSON / CSV exports.
    per_finding_compliance: list[dict] = []

    for f in norm:
        comp: dict[str, list[str]] = {}

        for fw in fws:
            label = FRAMEWORK_LABELS.get(fw, fw)
            controls: list[tuple[str, str, str]] = []  # (key, code, title)

            if fw == "owasp":
                code = (
                    f["owasp_category"].split(":", 1)[0].strip()
                    if f["owasp_category"]
                    else None
                ) or CATEGORY_TO_OWASP.get(f["category"])
                if code in OWASP_TOP_10:
                    title = OWASP_TOP_10[code]
                    controls.append((f"{code}: {title}", code, title))
            elif fw == "owasp-llm":
                code = _llm_category_from_owasp(f["owasp_category"])
                if code:
                    title = OWASP_LLM_TOP_10[code]
                    controls.append((f"{code}: {title}", code, title))
            elif fw in ("mitre-atlas", "nist-ai-rmf", "eu-ai-act"):
                code = _llm_category_from_owasp(f["owasp_category"])
                if code:
                    fw_map = _FRAMEWORK_MAPS.get(fw, {})
                    for ctrl in fw_map.get(code, []):
                        controls.append((ctrl, ctrl, ctrl))
            else:
                fw_map = _FRAMEWORK_MAPS.get(fw, {})
                for ctrl in fw_map.get(f["category"], []):
                    controls.append((ctrl, ctrl, ctrl))

            if not controls:
                continue

            comp.setdefault(label, [])
            for key, code, title in controls:
                if key not in comp[label]:
                    comp[label].append(key)
                bucket = summary[label]["controls"].setdefault(key, {
                    "id": key,
                    "control": code,
                    "title": title,
                    "finding_count": 0,
                    "severity_breakdown": _empty_severity_bucket(),
                    "finding_ids": [],
                })
                bucket["finding_count"] += 1
                _bump_severity(bucket["severity_breakdown"], f["severity"])
                if len(bucket["finding_ids"]) < 50:
                    bucket["finding_ids"].append(f["id"])

        per_finding_compliance.append({
            "id": f["id"],
            "title": f["title"],
            "severity": f["severity"],
            "category": f["category"],
            "owasp_category": f["owasp_category"],
            "scanner": f["scanner"],
            "compliance": comp,
        })

    # Flatten control buckets → list, compute coverage denominators.
    controls_touched_total = 0
    for fw in fws:
        label = FRAMEWORK_LABELS.get(fw, fw)
        ctrls = list(summary[label]["controls"].values())
        ctrls.sort(key=lambda c: (-c["finding_count"], c["id"]))
        controls_touched_total += len(ctrls)
        summary[label]["controls"] = ctrls
        summary[label]["covered"] = len(ctrls)
        if fw == "owasp":
            summary[label]["total"] = len(OWASP_TOP_10)
        elif fw == "owasp-llm":
            summary[label]["total"] = len(OWASP_LLM_TOP_10)
        else:
            # No fixed denominator for control catalogues — surface the
            # number of unique controls fired by this scan instead.
            summary[label]["total"] = len(ctrls)

    return {
        "scan_id": scan_id,
        "target_kind": target_kind,
        "frameworks": [FRAMEWORK_LABELS.get(fw, fw) for fw in fws],
        "totals": {
            "findings": len(norm),
            "controls_touched": controls_touched_total,
        },
        "frameworks_summary": summary,
        "findings": per_finding_compliance,
    }
