"""Normalize scanner output into a shared RepoFinding-shaped dict.

Each scanner speaks its own JSON dialect. This module is the single place
where those dialects are mapped onto the columns of ``RepoFinding`` so
adding a new scanner is a small, additive change.

All normalizers return a list of dicts with (at least) these keys:
    scanner, rule_id, severity, title, description, file_path,
    line_start, line_end, code_snippet, cve, package, installed_version,
    fixed_version, raw
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _canonical_severity(value: str | None) -> str:
    if not value:
        return "medium"
    v = str(value).lower().strip()
    if v in SEV_ORDER:
        return v
    # Semgrep + others sometimes use ERROR/WARNING/INFO
    return {
        "error": "high",
        "warning": "medium",
        "info": "low",
        "unknown": "medium",
    }.get(v, "medium")


def _rel(path: str, repo_root: str) -> str:
    try:
        return str(Path(path).resolve().relative_to(Path(repo_root).resolve()))
    except Exception:
        return path


def normalize_semgrep(raw_json: str | dict, repo_root: str) -> list[dict[str, Any]]:
    """Parse Semgrep OSS JSON into RepoFinding-shaped dicts.

    Pencheff invokes Semgrep with an explicit allowlist of OSS Registry
    packs (no Pro rules). Severity comes from ``extra.severity`` (ERROR /
    WARNING / INFO) which ``_canonical_severity`` already maps onto our
    five-level scale.
    """
    data = raw_json if isinstance(raw_json, dict) else json.loads(raw_json or "{}")
    out: list[dict[str, Any]] = []
    for r in data.get("results") or []:
        rule_id = r.get("check_id") or "semgrep"
        path = _rel(r.get("path") or "", repo_root)
        line_start = (r.get("start") or {}).get("line")
        line_end = (r.get("end") or {}).get("line") or line_start
        extra = r.get("extra") or {}
        meta = extra.get("metadata") or {}

        cwe_field = meta.get("cwe")
        if isinstance(cwe_field, list):
            cwe_field = cwe_field[0] if cwe_field else None
        cwe = None
        if isinstance(cwe_field, str):
            for tok in cwe_field.split():
                if tok.upper().startswith("CWE-"):
                    cwe = tok.upper().rstrip(":")
                    break

        message = extra.get("message") or rule_id
        out.append({
            "scanner": "semgrep",
            "rule_id": rule_id,
            "severity": _canonical_severity(extra.get("severity")),
            "title": message.split("\n")[0][:500],
            "description": message,
            "file_path": path,
            "line_start": line_start,
            "line_end": line_end,
            "code_snippet": (extra.get("lines") or "")[:500],
            "cve": None,
            "package": None,
            "installed_version": None,
            "fixed_version": None,
            "raw": {"result": r, "cwe": cwe, "metadata": meta},
        })
    return out


def normalize_bandit(raw_json: str | dict, repo_root: str) -> list[dict[str, Any]]:
    """Parse Bandit JSON output into RepoFinding-shaped dicts."""
    data = raw_json if isinstance(raw_json, dict) else json.loads(raw_json or "{}")
    out: list[dict[str, Any]] = []
    for r in data.get("results") or []:
        rel = _rel(r.get("filename") or "", repo_root)
        sev_label = (r.get("issue_severity") or "").lower()
        # Bandit's severity vocabulary: LOW / MEDIUM / HIGH. Bandit's
        # confidence is orthogonal — keep it on the description rather
        # than collapse it into severity.
        severity = _canonical_severity(sev_label)
        confidence = r.get("issue_confidence", "MEDIUM")
        test_id = r.get("test_id", "")
        test_name = r.get("test_name", "security issue")
        text = r.get("issue_text", "Bandit finding")
        cwe_id = (r.get("issue_cwe") or {}).get("id")
        cwe = f"CWE-{cwe_id}" if cwe_id else None
        out.append({
            "scanner": "bandit",
            "rule_id": test_id,
            "severity": severity,
            "title": f"{test_id}: {test_name}"[:500],
            "description": f"{text} (confidence: {confidence})",
            "file_path": rel,
            "line_start": r.get("line_number"),
            "line_end": r.get("line_number"),
            "code_snippet": (r.get("code") or "")[:500],
            "cve": None,
            "package": None,
            "installed_version": None,
            "fixed_version": None,
            "raw": {"result": r, "cwe": cwe},
        })
    return out


def normalize_gosec(raw_json: str | dict, repo_root: str) -> list[dict[str, Any]]:
    """Parse gosec JSON output into RepoFinding-shaped dicts."""
    data = raw_json if isinstance(raw_json, dict) else json.loads(raw_json or "{}")
    out: list[dict[str, Any]] = []
    for r in data.get("Issues") or []:
        rule_id = r.get("rule_id") or "gosec"
        severity = _canonical_severity(r.get("severity"))
        cwe_id = (r.get("cwe") or {}).get("ID")
        cwe = f"CWE-{cwe_id}" if cwe_id else None
        # gosec's "line" is sometimes a range like "12-15".
        line_str = str(r.get("line") or "")
        line_start = None
        line_end = None
        if line_str:
            parts = line_str.split("-", 1)
            try:
                line_start = int(parts[0])
                line_end = int(parts[1]) if len(parts) > 1 else line_start
            except ValueError:
                pass
        out.append({
            "scanner": "gosec",
            "rule_id": rule_id,
            "severity": severity,
            "title": (r.get("details") or rule_id)[:500],
            "description": r.get("details"),
            "file_path": _rel(r.get("file") or "", repo_root),
            "line_start": line_start,
            "line_end": line_end,
            "code_snippet": (r.get("code") or "")[:500],
            "cve": None,
            "package": None,
            "installed_version": None,
            "fixed_version": None,
            "raw": {"result": r, "cwe": cwe, "confidence": r.get("confidence")},
        })
    return out


def normalize_brakeman(raw_json: str | dict, repo_root: str) -> list[dict[str, Any]]:
    """Parse Brakeman JSON output into RepoFinding-shaped dicts."""
    data = raw_json if isinstance(raw_json, dict) else json.loads(raw_json or "{}")
    out: list[dict[str, Any]] = []
    for w in data.get("warnings") or []:
        # Brakeman uses 1-3 confidence levels; map confidence + warning_type
        # into our severity scale conservatively.
        confidence = (w.get("confidence") or "Medium").lower()
        sev_map = {"high": "high", "medium": "medium", "weak": "low"}
        severity = sev_map.get(confidence, "medium")
        check_name = w.get("check_name") or "BrakemanCheck"
        warning_type = w.get("warning_type") or check_name
        out.append({
            "scanner": "brakeman",
            "rule_id": check_name,
            "severity": severity,
            "title": f"{warning_type}: {w.get('message', '')[:400]}"[:500],
            "description": w.get("message"),
            "file_path": _rel(w.get("file") or "", repo_root),
            "line_start": w.get("line"),
            "line_end": w.get("line"),
            "code_snippet": (w.get("code") or "")[:500],
            "cve": None,
            "package": None,
            "installed_version": None,
            "fixed_version": None,
            "raw": w,
        })
    return out


def normalize_eslint(raw_json: str | list, repo_root: str) -> list[dict[str, Any]]:
    """Parse ESLint JSON output into RepoFinding-shaped dicts.

    ESLint emits a top-level array of file-result objects, each with a
    ``messages`` list. We only forward ``security/*`` rule hits — the
    ESLint runner ships a flat config that disables everything else, but
    a stray rule from a transitively-loaded config could still slip in.
    """
    data = raw_json if isinstance(raw_json, list) else json.loads(raw_json or "[]")
    out: list[dict[str, Any]] = []
    for file_result in data or []:
        rel = _rel(file_result.get("filePath") or "", repo_root)
        for m in file_result.get("messages") or []:
            rule_id = m.get("ruleId") or ""
            if not rule_id.startswith("security/"):
                continue
            sev_int = m.get("severity")  # 1=warn, 2=error
            severity = "high" if sev_int == 2 else "medium"
            out.append({
                "scanner": "eslint",
                "rule_id": rule_id,
                "severity": severity,
                "title": (m.get("message") or rule_id)[:500],
                "description": m.get("message"),
                "file_path": rel,
                "line_start": m.get("line"),
                "line_end": m.get("endLine") or m.get("line"),
                "code_snippet": None,
                "cve": None,
                "package": None,
                "installed_version": None,
                "fixed_version": None,
                "raw": m,
            })
    return out


def normalize_gitleaks(raw_json: str | list, repo_root: str) -> list[dict[str, Any]]:
    data = raw_json if isinstance(raw_json, list) else json.loads(raw_json or "[]")
    out: list[dict[str, Any]] = []
    for r in data or []:
        rule = r.get("RuleID") or r.get("Description", "secret")
        out.append({
            "scanner": "gitleaks",
            "rule_id": rule,
            "severity": "high",  # every leaked secret is high by default
            "title": f"Secret: {rule}",
            "description": r.get("Description"),
            "file_path": _rel(r.get("File", ""), repo_root),
            "line_start": r.get("StartLine"),
            "line_end": r.get("EndLine"),
            "code_snippet": (r.get("Match") or r.get("Secret") or "")[:500],
            "cve": None,
            "package": None,
            "installed_version": None,
            "fixed_version": None,
            "raw": r,
        })
    return out


def normalize_ghsa(raw_json: str | dict, repo_root: str) -> list[dict[str, Any]]:
    """Normalize osv-scanner output, surfacing it as ``scanner="ghsa"``.

    osv-scanner queries OSV.dev, which mirrors the GitHub Advisory
    Database (and other sources). Every finding here is sourced from
    GHSA when an alias starting with ``GHSA-`` is present; otherwise we
    still surface the advisory but use its native ID as the rule id.
    """
    data = raw_json if isinstance(raw_json, dict) else json.loads(raw_json or "{}")
    out: list[dict[str, Any]] = []
    for result in data.get("results", []):
        source_path = (result.get("source") or {}).get("path", "")
        for pkg in result.get("packages", []):
            pkg_info = pkg.get("package", {}) or {}
            name = pkg_info.get("name", "unknown")
            version = pkg_info.get("version", "")
            for vuln in pkg.get("vulnerabilities", []):
                vid = vuln.get("id", "VULN")
                aliases = vuln.get("aliases", []) or []
                ghsa = next((a for a in aliases if a.startswith("GHSA-")), None)
                cve = next((a for a in aliases if a.startswith("CVE-")), None)
                rule_id = ghsa or vid
                fixed_version = None
                for af in vuln.get("affected", []):
                    for rng in af.get("ranges", []):
                        for ev in rng.get("events", []):
                            if "fixed" in ev:
                                fixed_version = ev["fixed"]
                                break
                    if fixed_version:
                        break
                sev = None
                for sv in vuln.get("severity", []) or []:
                    score = sv.get("score", "")
                    if "CVSS" in sv.get("type", ""):
                        sev = _severity_from_cvss(score)
                        break
                sev = sev or _canonical_severity(vuln.get("database_specific", {}).get("severity"))
                summary = vuln.get("summary") or vid
                out.append({
                    "scanner": "ghsa",
                    "rule_id": rule_id,
                    "severity": sev,
                    "title": f"{name}@{version}: {summary}"[:500],
                    "description": vuln.get("details"),
                    "file_path": _rel(source_path, repo_root) if source_path else None,
                    "line_start": None,
                    "line_end": None,
                    "code_snippet": None,
                    "cve": cve,
                    "package": name,
                    "installed_version": version,
                    "fixed_version": fixed_version,
                    "raw": vuln,
                })
    return out


def _severity_from_cvss(score: str) -> str:
    """Map a CVSS v3 vector or numeric score to a severity bucket."""
    try:
        # The score string looks like "CVSS:3.1/AV:N/..." or "7.5"
        if score.startswith("CVSS"):
            # try to extract base score from end
            return "medium"
        val = float(score)
    except Exception:
        return "medium"
    if val >= 9.0:
        return "critical"
    if val >= 7.0:
        return "high"
    if val >= 4.0:
        return "medium"
    if val > 0:
        return "low"
    return "info"


def normalize_dependabot(alerts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """GitHub's /dependabot/alerts API shape (not the OSV shape)."""
    out: list[dict[str, Any]] = []
    for a in alerts or []:
        adv = a.get("security_advisory") or {}
        vuln = a.get("security_vulnerability") or {}
        pkg = (vuln.get("package") or {}).get("name") or (adv.get("cve_id") or "unknown")
        ghsa = adv.get("ghsa_id")
        cve = adv.get("cve_id")
        severity = _canonical_severity(adv.get("severity"))
        installed = ((a.get("dependency") or {}).get("manifest_path") or "")
        out.append({
            "scanner": "ghsa",
            "rule_id": ghsa or cve or "DEPENDABOT",
            "severity": severity,
            "title": (adv.get("summary") or "Dependabot alert")[:500],
            "description": adv.get("description"),
            "file_path": installed or None,
            "line_start": None,
            "line_end": None,
            "code_snippet": None,
            "cve": cve,
            "package": pkg,
            "installed_version": (a.get("security_vulnerability") or {}).get("vulnerable_version_range"),
            "fixed_version": (vuln.get("first_patched_version") or {}).get("identifier"),
            "raw": a,
        })
    return out


def normalize_yara(ndjson_text: str, repo_root: str) -> list[dict[str, Any]]:
    """Each line is `{rule, file}`; we group adjacent duplicates."""
    out: list[dict[str, Any]] = []
    for line in (ndjson_text or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        rule = obj.get("rule", "yara")
        file_path = obj.get("file", "")
        severity = _severity_for_yara_rule(rule)
        out.append({
            "scanner": "yara",
            "rule_id": rule,
            "severity": severity,
            "title": f"YARA match: {rule}"[:500],
            "description": f"YARA rule `{rule}` matched in `{_rel(file_path, repo_root)}`.",
            "file_path": _rel(file_path, repo_root),
            "line_start": None,
            "line_end": None,
            "code_snippet": None,
            "cve": None,
            "package": None,
            "installed_version": None,
            "fixed_version": None,
            "raw": obj,
        })
    return out


def _severity_for_yara_rule(rule: str) -> str:
    rule_l = rule.lower()
    if any(k in rule_l for k in ("webshell", "reverse_shell", "backdoor")):
        return "critical"
    if any(k in rule_l for k in ("miner", "loader", "rce")):
        return "high"
    return "medium"


def normalize_trivy_iac(raw_json: str | dict, repo_root: str) -> list[dict[str, Any]]:
    """Trivy `config` mode JSON shape: {Results: [{Target, Misconfigurations: [...]}]}."""
    data = raw_json if isinstance(raw_json, dict) else json.loads(raw_json or "{}")
    out: list[dict[str, Any]] = []
    for r in data.get("Results", []):
        target_path = r.get("Target", "")
        for m in r.get("Misconfigurations", []) or []:
            severity = _canonical_severity(m.get("Severity"))
            cause = m.get("CauseMetadata") or {}
            out.append({
                "scanner": "trivy_iac",
                "rule_id": m.get("ID") or m.get("AVDID"),
                "severity": severity,
                "title": (m.get("Title") or m.get("Description") or "IaC misconfig")[:500],
                "description": m.get("Description") or m.get("Resolution"),
                "file_path": _rel(target_path, repo_root) if target_path else None,
                "line_start": cause.get("StartLine"),
                "line_end": cause.get("EndLine"),
                "code_snippet": (cause.get("Code") or {}).get("Lines", [{}])[0].get("Content") if cause.get("Code") else None,
                "cve": None,
                "package": None,
                "installed_version": None,
                "fixed_version": None,
                "raw": m,
            })
    return out


def normalize_checkov(raw_json: str | dict, repo_root: str) -> list[dict[str, Any]]:
    """Checkov JSON: top-level may be a list of run outputs or a single run."""
    data = raw_json if isinstance(raw_json, (dict, list)) else json.loads(raw_json or "{}")
    runs = data if isinstance(data, list) else [data]
    out: list[dict[str, Any]] = []
    for run in runs:
        results = (run or {}).get("results") or {}
        for check in results.get("failed_checks", []) or []:
            severity_raw = (check.get("severity") or "MEDIUM").lower()
            severity = _canonical_severity(severity_raw)
            file_path = check.get("file_path") or ""
            file_line_range = check.get("file_line_range") or [None, None]
            out.append({
                "scanner": "checkov",
                "rule_id": check.get("check_id"),
                "severity": severity,
                "title": (check.get("check_name") or "Checkov failure")[:500],
                "description": check.get("guideline") or check.get("description"),
                "file_path": _rel(file_path, repo_root) if file_path else None,
                "line_start": file_line_range[0] if file_line_range else None,
                "line_end": file_line_range[1] if len(file_line_range) > 1 else None,
                "code_snippet": "\n".join(line[1] for line in (check.get("code_block") or []))[:2000] if check.get("code_block") else None,
                "cve": None,
                "package": check.get("resource"),
                "installed_version": None,
                "fixed_version": None,
                "raw": check,
            })
    return out
