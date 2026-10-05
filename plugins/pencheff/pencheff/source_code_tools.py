"""Source-code SAST scanner wrappers (feature 001-multi-target-scan-pipelines).

Thin agent-callable wrappers around semgrep / bandit / gosec / brakeman /
eslint / gitleaks / yara / osv-scanner. The existing pencheff_api's
``tasks.repo_scan_task`` already drives these scanners for legacy ``repo``
targets; this module exposes the same scanners as MCP tools so the
artifact_orchestrator can run them under the kind=source_code allowlist
when the agent picks a scanner subset.

The wrappers are intentionally NOT a refactor of repo_scan_task — they
duplicate the subprocess invocation but normalize the output into the
same finding shape used by artifact_tools (severity / category /
owasp_category / file_path / line_start / line_end / description). The
legacy ``repo_scan_task`` continues to use its own ``_run_*`` privates
unchanged for backward compat.
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

from .artifact_tools import _kind_config_for_session, _run_subprocess, _which


_SEV_NORMALIZE = {
    "critical": "critical", "high": "high", "medium": "medium",
    "low": "low", "info": "info", "warning": "medium", "error": "high",
    "note": "low", "informational": "info", "unknown": "info",
}


def _normalize_sev(raw: str | None) -> str:
    return _SEV_NORMALIZE.get((raw or "info").lower(), "info")


# ============================================================================
# run_semgrep
# ============================================================================


async def run_semgrep(
    session_id: str,
    source_path: str,
    config: str = "auto",
) -> dict[str, Any]:
    """Run semgrep against a source directory.

    ``config="auto"`` lets semgrep choose rules based on detected languages
    (the same default repo_scan_task uses). Operators can override with
    explicit rule packs via the agent's kind_config.scanners_disabled hook
    in future iterations.
    """
    if not _which("semgrep"):
        return {"error": "binary not found: semgrep", "skipped": True}
    if not Path(source_path).exists():
        return {"error": "source_path does not exist"}
    argv = ["semgrep", "--json", "--quiet", "--config", config, source_path]
    result = await _run_subprocess(argv, timeout=900)  # SAST runs are slow
    if result.get("error"):
        return result
    findings = _parse_semgrep_json(result.get("stdout", ""))
    return {"scanner": "semgrep", "findings_count": len(findings), "findings": findings}


def _parse_semgrep_json(stdout: str) -> list[dict[str, Any]]:
    if not stdout.strip():
        return []
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return []
    findings: list[dict[str, Any]] = []
    for r in data.get("results", []) or []:
        meta = r.get("extra", {}) or {}
        sev = _normalize_sev(meta.get("severity"))
        # Semgrep often tags rules with OWASP metadata in extra.metadata.owasp.
        owasp_tags = (meta.get("metadata") or {}).get("owasp") or []
        owasp = owasp_tags[0] if isinstance(owasp_tags, list) and owasp_tags else "A03:2021"
        findings.append({
            "title": meta.get("message", r.get("check_id", "semgrep finding"))[:255],
            "severity": sev,
            "category": "sast",
            "owasp_category": owasp,
            "file_path": r.get("path"),
            "line_start": (r.get("start") or {}).get("line"),
            "line_end": (r.get("end") or {}).get("line"),
            "description": (meta.get("message") or "")[:512],
            "remediation": (meta.get("fix") or "")[:512],
        })
    return findings


# ============================================================================
# run_bandit (Python)
# ============================================================================


async def run_bandit(session_id: str, source_path: str) -> dict[str, Any]:
    """Run bandit against a Python source directory."""
    if not _which("bandit"):
        return {"error": "binary not found: bandit", "skipped": True}
    if not Path(source_path).exists():
        return {"error": "source_path does not exist"}
    argv = ["bandit", "-r", source_path, "-f", "json", "-q"]
    result = await _run_subprocess(argv, timeout=600)
    if result.get("error"):
        return result
    findings = _parse_bandit_json(result.get("stdout", ""))
    return {"scanner": "bandit", "findings_count": len(findings), "findings": findings}


def _parse_bandit_json(stdout: str) -> list[dict[str, Any]]:
    if not stdout.strip():
        return []
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return []
    findings: list[dict[str, Any]] = []
    for r in data.get("results", []) or []:
        sev = _normalize_sev(r.get("issue_severity"))
        findings.append({
            "title": r.get("test_name", "bandit finding")[:255],
            "severity": sev,
            "category": "sast",
            "owasp_category": "A03:2021",  # default — Injection / weak crypto, etc.
            "file_path": r.get("filename"),
            "line_start": r.get("line_number"),
            "description": (r.get("issue_text") or "")[:512],
            "remediation": r.get("more_info") or "",
        })
    return findings


# ============================================================================
# run_gosec (Go)
# ============================================================================


async def run_gosec(session_id: str, source_path: str) -> dict[str, Any]:
    if not _which("gosec"):
        return {"error": "binary not found: gosec", "skipped": True}
    if not Path(source_path).exists():
        return {"error": "source_path does not exist"}
    argv = ["gosec", "-fmt=json", "-quiet", "./..."]
    result = await _run_subprocess(argv, timeout=600, cwd=source_path)
    if result.get("error"):
        return result
    findings = _parse_gosec_json(result.get("stdout", ""))
    return {"scanner": "gosec", "findings_count": len(findings), "findings": findings}


def _parse_gosec_json(stdout: str) -> list[dict[str, Any]]:
    if not stdout.strip():
        return []
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return []
    findings: list[dict[str, Any]] = []
    for r in data.get("Issues", []) or []:
        sev = _normalize_sev(r.get("severity"))
        line_str = (r.get("line") or "1").split("-")[0]
        try:
            line_start = int(line_str)
        except ValueError:
            line_start = None
        findings.append({
            "title": r.get("rule_id", "gosec rule"),
            "severity": sev,
            "category": "sast",
            "owasp_category": "A03:2021",
            "file_path": r.get("file"),
            "line_start": line_start,
            "description": (r.get("details") or "")[:512],
        })
    return findings


# ============================================================================
# run_brakeman (Ruby on Rails)
# ============================================================================


async def run_brakeman(session_id: str, source_path: str) -> dict[str, Any]:
    if not _which("brakeman"):
        return {"error": "binary not found: brakeman", "skipped": True}
    if not Path(source_path).exists():
        return {"error": "source_path does not exist"}
    argv = ["brakeman", "-q", "-f", "json", source_path]
    result = await _run_subprocess(argv, timeout=600)
    # Brakeman exits non-zero when warnings are present — parse output regardless.
    findings = _parse_brakeman_json(result.get("stdout", ""))
    return {"scanner": "brakeman", "findings_count": len(findings), "findings": findings}


def _parse_brakeman_json(stdout: str) -> list[dict[str, Any]]:
    if not stdout.strip():
        return []
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return []
    findings: list[dict[str, Any]] = []
    for w in data.get("warnings", []) or []:
        sev = _normalize_sev(w.get("confidence"))
        findings.append({
            "title": w.get("warning_type", "brakeman warning"),
            "severity": sev,
            "category": "sast",
            "owasp_category": "A03:2021",
            "file_path": w.get("file"),
            "line_start": w.get("line"),
            "description": (w.get("message") or "")[:512],
        })
    return findings


# ============================================================================
# run_eslint (JavaScript/TypeScript security rules)
# ============================================================================


async def run_eslint(
    session_id: str,
    source_path: str,
) -> dict[str, Any]:
    if not _which("npx"):
        return {"error": "binary not found: npx", "skipped": True}
    if not Path(source_path).exists():
        return {"error": "source_path does not exist"}
    argv = ["npx", "--no-install", "eslint", "-f", "json", source_path]
    result = await _run_subprocess(argv, timeout=600, cwd=source_path)
    findings = _parse_eslint_json(result.get("stdout", ""))
    return {"scanner": "eslint", "findings_count": len(findings), "findings": findings}


def _parse_eslint_json(stdout: str) -> list[dict[str, Any]]:
    if not stdout.strip():
        return []
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return []
    findings: list[dict[str, Any]] = []
    for file_block in data if isinstance(data, list) else []:
        path = file_block.get("filePath")
        for msg in file_block.get("messages", []) or []:
            # eslint severity is 1=warning, 2=error; we only flag security
            # rules (ruleId starting with "security/") as findings.
            rule = msg.get("ruleId") or ""
            if not (rule.startswith("security/") or rule.startswith("no-eval")):
                continue
            sev = "high" if msg.get("severity") == 2 else "medium"
            findings.append({
                "title": rule or "eslint security rule",
                "severity": sev,
                "category": "sast",
                "owasp_category": "A03:2021",
                "file_path": path,
                "line_start": msg.get("line"),
                "description": (msg.get("message") or "")[:512],
            })
    return findings


# ============================================================================
# run_gitleaks (secret scanning)
# ============================================================================


async def run_gitleaks(session_id: str, source_path: str) -> dict[str, Any]:
    if not _which("gitleaks"):
        return {"error": "binary not found: gitleaks", "skipped": True}
    if not Path(source_path).exists():
        return {"error": "source_path does not exist"}
    git_dir = Path(source_path) / ".git"
    cmd = "detect" if git_dir.exists() else "dir"
    argv = ["gitleaks", cmd, "--source", source_path, "--report-format", "json",
            "--no-banner", "--exit-code", "0"]
    if cmd == "dir":
        argv.append("--no-git")
    result = await _run_subprocess(argv, timeout=600)
    findings = _parse_gitleaks_json(result.get("stdout", ""))
    return {"scanner": "gitleaks", "findings_count": len(findings), "findings": findings}


def _parse_gitleaks_json(stdout: str) -> list[dict[str, Any]]:
    if not stdout.strip():
        return []
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return []
    items = data if isinstance(data, list) else data.get("findings") or []
    findings: list[dict[str, Any]] = []
    for item in items:
        findings.append({
            "title": f"Secret leak: {item.get('RuleID') or item.get('Description', 'secret')}",
            "severity": "high",  # secrets always default high
            "category": "secret_leak",
            "owasp_category": "A07:2021",  # Identification & Authentication Failures
            "file_path": item.get("File"),
            "line_start": item.get("StartLine"),
            "line_end": item.get("EndLine"),
            "description": (item.get("Description") or "")[:512],
            "evidence": {"secret_excerpt": (item.get("Secret") or "")[:64]},
        })
    return findings


# ============================================================================
# run_zizmor (GitHub Actions CI/CD static analysis)
# ============================================================================


# audit ident → (owasp_category, cwe_id). Maps zizmor's CI/CD attack classes
# onto the closest web-OWASP bucket the grader/report understand; the precise
# CI/CD taxonomy lives in the finding description (audit: <ident>).
_ZIZMOR_OWASP: dict[str, tuple[str, str | None]] = {
    "template-injection":       ("A03:2021", "CWE-94"),   # code injection via ${{ }}
    "github-env-injection":     ("A03:2021", "CWE-94"),
    "dangerous-triggers":       ("A01:2021", "CWE-863"),  # pull_request_target PPE
    "excessive-permissions":    ("A01:2021", "CWE-732"),  # write-all GITHUB_TOKEN
    "artipacked":               ("A07:2021", "CWE-522"),  # credential persistence
    "unpinned-uses":            ("A08:2021", "CWE-829"),  # supply chain / unpinned
    "known-vulnerable-actions": ("A06:2021", "CWE-1104"),
    "self-hosted-runner":       ("A01:2021", "CWE-284"),
    "cache-poisoning":          ("A08:2021", "CWE-349"),
    "secrets-inherit":          ("A05:2021", "CWE-668"),
    "secrets-outside-env":      ("A05:2021", "CWE-668"),
    "undocumented-permissions": ("A01:2021", "CWE-732"),
    "concurrency-limits":       ("A05:2021", None),
    "bot-conditions":           ("A01:2021", "CWE-863"),
}


# Per-audit attacker-impact narrative — turns a bare misconfig into a
# pentest-grade "here's how it's weaponised" line. Folded into the finding
# description so the report proves impact, not just presence.
_ZIZMOR_IMPACT: dict[str, str] = {
    "dangerous-triggers": "Attacker opens a PR from a fork; the pull_request_target "
        "trigger runs against repo secrets with a write-scoped GITHUB_TOKEN → secret "
        "exfiltration / repo takeover (Poisoned Pipeline Execution, OWASP CICD-SEC-4).",
    "template-injection": "Attacker-controlled text (PR title, issue body, branch name) "
        "is interpolated into a run: shell → arbitrary command execution on the runner "
        "with the workflow's token and secrets.",
    "excessive-permissions": "A compromised step or malicious dependency inherits the "
        "over-broad GITHUB_TOKEN scope → push code, publish releases, or rewrite the repo.",
    "artipacked": "checkout persists the GITHUB_TOKEN in .git/config; if the workspace is "
        "later uploaded as a build artifact the token leaks to anyone who can read it.",
    "unpinned-uses": "A tag/branch action ref can be repointed to malicious code by its "
        "owner (or a compromised owner account) → supply-chain code execution in your pipeline.",
    "self-hosted-runner": "Public-repo workflows on self-hosted runners let a forked-PR "
        "attacker execute code on your infrastructure and pivot into the network / persist.",
    "known-vulnerable-actions": "The pinned action version has a known exploit → an "
        "attacker leverages it to run code or steal secrets inside the pipeline.",
    "cache-poisoning": "Attacker writes a poisoned cache entry that a later privileged run "
        "restores → code execution or artifact tampering with the pipeline's privileges.",
    "secrets-outside-env": "Secrets declared outside a scoped environment are readable by "
        "more jobs/steps than needed, widening blast radius on any single step compromise.",
}


async def run_zizmor(session_id: str, source_path: str) -> dict[str, Any]:
    """Run zizmor against a repo clone's GitHub Actions workflows.

    zizmor is the CI/CD-attack analyzer checkov isn't: it audits
    ``.github/workflows/*.yml`` for template injection, dangerous triggers
    (poisoned pipeline execution via ``pull_request_target``), excessive
    ``GITHUB_TOKEN`` permissions, credential persistence (artipacked),
    unpinned / known-vulnerable actions, self-hosted-runner exposure, and
    cache poisoning. ``--offline`` keeps Phase A deterministic and token-free;
    the online ``known-vulnerable-actions`` cross-check belongs to Phase B.
    """
    if not _which("zizmor"):
        return {"error": "binary not found: zizmor", "skipped": True}
    if not Path(source_path).exists():
        return {"error": "source_path does not exist"}
    # No workflows → nothing to audit; skip cleanly instead of erroring on
    # "no inputs" (keeps zizmor a no-op for non-GitHub-Actions repos).
    if not (Path(source_path) / ".github" / "workflows").is_dir():
        return {"scanner": "zizmor", "findings_count": 0, "findings": [],
                "skipped": "no .github/workflows"}
    # auditor persona = max recall: surfaces self-hosted-runner exposure and
    # deeper permission / injection classes the default 'regular' persona
    # suppresses. FPs are acceptable for a pentest (triaged downstream) and the
    # report groups duplicates, so recall beats a low-FP default here.
    argv = ["zizmor", "--format", "json", "--offline", "--persona", "auditor",
            "--min-confidence", "low", source_path]
    result = await _run_subprocess(argv, timeout=600)
    stdout = result.get("stdout", "")
    # zizmor exits 14 when it finds issues and 0 when clean — both are success
    # (same convention as checkov). A crash emits no JSON array; surface that
    # as an error rather than silently reporting a clean pipeline.
    if not stdout.lstrip().startswith("["):
        tail = ((result.get("stderr") or "").strip().splitlines() or [""])[-1]
        return {"error": f"zizmor failed: {tail}"[:500], "skipped": True}
    findings = _parse_zizmor_json(stdout)
    return {"scanner": "zizmor", "findings_count": len(findings), "findings": findings}


def _parse_zizmor_json(stdout: str) -> list[dict[str, Any]]:
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return []
    if not isinstance(data, list):
        return []
    findings: list[dict[str, Any]] = []
    for r in data:
        if r.get("ignored"):
            continue
        ident = r.get("ident") or "zizmor"
        # anonymous-definition is a naming/style smell, not a security issue;
        # drop it so the auditor-persona recall boost doesn't add report noise.
        if ident == "anonymous-definition":
            continue
        det = r.get("determinations") or {}
        sev = _normalize_sev(det.get("severity"))
        confidence = det.get("confidence") or "Unknown"
        locs = r.get("locations") or []
        # Prefer the Primary location; fall back to the first reported.
        primary = next(
            (l for l in locs if (l.get("symbolic") or {}).get("kind") == "Primary"),
            locs[0] if locs else {},
        )
        sym = primary.get("symbolic") or {}
        path = ((sym.get("key") or {}).get("Local") or {}).get("given_path")
        annotation = sym.get("annotation") or ""
        conc = (primary.get("concrete") or {}).get("location") or {}
        row = (conc.get("start_point") or {}).get("row")
        # zizmor rows are 0-indexed (tree-sitter); +1 for human line numbers.
        line_start = row + 1 if isinstance(row, int) else None
        snippet = (primary.get("concrete") or {}).get("feature") or ""
        owasp, cwe = _ZIZMOR_OWASP.get(ident, ("A05:2021", None))
        desc = r.get("desc") or ident
        detail = desc + (f" — {annotation}" if annotation else "")
        impact = _ZIZMOR_IMPACT.get(ident)
        if impact:
            detail += f" Attacker impact: {impact}"
        detail += f" (audit: {ident}, confidence: {confidence})"
        findings.append({
            "title": desc[:255],
            "severity": sev,
            "category": "cicd_security",
            "owasp_category": owasp,
            "cwe_id": cwe,
            "file_path": path,
            "line_start": line_start,
            "description": detail[:1000],
            "remediation": (f"See {r['url']}" if r.get("url") else "")[:512],
            "evidence": {"audit": ident, "confidence": confidence,
                         "snippet": snippet[:200]},
        })
    return findings


# ============================================================================
# run_gitlab_ci_audit (custom GitLab CI/CD attack analysis)
# ============================================================================
#
# zizmor is GitHub-Actions-only and poutine's GitLab coverage is weak, so this
# is a hand-written analyzer for the flagship GitLab CI attack: command
# injection via attacker-controllable predefined variables interpolated into
# job scripts (the GitLab analog of GitHub's template-injection / PPE).

# GitLab predefined variables an external contributor controls (branch / tag /
# commit / MR metadata). Interpolating any of these into a shell script = RCE.
# https://docs.gitlab.com/ee/ci/variables/predefined_variables.html
_GITLAB_UNTRUSTED_VARS = frozenset({
    "CI_COMMIT_MESSAGE", "CI_COMMIT_DESCRIPTION", "CI_COMMIT_TITLE",
    "CI_COMMIT_REF_NAME", "CI_COMMIT_REF_SLUG", "CI_COMMIT_TAG",
    "CI_COMMIT_AUTHOR", "CI_COMMIT_BRANCH",
    "CI_MERGE_REQUEST_TITLE", "CI_MERGE_REQUEST_DESCRIPTION",
    "CI_MERGE_REQUEST_SOURCE_BRANCH_NAME", "CI_MERGE_REQUEST_LABELS",
    "CI_MERGE_REQUEST_ASSIGNEES", "CI_MERGE_REQUEST_MILESTONE",
    "CI_EXTERNAL_PULL_REQUEST_SOURCE_BRANCH_NAME",
})

# GitLab global keywords that are not job definitions.
_GITLAB_RESERVED = frozenset({
    "stages", "variables", "default", "include", "workflow", "image",
    "services", "cache", "before_script", "after_script", "types", "sast",
})

_SCRIPT_KEYS = ("script", "before_script", "after_script")


async def run_gitlab_ci_audit(session_id: str, source_path: str) -> dict[str, Any]:
    """Detect CI/CD attacks in GitLab pipeline files (.gitlab-ci.yml).

    v1 covers the highest-impact class — command injection via untrusted
    predefined variables in job scripts. Extensible to unmasked-secret and
    always-true-rule checks in a follow-up.
    """
    import re
    if not Path(source_path).exists():
        return {"error": "source_path does not exist"}
    try:
        import yaml
    except ImportError:
        return {"error": "pyyaml not available", "skipped": True}

    root = Path(source_path)
    files = {str(p) for p in root.rglob("*.gitlab-ci.yml") if p.is_file()}
    top = root / ".gitlab-ci.yml"
    if top.is_file():
        files.add(str(top))
    if not files:
        return {"scanner": "gitlab-ci-audit", "findings_count": 0, "findings": [],
                "skipped": "no .gitlab-ci.yml"}

    var_re = re.compile(r"\$\{?([A-Z][A-Z0-9_]*)\}?")
    findings: list[dict[str, Any]] = []
    for fp in sorted(files):
        try:
            raw = Path(fp).read_text(encoding="utf-8", errors="replace")
            doc = yaml.safe_load(raw)
        except Exception:  # noqa: BLE001 — malformed YAML: skip this file, not the scan
            continue
        if not isinstance(doc, dict):
            continue
        raw_lines = raw.splitlines()
        for job_name, job in doc.items():
            if job_name in _GITLAB_RESERVED or not isinstance(job, dict):
                continue
            for skey in _SCRIPT_KEYS:
                block = job.get(skey)
                if not block:
                    continue
                for ln in (block if isinstance(block, list) else [block]):
                    if not isinstance(ln, str):
                        continue
                    hit = next((m.group(1) for m in var_re.finditer(ln)
                                if m.group(1) in _GITLAB_UNTRUSTED_VARS), None)
                    if not hit:
                        continue
                    line_no = next((i for i, rl in enumerate(raw_lines, 1)
                                    if ln.strip() and ln.strip() in rl), None)
                    findings.append({
                        "title": "GitLab CI command injection via untrusted pipeline variable",
                        "severity": "high",
                        "category": "cicd_security",
                        "owasp_category": "A03:2021",
                        "cwe_id": "CWE-94",
                        "file_path": fp,
                        "line_start": line_no,
                        "description": (
                            f"Job {job_name!r} interpolates the attacker-controllable variable "
                            f"${hit} directly into a {skey} shell command. Attacker impact: an "
                            f"attacker who sets that value (branch/tag/commit message or merge-"
                            f"request title from a fork) injects arbitrary commands that run on "
                            f"the runner with the pipeline's CI_JOB_TOKEN and secrets — pipeline "
                            f"RCE / secret exfiltration (OWASP CICD-SEC-4)."
                        )[:1000],
                        "remediation": (
                            "Never interpolate untrusted CI variables into scripts. Bind them to "
                            "a quoted env var (e.g. `MSG: $CI_COMMIT_MESSAGE` then use \"$MSG\") "
                            "and validate/escape before use."
                        ),
                        "evidence": {"snippet": ln.strip()[:200], "variable": hit, "job": job_name},
                    })
                    # one finding per script line (next() already de-dups vars within a line)
    return {"scanner": "gitlab-ci-audit", "findings_count": len(findings), "findings": findings}


# ============================================================================
# run_yara (malware-signature matching)
# ============================================================================


async def run_yara(
    session_id: str,
    source_path: str,
    rules_path: str | None = None,
) -> dict[str, Any]:
    if not _which("yara"):
        return {"error": "binary not found: yara", "skipped": True}
    if not Path(source_path).exists():
        return {"error": "source_path does not exist"}
    if not rules_path:
        return {"error": "rules_path required (no operator-supplied YARA rules)"}
    if not Path(rules_path).exists():
        return {"error": "rules_path does not exist"}
    # YARA matches per file; -r recurses, -s prints matching strings, output is
    # newline-delimited "rule_name file" — we parse to a finding per match.
    argv = ["yara", "-r", "-s", rules_path, source_path]
    result = await _run_subprocess(argv, timeout=600)
    findings: list[dict[str, Any]] = []
    for line in (result.get("stdout") or "").splitlines():
        line = line.strip()
        if not line or line.startswith("0x") or " " not in line:
            continue
        rule_name, _, path = line.partition(" ")
        findings.append({
            "title": f"YARA rule matched: {rule_name}",
            "severity": "high",
            "category": "malware_signature",
            "owasp_category": "A08:2021",
            "file_path": path,
            "description": f"YARA rule {rule_name!r} matched.",
        })
    return {"scanner": "yara", "findings_count": len(findings), "findings": findings}


# ============================================================================
# run_osv_scanner (against a source directory — package_registry uses
# osv-scanner via a different code path on the SBOM)
# ============================================================================


async def run_osv_scanner(session_id: str, source_path: str) -> dict[str, Any]:
    if not _which("osv-scanner"):
        return {"error": "binary not found: osv-scanner", "skipped": True}
    if not Path(source_path).exists():
        return {"error": "source_path does not exist"}
    argv = ["osv-scanner", "--format", "json", "--recursive", source_path]
    result = await _run_subprocess(argv, timeout=600)
    findings = _parse_osv_source_json(result.get("stdout", ""))
    return {"scanner": "osv-scanner", "findings_count": len(findings), "findings": findings}


def _parse_osv_source_json(stdout: str) -> list[dict[str, Any]]:
    if not stdout.strip():
        return []
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return []
    findings: list[dict[str, Any]] = []
    for r in data.get("results", []) or []:
        for pkg in r.get("packages", []) or []:
            pkg_info = pkg.get("package", {})
            for vuln in pkg.get("vulnerabilities", []) or []:
                findings.append({
                    "title": f"{vuln.get('id')} in {pkg_info.get('name', 'package')}",
                    "severity": "high",  # OSV doesn't always include CVSS here
                    "category": "vulnerable_dependency",
                    "owasp_category": "A06:2021",
                    "cve": vuln.get("id"),
                    "package": pkg_info.get("name"),
                    "installed_version": pkg_info.get("version"),
                    "description": (vuln.get("summary") or vuln.get("details", ""))[:512],
                })
    return findings


__all__ = [
    "run_semgrep",
    "run_bandit",
    "run_gosec",
    "run_brakeman",
    "run_eslint",
    "run_gitleaks",
    "run_zizmor",
    "run_gitlab_ci_audit",
    "run_yara",
    "run_osv_scanner",
]
