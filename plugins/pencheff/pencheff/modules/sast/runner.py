"""SAST runner — invokes installed code-scanners against an attached repo
and merges their results into the session FindingsDB.

Each repo runs in its own asyncio task (spawned by the server tools).
Within a task, scanners run sequentially to keep CPU/IO bounded. Scanners
that aren't installed are skipped silently (mirrors check_dependencies).
"""

from __future__ import annotations

import json
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pencheff.config import Severity, VerificationStatus
from pencheff.core.findings import Evidence, Finding, FindingsDB
from pencheff.core.session import AttachedRepo, PentestSession
from pencheff.core.tool_runner import run_tool, tool_available

DEFAULT_PER_TOOL_TIMEOUT = 180.0
DEFAULT_PER_REPO_TIMEOUT = 600.0

# OWASP Top 10 fallback for SAST findings without explicit mapping.
_DEFAULT_OWASP = "A04"  # Insecure Design
_SAST_CATEGORY = "sast"


# ─── Severity mapping helpers ────────────────────────────────────────


def _severity_from_label(label: str | None) -> Severity:
    if not label:
        return Severity.INFO
    s = label.lower()
    if s in ("critical", "crit"):
        return Severity.CRITICAL
    if s in ("high", "error"):
        return Severity.HIGH
    if s in ("medium", "moderate", "warning"):
        return Severity.MEDIUM
    if s in ("low", "minor"):
        return Severity.LOW
    return Severity.INFO


def _read_snippet(repo_root: Path, rel_path: str, line: int | None, span: int = 5) -> str | None:
    if not rel_path or line is None or line <= 0:
        return None
    full = (repo_root / rel_path).resolve()
    try:
        full.relative_to(repo_root.resolve())
    except (ValueError, OSError):
        return None
    if not full.is_file():
        return None
    try:
        text = full.read_text(errors="replace").splitlines()
    except OSError:
        return None
    start = max(0, line - 1 - span)
    end = min(len(text), line - 1 + span + 1)
    return "\n".join(f"{i + 1}: {text[i]}" for i in range(start, end))


def _endpoint_for(repo: AttachedRepo, rel_path: str | None) -> str:
    if rel_path:
        return f"repo://{repo.name}/{rel_path.lstrip('/')}"
    return f"repo://{repo.name}/"


def _make_finding(
    *,
    repo: AttachedRepo,
    repo_root: Path,
    tool: str,
    title: str,
    severity: Severity,
    description: str,
    remediation: str,
    rel_path: str | None,
    line: int | None = None,
    cwe: str | None = None,
    owasp: str | None = None,
    references: list[str] | None = None,
    extra_evidence: str | None = None,
    auto_fix: dict[str, Any] | None = None,
) -> Finding:
    """Build a SAST finding.

    ``auto_fix`` carries scanner-native fix metadata when the scanner emitted
    one (semgrep ``extra.fix``, pip-audit ``fix_versions``, npm-audit
    ``fixAvailable``, detect-secrets rotation hint). Persisted on the API
    side as part of the finding row so the fix-proposer can produce a
    deterministic patch without re-running the scanner.
    """
    snippet = _read_snippet(repo_root, rel_path, line) if rel_path else None
    evidence_desc = f"{tool}: {title}"
    if extra_evidence:
        evidence_desc = f"{evidence_desc} — {extra_evidence}"
    evidence = Evidence(
        request_method="SAST",
        request_url=_endpoint_for(repo, rel_path) + (f"#L{line}" if line else ""),
        response_body_snippet=snippet,
        description=evidence_desc,
    )
    if auto_fix:
        # Embed the autofix payload as an extra Evidence row so it survives
        # the existing Finding.to_dict()/serializer without changing the
        # Finding dataclass. The proposer keys on description="autofix:..."
        # to pull it back out.
        evidence_fix = Evidence(
            request_method="SAST_AUTOFIX",
            request_url=f"sast-autofix://{tool}",
            request_body=json.dumps({"tool": tool, **auto_fix})[:5000],
            description=f"autofix:{tool}",
        )
        evidence_list = [evidence, evidence_fix]
    else:
        evidence_list = [evidence]
    return Finding(
        title=title,
        severity=severity,
        category=_SAST_CATEGORY,
        owasp_category=owasp or _DEFAULT_OWASP,
        description=description,
        remediation=remediation,
        endpoint=_endpoint_for(repo, rel_path),
        parameter=str(line) if line else None,
        cvss_vector="",
        cvss_score=0.0,
        cwe_id=cwe,
        verification_status=VerificationStatus.UNVERIFIED,
        references=references or [],
        evidence=evidence_list,
        noise="quiet",
    )


# ─── Per-tool translators ────────────────────────────────────────────


def _semgrep_owasp(meta: dict[str, Any]) -> str | None:
    """Pull an OWASP A0x code out of semgrep rule metadata if present."""
    owasp = meta.get("owasp")
    if isinstance(owasp, str):
        owasp = [owasp]
    if isinstance(owasp, list):
        for item in owasp:
            if isinstance(item, str):
                # values look like "A03:2021 - Injection"
                code = item.split(":")[0].strip().upper()
                if code.startswith("A") and len(code) <= 3:
                    return code
    return None


def _semgrep_findings(stdout: str, repo: AttachedRepo, repo_root: Path) -> list[Finding]:
    if not stdout.strip():
        return []
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return []
    findings: list[Finding] = []
    for r in data.get("results") or []:
        rel = r.get("path") or ""
        try:
            rel = str(Path(rel).resolve().relative_to(repo_root.resolve()))
        except (ValueError, OSError):
            pass
        line = (r.get("start") or {}).get("line")
        extra = r.get("extra") or {}
        meta = extra.get("metadata") or {}
        sev_label = extra.get("severity") or meta.get("impact")
        message = extra.get("message") or r.get("check_id") or "Semgrep finding"
        cwe_field = meta.get("cwe")
        if isinstance(cwe_field, list):
            cwe_field = cwe_field[0] if cwe_field else None
        cwe = None
        if isinstance(cwe_field, str):
            for tok in cwe_field.split():
                if tok.upper().startswith("CWE-"):
                    cwe = tok.upper().rstrip(":")
                    break
        refs = meta.get("references") or []
        if isinstance(refs, str):
            refs = [refs]
        # Semgrep autofix: rules with `fix:` emit `extra.fix` (literal
        # replacement string) and/or `extra.fix_regex` (regex-based). Both
        # come with `start.line/end.line/start.col/end.col` for the byte
        # range to replace.
        autofix: dict[str, Any] | None = None
        fix_text = extra.get("fix")
        fix_regex = extra.get("fix_regex")
        start = r.get("start") or {}
        end = r.get("end") or {}
        if fix_text or fix_regex:
            autofix = {
                "kind": "text_replace",
                "fix": fix_text,
                "fix_regex": fix_regex,
                "start_line": start.get("line"),
                "start_col": start.get("col"),
                "end_line": end.get("line"),
                "end_col": end.get("col"),
                "rule_id": r.get("check_id"),
                "file": rel,
            }
        findings.append(
            _make_finding(
                repo=repo,
                repo_root=repo_root,
                tool="semgrep",
                title=f"[semgrep] {r.get('check_id', 'rule')}",
                severity=_severity_from_label(sev_label),
                description=message,
                remediation=meta.get("fix") or "Review the flagged code path and apply the rule's recommended remediation.",
                rel_path=rel,
                line=line,
                cwe=cwe,
                owasp=_semgrep_owasp(meta),
                references=[str(x) for x in refs if isinstance(x, str)],
                auto_fix=autofix,
            )
        )
    return findings


def _bandit_findings(stdout: str, repo: AttachedRepo, repo_root: Path) -> list[Finding]:
    if not stdout.strip():
        return []
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return []
    findings: list[Finding] = []
    for r in data.get("results") or []:
        rel = r.get("filename") or ""
        try:
            rel = str(Path(rel).resolve().relative_to(repo_root.resolve()))
        except (ValueError, OSError):
            pass
        line = r.get("line_number")
        sev = _severity_from_label(r.get("issue_severity"))
        confidence = r.get("issue_confidence", "MEDIUM")
        test_id = r.get("test_id", "")
        text = r.get("issue_text", "Bandit finding")
        cwe_field = r.get("issue_cwe", {}).get("id")
        cwe = f"CWE-{cwe_field}" if cwe_field else None
        findings.append(
            _make_finding(
                repo=repo,
                repo_root=repo_root,
                tool="bandit",
                title=f"[bandit] {test_id}: {r.get('test_name', 'security issue')}",
                severity=sev,
                description=f"{text} (confidence: {confidence})",
                remediation="Review the flagged code; bandit's documentation explains safe alternatives for each test ID.",
                rel_path=rel,
                line=line,
                cwe=cwe,
                extra_evidence=r.get("code"),
            )
        )
    return findings


def _detect_secrets_findings(stdout: str, repo: AttachedRepo, repo_root: Path) -> list[Finding]:
    if not stdout.strip():
        return []
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return []
    findings: list[Finding] = []
    for rel, hits in (data.get("results") or {}).items():
        for hit in hits:
            findings.append(
                _make_finding(
                    repo=repo,
                    repo_root=repo_root,
                    tool="detect-secrets",
                    title=f"Hardcoded secret: {hit.get('type', 'Unknown')}",
                    severity=Severity.HIGH,
                    description=(
                        f"detect-secrets flagged a potential {hit.get('type', 'secret')} "
                        f"at {rel}:{hit.get('line_number')} (hash: {hit.get('hashed_secret', 'n/a')[:12]}...)."
                    ),
                    remediation="Rotate the credential immediately, remove it from version control history, "
                                "and load secrets from environment variables or a secrets manager.",
                    rel_path=rel,
                    line=hit.get("line_number"),
                    cwe="CWE-798",
                    owasp="A07",
                )
            )
    return findings


def _pip_audit_findings(stdout: str, repo: AttachedRepo, repo_root: Path) -> list[Finding]:
    if not stdout.strip():
        return []
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return []
    # pip-audit json shape: {"dependencies": [{name, version, vulns: [...]}]}
    deps = data.get("dependencies") if isinstance(data, dict) else data
    findings: list[Finding] = []
    for dep in deps or []:
        name = dep.get("name") or "unknown"
        version = dep.get("version") or "?"
        for vuln in dep.get("vulns") or []:
            vid = vuln.get("id") or "VULN"
            sev = _severity_from_label(vuln.get("severity"))
            if sev is Severity.INFO:
                # pip-audit often omits severity; treat unknowns as MEDIUM
                sev = Severity.MEDIUM
            fix_versions = vuln.get("fix_versions") or []
            fix_text = (
                f"Upgrade {name} to {', '.join(fix_versions)}."
                if fix_versions
                else f"No fixed version published for {vid}; consider replacing the dependency or applying a workaround."
            )
            findings.append(
                _make_finding(
                    repo=repo,
                    repo_root=repo_root,
                    tool="pip-audit",
                    title=f"Vulnerable dependency: {name} {version} ({vid})",
                    severity=sev,
                    description=vuln.get("description") or f"{vid} affects {name} {version}.",
                    remediation=fix_text,
                    rel_path="requirements.txt",
                    line=None,
                    owasp="A06",
                    references=vuln.get("aliases") or [],
                )
            )
    return findings


def _npm_audit_findings(stdout: str, repo: AttachedRepo, repo_root: Path) -> list[Finding]:
    if not stdout.strip():
        return []
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return []
    findings: list[Finding] = []
    # npm audit v7+ shape: {"vulnerabilities": {pkg: {severity, via, fixAvailable, ...}}}
    vulns = (data.get("vulnerabilities") or {}) if isinstance(data, dict) else {}
    for pkg, info in vulns.items():
        sev = _severity_from_label(info.get("severity"))
        via = info.get("via")
        advisory_titles: list[str] = []
        if isinstance(via, list):
            for v in via:
                if isinstance(v, dict) and v.get("title"):
                    advisory_titles.append(v["title"])
        title = (
            advisory_titles[0]
            if advisory_titles
            else f"Vulnerable npm dependency: {pkg}"
        )
        fix = info.get("fixAvailable")
        if isinstance(fix, dict):
            fix_text = f"Upgrade to {fix.get('name')}@{fix.get('version')} (npm audit fix)."
        elif fix is True:
            fix_text = "Run `npm audit fix` to apply available fixes."
        else:
            fix_text = "No automatic fix available; review the advisory and pin to a safe version."
        findings.append(
            _make_finding(
                repo=repo,
                repo_root=repo_root,
                tool="npm-audit",
                title=f"[npm-audit] {pkg}: {title}",
                severity=sev,
                description=f"npm audit reports advisories on {pkg}: {', '.join(advisory_titles) or 'see npm advisory database'}.",
                remediation=fix_text,
                rel_path="package.json",
                line=None,
                owasp="A06",
            )
        )
    return findings


# ─── Runner ──────────────────────────────────────────────────────────


class SastRunner:
    """Execute installed SAST scanners against a single AttachedRepo."""

    def __init__(
        self,
        repo: AttachedRepo,
        per_tool_timeout: float = DEFAULT_PER_TOOL_TIMEOUT,
    ):
        self.repo = repo
        self.repo_root = Path(repo.path).resolve()
        self.per_tool_timeout = per_tool_timeout
        self.tools_run: list[str] = []
        self.tools_skipped: list[str] = []

    # Permissively-licensed Semgrep Registry packs only — no Pro rules.
    # Override per-deployment via the PENCHEFF_SEMGREP_PACKS env var
    # (comma-separated). Matches the API-side runner at
    # ``bench/runners/semgrep.sh`` so the SaaS worker and the MCP plugin
    # always run the same rule corpus.
    _DEFAULT_SEMGREP_PACKS = (
        "p/owasp-top-ten,p/security-audit,p/cwe-top-25,p/secrets,"
        "p/jwt,p/django,p/flask,p/express,p/nodejs,p/golang,"
        "p/r2c-security-audit"
    )

    async def _run_semgrep(self) -> list[Finding]:
        import os
        if not tool_available("semgrep"):
            self.tools_skipped.append("semgrep")
            return []
        packs_env = os.environ.get("PENCHEFF_SEMGREP_PACKS") or self._DEFAULT_SEMGREP_PACKS
        config_args: list[str] = []
        for pack in packs_env.split(","):
            pack = pack.strip()
            if not pack:
                continue
            config_args.extend(["--config", pack])
        if not config_args:
            self.tools_skipped.append("semgrep")
            return []
        result = await run_tool(
            ["semgrep", *config_args, "--json", "--quiet", "--metrics", "off",
             "--timeout", "30", str(self.repo_root)],
            timeout=self.per_tool_timeout,
        )
        self.tools_run.append("semgrep")
        return _semgrep_findings(result.stdout, self.repo, self.repo_root)

    async def _run_bandit(self) -> list[Finding]:
        if not tool_available("bandit"):
            self.tools_skipped.append("bandit")
            return []
        # Only run bandit if there's any Python in the tree
        if not any(self.repo_root.rglob("*.py")):
            self.tools_skipped.append("bandit")
            return []
        result = await run_tool(
            ["bandit", "-r", str(self.repo_root), "-f", "json", "-q"],
            timeout=self.per_tool_timeout,
        )
        self.tools_run.append("bandit")
        return _bandit_findings(result.stdout, self.repo, self.repo_root)

    async def _run_detect_secrets(self) -> list[Finding]:
        if not tool_available("detect-secrets"):
            self.tools_skipped.append("detect-secrets")
            return []
        result = await run_tool(
            ["detect-secrets", "scan", str(self.repo_root)],
            timeout=self.per_tool_timeout,
        )
        self.tools_run.append("detect-secrets")
        return _detect_secrets_findings(result.stdout, self.repo, self.repo_root)

    async def _run_pip_audit(self) -> list[Finding]:
        if not tool_available("pip-audit"):
            self.tools_skipped.append("pip-audit")
            return []
        if not (
            (self.repo_root / "requirements.txt").is_file()
            or (self.repo_root / "pyproject.toml").is_file()
        ):
            self.tools_skipped.append("pip-audit")
            return []
        # Prefer requirements.txt mode for portability; fall back to project mode.
        args = ["pip-audit", "--format", "json"]
        if (self.repo_root / "requirements.txt").is_file():
            args += ["-r", str(self.repo_root / "requirements.txt")]
        else:
            args += [str(self.repo_root)]
        result = await run_tool(args, timeout=self.per_tool_timeout)
        self.tools_run.append("pip-audit")
        return _pip_audit_findings(result.stdout, self.repo, self.repo_root)

    async def _run_npm_audit(self) -> list[Finding]:
        if not tool_available("npm"):
            self.tools_skipped.append("npm-audit")
            return []
        if not (self.repo_root / "package.json").is_file():
            self.tools_skipped.append("npm-audit")
            return []
        # `npm audit` requires either a lockfile or running install first; respect
        # whatever the repo ships with (no implicit install).
        if not any(
            (self.repo_root / lf).is_file()
            for lf in ("package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml")
        ):
            self.tools_skipped.append("npm-audit")
            return []
        # Run from the repo root via subprocess args; tool_runner doesn't pass cwd, so
        # rely on the absolute --prefix flag instead.
        result = await run_tool(
            ["npm", "audit", "--json", "--prefix", str(self.repo_root)],
            timeout=self.per_tool_timeout,
        )
        self.tools_run.append("npm-audit")
        return _npm_audit_findings(result.stdout, self.repo, self.repo_root)

    async def _run_treesitter_queries(self) -> list[Finding]:
        """Phase 2.3 — tree-sitter SAST sub-packs (Solidity / Lua /
        Scala / Dart / Kotlin / Swift / …).

        Per-language sub-packs live under ``treesitter_pack/<lang>/``.
        Each is gracefully skipped when ``tree_sitter`` or its language
        grammar isn't installed so the SAST pass never blocks on an
        optional dependency.
        """
        from .treesitter_pack import (
            available_subpacks, is_treesitter_available, run_subpack,
        )

        if not is_treesitter_available():
            self.tools_skipped.append("treesitter")
            return []

        ran_at_least_one = False
        findings: list[Finding] = []
        for sp in available_subpacks():
            if not sp.available:
                self.tools_skipped.append(f"treesitter:{sp.name}")
                continue
            ran_at_least_one = True
            self.tools_run.append(f"treesitter:{sp.name}")
            for raw in run_subpack(sp, self.repo_root):
                findings.append(
                    _make_finding(
                        repo=self.repo,
                        repo_root=self.repo_root,
                        tool=raw["scanner"],
                        title=f"[{raw['scanner']}] {raw['title']}",
                        severity=_severity_from_label(raw.get("severity")),
                        description=raw.get("description") or "",
                        remediation=(raw.get("raw") or {}).get("rule", {}).get(
                            "remediation",
                            "Review the flagged code path and follow the rule's "
                            "remediation guidance.",
                        ),
                        rel_path=raw.get("file_path"),
                        line=raw.get("line_start"),
                        cwe=(raw.get("raw") or {}).get("rule", {}).get("cwe"),
                        extra_evidence=raw.get("code_snippet"),
                    )
                )
        if not ran_at_least_one:
            self.tools_skipped.append("treesitter")
        return findings

    async def run_all(self) -> list[Finding]:
        findings: list[Finding] = []
        for runner in (
            self._run_semgrep,
            self._run_bandit,
            self._run_detect_secrets,
            self._run_pip_audit,
            self._run_npm_audit,
            self._run_treesitter_queries,
        ):
            try:
                findings.extend(await runner())
            except Exception:
                # A single tool blowing up shouldn't kill the whole SAST pass.
                continue
        return findings


async def run_sast_for_repo(
    session: PentestSession,
    repo: AttachedRepo,
    per_tool_timeout: float = DEFAULT_PER_TOOL_TIMEOUT,
) -> dict[str, Any]:
    """Run SAST against ``repo`` and merge findings into ``session.findings``.

    Updates ``session.sast_task_state[repo.name]`` throughout. Designed to be
    spawned as an asyncio task so DAST modules can run in parallel.
    """
    state = session.sast_task_state.setdefault(repo.name, {})
    state.update({
        "status": "running",
        "started_at": datetime.now(timezone.utc).isoformat(),
        "finished_at": None,
        "finding_count": 0,
        "tools_run": [],
        "tools_skipped": [],
        "error": None,
    })

    runner = SastRunner(repo, per_tool_timeout=per_tool_timeout)
    if not Path(repo.path).is_dir():
        state.update({
            "status": "error",
            "finished_at": datetime.now(timezone.utc).isoformat(),
            "error": f"Repo path no longer exists: {repo.path}",
        })
        return state

    try:
        findings = await runner.run_all()
        added = session.findings.add_many(findings) if findings else 0
        state.update({
            "status": "done",
            "finished_at": datetime.now(timezone.utc).isoformat(),
            "finding_count": added,
            "tools_run": list(runner.tools_run),
            "tools_skipped": list(runner.tools_skipped),
            "error": None,
        })
    except Exception as exc:
        state.update({
            "status": "error",
            "finished_at": datetime.now(timezone.utc).isoformat(),
            "tools_run": list(runner.tools_run),
            "tools_skipped": list(runner.tools_skipped),
            "error": f"{type(exc).__name__}: {exc}",
        })
    return state


def installed_sast_tools() -> dict[str, bool]:
    """Quick probe of which SAST tools are available — used by status APIs."""
    return {name: shutil.which(name) is not None for name in (
        "semgrep", "bandit", "detect-secrets", "pip-audit", "npm",
    )}
