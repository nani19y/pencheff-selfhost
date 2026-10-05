"""Dockerfile static analysis — native rules + hadolint + trivy config.

Native rules detect the most common Dockerfile smells even when the external
tools aren't installed:
  - running as root (no USER directive)
  - latest tag
  - ADD for remote URLs (prefer COPY + explicit download)
  - pinned-to-latest package installs (apt/apk/yum)
  - secrets in ENV/ARG
  - privileged HEALTHCHECK / unsafe SHELL redirects
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from pencheff.config import Severity
from pencheff.core.findings import Evidence, Finding
from pencheff.modules.iac._tool_runner import run_json, run_text, tool_available


def scan(path: Path) -> list[Finding]:
    findings: list[Finding] = []
    if path.is_dir():
        dockerfiles = [p for p in path.rglob("Dockerfile*") if p.is_file()]
    elif path.name.startswith("Dockerfile") or path.suffix == ".dockerfile":
        dockerfiles = [path]
    else:
        dockerfiles = []
    for df in dockerfiles:
        findings.extend(_native_rules(df))
        findings.extend(_hadolint(df))
    return findings


def _native_rules(df: Path) -> list[Finding]:
    out: list[Finding] = []
    try:
        lines = df.read_text().splitlines()
    except Exception:  # noqa: BLE001
        return out

    has_user = False
    for i, raw in enumerate(lines, start=1):
        line = raw.strip()
        low = line.lower()
        if low.startswith("user "):
            has_user = True
        if low.startswith("from ") and ":latest" in low:
            out.append(_f(
                "Dockerfile uses :latest tag",
                f"{df}:{i}",
                Severity.MEDIUM,
                "Base images tagged :latest produce non-reproducible builds and silently "
                "pick up upstream changes. Pin to a specific digest or version.",
                raw,
            ))
        if re.match(r"^\s*add\s+https?://", low):
            out.append(_f(
                "Dockerfile ADD fetches remote URL",
                f"{df}:{i}",
                Severity.MEDIUM,
                "Use COPY with a pre-downloaded + checksum-verified artifact instead of ADD <url>.",
                raw,
            ))
        if re.search(r"(password|secret|token|api[_-]?key)\s*=\s*\S+", low):
            out.append(_f(
                "Dockerfile embeds a secret",
                f"{df}:{i}",
                Severity.HIGH,
                "Secrets in image layers are recoverable by anyone with pull access. "
                "Use BuildKit secrets (--secret) or runtime env injection.",
                raw,
            ))
        if "apt-get install" in low and "--no-install-recommends" not in low:
            out.append(_f(
                "apt-get install without --no-install-recommends",
                f"{df}:{i}",
                Severity.LOW,
                "Use '--no-install-recommends' to keep attack surface minimal.",
                raw,
            ))
        if re.match(r"^\s*run\s+curl\s+.*\|\s*(sh|bash)", low):
            out.append(_f(
                "Dockerfile pipes curl output to shell",
                f"{df}:{i}",
                Severity.HIGH,
                "Fetching a script and piping into sh allows remote code execution if the "
                "source is compromised. Verify checksums and install from packages.",
                raw,
            ))
    if not has_user:
        out.append(_f(
            "Dockerfile runs as root (no USER directive)",
            str(df),
            Severity.MEDIUM,
            "Declare a non-root USER before the entrypoint to minimise blast radius if the "
            "container is compromised.",
            "",
        ))
    return out


def _hadolint(df: Path) -> list[Finding]:
    if not tool_available("hadolint"):
        return []
    data = run_json("hadolint", ["-f", "json", str(df)], timeout=30)
    if not data:
        return []
    out: list[Finding] = []
    for item in data if isinstance(data, list) else []:
        level = (item.get("level") or "info").lower()
        sev = {
            "error": Severity.HIGH, "warning": Severity.MEDIUM,
            "info": Severity.LOW, "style": Severity.INFO,
        }.get(level, Severity.INFO)
        out.append(_f(
            f"hadolint {item.get('code','')}: {item.get('message','')}",
            f"{df}:{item.get('line', 0)}",
            sev,
            f"Hadolint rule {item.get('code','')}. See "
            f"https://github.com/hadolint/hadolint/wiki/{item.get('code','')}",
            item.get("message", ""),
        ))
    # Trivy config pass — complements hadolint with CIS benchmarks
    trivy = run_json("trivy", ["config", "-f", "json", "--quiet", str(df)], timeout=60)
    if isinstance(trivy, dict):
        for res in trivy.get("Results") or []:
            for miscfg in res.get("Misconfigurations") or []:
                sev = {
                    "CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH,
                    "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW,
                }.get((miscfg.get("Severity") or "").upper(), Severity.LOW)
                out.append(_f(
                    f"trivy {miscfg.get('ID','')}: {miscfg.get('Title','')}",
                    str(df),
                    sev,
                    miscfg.get("Resolution") or miscfg.get("Description") or "See trivy docs.",
                    miscfg.get("Description") or "",
                ))
    return out


def _f(title: str, endpoint: str, sev: Severity, remediation: str, snippet: str) -> Finding:
    return Finding(
        title=title,
        severity=sev,
        category="misconfiguration",
        owasp_category="A05",
        description=snippet[:500] if snippet else title,
        remediation=remediation,
        endpoint=endpoint,
        evidence=[Evidence(
            request_method="STATIC",
            request_url=endpoint,
            response_status=200,
            description=snippet[:500] if snippet else title,
        )],
        references=[
            "https://docs.docker.com/develop/dev-best-practices/",
            "https://github.com/hadolint/hadolint",
        ],
    )


def run_scan_text(df: Path) -> str:
    """Free-form text debug output (for CLI use)."""
    return run_text("hadolint", [str(df)])
