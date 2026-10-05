"""Per-tool stdout → canonical Finding adapters.

Each registered normalizer takes the raw stdout/stderr of a tool plus the
target it was run against, and returns a list of ``Finding`` objects. A
default ``raw`` adapter is included so every tool has at least an
informational finding, even if a specialised parser doesn't exist.

Adapters can be added at runtime via ``register("toolname", fn)``.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

from pencheff.config import Severity
from pencheff.core.findings import Evidence, Finding


Normalizer = Callable[[str, str, str], list[Finding]]
# (stdout, stderr, target) → findings


_REGISTRY: dict[str, Normalizer] = {}


def register(tool: str, fn: Normalizer) -> None:
    _REGISTRY[tool] = fn


def normalize(tool: str, stdout: str, target: str, *, stderr: str = "") -> list[Finding]:
    fn = _REGISTRY.get(tool, _raw)
    try:
        return fn(stdout, stderr, target)
    except Exception as exc:  # pragma: no cover — never fail the engagement
        return [
            _info(
                title=f"{tool} parser failure",
                description=f"Could not parse output: {exc}",
                target=target,
                evidence_text=stdout[:1000] if stdout else "",
            )
        ]


# ─── built-in adapters ─────────────────────────────────────────────────
def _raw(stdout: str, stderr: str, target: str) -> list[Finding]:
    body = stdout.strip() or stderr.strip()
    if not body:
        return []
    return [_info("Tool output", body[:2000], target, evidence_text=body[:2000])]


def _nuclei(stdout: str, _stderr: str, target: str) -> list[Finding]:
    out: list[Finding] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = entry.get("info", {})
        sev_label = (info.get("severity") or "info").lower()
        sev_map = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
            "info": Severity.INFO,
        }
        out.append(
            Finding(
                title=info.get("name") or entry.get("template-id") or "nuclei finding",
                severity=sev_map.get(sev_label, Severity.INFO),
                category=info.get("classification", {}).get("cwe-id", "")
                or entry.get("type", "nuclei"),
                owasp_category=info.get("classification", {}).get("owasp-id", ""),
                description=info.get("description", ""),
                remediation=info.get("remediation", "")
                or "Apply vendor patch or recommended mitigation.",
                endpoint=entry.get("matched-at") or target,
                cwe_id=info.get("classification", {}).get("cwe-id") or None,
                references=info.get("reference", []) or [],
                evidence=[
                    Evidence(
                        request_method="GET",
                        request_url=entry.get("matched-at") or target,
                        response_body_snippet=(entry.get("matcher-name") or "")[:500],
                        description=entry.get("template-id", ""),
                    )
                ],
            )
        )
    return out


def _httpx(stdout: str, _stderr: str, target: str) -> list[Finding]:
    out: list[Finding] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        url = entry.get("url") or target
        out.append(
            _info(
                title=f"Live host: {url}",
                description=f"status={entry.get('status_code')} title={entry.get('title') or ''}",
                target=url,
                evidence_text=line[:500],
            )
        )
    return out


def _ffuf(stdout: str, _stderr: str, target: str) -> list[Finding]:
    """ffuf -of json one-line summary or full file? Accept both."""
    out: list[Finding] = []
    text = stdout.strip()
    if not text:
        return out
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return _raw(stdout, "", target)
    for entry in data.get("results", []):
        url = entry.get("url") or target
        out.append(
            _info(
                title=f"Path: {url} ({entry.get('status')})",
                description=f"len={entry.get('length')} words={entry.get('words')}",
                target=url,
                evidence_text=str(entry)[:500],
            )
        )
    return out


def _checksec(stdout: str, _stderr: str, target: str) -> list[Finding]:
    """checksec --output=json output."""
    text = stdout.strip()
    if not text:
        return []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return _raw(stdout, "", target)
    findings: list[Finding] = []
    for binary, props in data.items():
        weak = []
        if props.get("nx") == "no":
            weak.append("NX disabled")
        if props.get("canary") == "no":
            weak.append("No stack canary")
        if props.get("pie") == "no":
            weak.append("No PIE")
        if props.get("relro") in ("no", "partial"):
            weak.append(f"RELRO={props.get('relro')}")
        if not weak:
            continue
        findings.append(
            Finding(
                title=f"Binary protection weaknesses: {binary}",
                severity=Severity.MEDIUM,
                category="binary_hardening",
                owasp_category="A05",
                description="; ".join(weak),
                remediation="Recompile with -fstack-protector-strong, -fpie -pie, "
                            "-Wl,-z,relro,-z,now, and link against fortified libc.",
                endpoint=target,
                evidence=[
                    Evidence(
                        request_method="N/A",
                        request_url=binary,
                        response_body_snippet=json.dumps(props),
                        description="checksec",
                    )
                ],
            )
        )
    return findings


# ─── helpers ────────────────────────────────────────────────────────────
def _info(
    title: str,
    description: str,
    target: str,
    *,
    evidence_text: str = "",
) -> Finding:
    evidence = []
    if evidence_text:
        evidence.append(
            Evidence(
                request_method="N/A",
                request_url=target,
                response_body_snippet=evidence_text[:500],
                description=title,
            )
        )
    return Finding(
        title=title,
        severity=Severity.INFO,
        category="recon",
        owasp_category="A05",
        description=description,
        remediation="Informational; no remediation required.",
        endpoint=target,
        evidence=evidence,
    )


# Wire the built-ins.
register("nuclei", _nuclei)
register("httpx", _httpx)
register("ffuf", _ffuf)
register("checksec", _checksec)
