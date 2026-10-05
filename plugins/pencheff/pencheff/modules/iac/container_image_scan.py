"""Container image scanning via trivy + grype (optional) + native secret grep."""

from __future__ import annotations

from typing import Any

from pencheff.config import Severity
from pencheff.core.findings import Evidence, Finding
from pencheff.modules.iac._tool_runner import run_json, tool_available


def scan(image_ref: str) -> list[Finding]:
    findings: list[Finding] = []
    if tool_available("trivy"):
        findings.extend(_trivy(image_ref))
    elif tool_available("grype"):
        findings.extend(_grype(image_ref))
    else:
        findings.append(Finding(
            title=f"Container scan skipped — neither trivy nor grype installed",
            severity=Severity.INFO,
            category="components",
            owasp_category="A06",
            description="Install `trivy` or `grype` to enable container image vuln scanning.",
            remediation="brew install aquasecurity/trivy/trivy  (or)  brew install grype",
            endpoint=image_ref,
        ))
    return findings


def _trivy(image_ref: str) -> list[Finding]:
    data = run_json("trivy", [
        "image", "-f", "json", "--quiet", "--scanners", "vuln,secret,misconfig",
        image_ref,
    ], timeout=300)
    if not isinstance(data, dict):
        return []
    out: list[Finding] = []
    for res in data.get("Results") or []:
        for vuln in res.get("Vulnerabilities") or []:
            out.append(_vuln_finding(vuln, image_ref))
        for sec in res.get("Secrets") or []:
            out.append(Finding(
                title=f"Secret in image: {sec.get('Title','')}",
                severity=Severity.HIGH,
                category="components",
                owasp_category="A08",
                description=sec.get("Match", "")[:500],
                remediation=(
                    "Rotate the leaked secret. Rebuild the image using BuildKit --secret or "
                    "runtime env injection. Purge all layers that contain the secret."
                ),
                endpoint=f"{image_ref}:{sec.get('StartLine','')}",
                evidence=[Evidence(
                    request_method="TRIVY", request_url=image_ref,
                    response_status=200, description=sec.get("Match", "")[:200],
                )],
            ))
        for miscfg in res.get("Misconfigurations") or []:
            sev = _trivy_sev(miscfg.get("Severity", ""))
            out.append(Finding(
                title=f"Image misconfig {miscfg.get('ID','')}: {miscfg.get('Title','')}",
                severity=sev,
                category="misconfiguration",
                owasp_category="A05",
                description=miscfg.get("Description") or "",
                remediation=miscfg.get("Resolution") or "See trivy docs.",
                endpoint=image_ref,
            ))
    return out


def _grype(image_ref: str) -> list[Finding]:
    data = run_json("grype", [image_ref, "-o", "json"], timeout=300)
    if not isinstance(data, dict):
        return []
    out: list[Finding] = []
    for m in data.get("matches") or []:
        v = m.get("vulnerability") or {}
        art = m.get("artifact") or {}
        sev = _trivy_sev((v.get("severity") or "").upper())
        out.append(Finding(
            title=f"{art.get('name','')}@{art.get('version','')} — {v.get('id','')}",
            severity=sev,
            category="components",
            owasp_category="A06",
            description=v.get("description") or "",
            remediation=(
                f"Upgrade {art.get('name','')} to {', '.join(v.get('fix',{}).get('versions', [])) or 'a patched release'}."
            ),
            endpoint=image_ref,
            parameter=f"{art.get('type','')}:{art.get('name','')}@{art.get('version','')}",
            cvss_score=_extract_cvss(v),
            references=[u for u in (v.get("urls") or []) if u][:5],
        ))
    return out


def _vuln_finding(v: dict[str, Any], image_ref: str) -> Finding:
    sev = _trivy_sev(v.get("Severity", ""))
    fixed = v.get("FixedVersion") or "no fixed version yet"
    return Finding(
        title=f"{v.get('PkgName','')}@{v.get('InstalledVersion','')} — {v.get('VulnerabilityID','')}",
        severity=sev,
        category="components",
        owasp_category="A06",
        description=(v.get("Description") or "")[:600],
        remediation=(
            f"Upgrade {v.get('PkgName','')} to {fixed}. "
            "Rebuild and redeploy the container image."
        ),
        endpoint=image_ref,
        parameter=f"{v.get('PkgName','')}@{v.get('InstalledVersion','')}",
        cvss_score=_cvss_from_trivy(v),
        references=[r for r in (v.get("References") or []) if r][:5],
    )


def _trivy_sev(sev: str) -> Severity:
    return {
        "CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH,
        "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW,
        "UNKNOWN": Severity.INFO, "NEGLIGIBLE": Severity.INFO,
    }.get((sev or "").upper(), Severity.INFO)


def _cvss_from_trivy(v: dict[str, Any]) -> float:
    for key in ("nvd", "redhat", "ghsa"):
        score = (((v.get("CVSS") or {}).get(key) or {}).get("V3Score"))
        if score:
            try:
                return float(score)
            except (TypeError, ValueError):
                continue
    return 0.0


def _extract_cvss(v: dict[str, Any]) -> float:
    for s in v.get("cvss") or []:
        metrics = s.get("metrics") or {}
        if metrics.get("baseScore"):
            try:
                return float(metrics["baseScore"])
            except (TypeError, ValueError):
                continue
    return 0.0
