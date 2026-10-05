"""Terraform (HCL) scan — native pattern rules + checkov + tfsec.

Native rules are intentionally narrow; they catch "smoke alarm" issues that
should never ship, regardless of whether checkov / tfsec is installed:
  - AWS S3 bucket with public-read / public-read-write ACL
  - Security groups opening 0.0.0.0/0 to 22/3389/3306/1433
  - Unencrypted RDS / EBS / S3
  - IAM policies with Action "*" and Resource "*"
  - Hardcoded AWS access key patterns
"""

from __future__ import annotations

import re
from pathlib import Path

from pencheff.config import Severity
from pencheff.core.findings import Evidence, Finding
from pencheff.modules.iac._tool_runner import run_json, tool_available


AWS_ACCESS_KEY_RE = re.compile(r"(?:AKIA|ASIA|AGPA|AROA|AIDA|ANPA|ANVA)[A-Z0-9]{16}")
PUBLIC_CIDR_RE = re.compile(r'"0\.0\.0\.0/0"')
DANGEROUS_PORTS = {"22", "3389", "3306", "1433", "5432", "6379", "27017"}


def scan(path: Path) -> list[Finding]:
    findings: list[Finding] = []
    if path.is_dir():
        files = [p for p in path.rglob("*.tf") if p.is_file()]
    elif path.suffix == ".tf":
        files = [path]
    else:
        files = []
    for f in files:
        findings.extend(_native_rules(f))
    for tool in ("tfsec", "checkov"):
        if tool_available(tool) and path.exists():
            findings.extend(_run_external(tool, path))
    return findings


def _native_rules(f: Path) -> list[Finding]:
    out: list[Finding] = []
    try:
        text = f.read_text()
    except Exception:  # noqa: BLE001
        return out

    for m in AWS_ACCESS_KEY_RE.finditer(text):
        line = text[:m.start()].count("\n") + 1
        out.append(_f(
            "Hardcoded AWS access key in Terraform",
            f"{f}:{line}",
            Severity.CRITICAL,
            "Remove the key from source, rotate it immediately, and use IAM roles or "
            "an external secret source (Vault, AWS Secrets Manager).",
            m.group(0),
        ))

    for m in re.finditer(r'acl\s*=\s*"(public-read|public-read-write)"', text):
        line = text[:m.start()].count("\n") + 1
        out.append(_f(
            f"S3 bucket ACL set to {m.group(1)}",
            f"{f}:{line}",
            Severity.HIGH,
            "Set acl = \"private\" and use bucket policies or CloudFront for public assets.",
            m.group(0),
        ))

    # 0.0.0.0/0 ingress on dangerous port
    for m in re.finditer(
        r"ingress\s*{[^}]*?from_port\s*=\s*(\d+)[^}]*?cidr_blocks\s*=\s*\[\s*\"0\.0\.0\.0/0\"",
        text, flags=re.DOTALL,
    ):
        port = m.group(1)
        line = text[:m.start()].count("\n") + 1
        sev = Severity.CRITICAL if port in DANGEROUS_PORTS else Severity.HIGH
        out.append(_f(
            f"Security group opens port {port} to 0.0.0.0/0",
            f"{f}:{line}",
            sev,
            f"Restrict cidr_blocks to a known allowlist; do not expose port {port} to the public internet.",
            "",
        ))

    for m in re.finditer(r'(storage_encrypted|encrypted)\s*=\s*false', text):
        line = text[:m.start()].count("\n") + 1
        out.append(_f(
            "Encryption disabled on AWS resource",
            f"{f}:{line}",
            Severity.HIGH,
            "Set encryption to true (or remove to inherit default). Rotate any plaintext snapshots.",
            m.group(0),
        ))

    for m in re.finditer(r'"Action"\s*:\s*"\*"[^}]*"Resource"\s*:\s*"\*"', text, flags=re.DOTALL):
        line = text[:m.start()].count("\n") + 1
        out.append(_f(
            "Overly permissive IAM policy (Action:* Resource:*)",
            f"{f}:{line}",
            Severity.HIGH,
            "Replace with least-privilege actions and resources scoped to the specific ARNs.",
            m.group(0)[:200],
        ))
    return out


def _run_external(tool: str, path: Path) -> list[Finding]:
    if tool == "tfsec":
        data = run_json("tfsec", [str(path), "--format", "json", "--no-colour"], timeout=120)
        return _tfsec_parse(data)
    if tool == "checkov":
        data = run_json("checkov", [
            "-d", str(path), "--framework", "terraform",
            "-o", "json", "--quiet", "--compact",
        ], timeout=180)
        return _checkov_parse(data)
    return []


def _tfsec_parse(data: dict | None) -> list[Finding]:
    if not isinstance(data, dict):
        return []
    out: list[Finding] = []
    for item in data.get("results") or []:
        sev = {
            "CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH,
            "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW,
        }.get((item.get("severity") or "").upper(), Severity.LOW)
        loc = item.get("location") or {}
        out.append(_f(
            f"tfsec {item.get('rule_id','')}: {item.get('description','')}",
            f"{loc.get('filename','')}:{loc.get('start_line',0)}",
            sev,
            item.get("resolution") or item.get("impact") or "See tfsec docs.",
            item.get("description") or "",
        ))
    return out


def _checkov_parse(data: dict | None) -> list[Finding]:
    if not isinstance(data, dict):
        return []
    out: list[Finding] = []
    results = data.get("results") or {}
    for item in results.get("failed_checks") or []:
        sev = {
            "CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH,
            "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW,
        }.get((item.get("severity") or "").upper(), Severity.LOW)
        out.append(_f(
            f"checkov {item.get('check_id')}: {item.get('check_name','')}",
            f"{item.get('file_path','')}:{item.get('resource','')}",
            sev,
            item.get("guideline") or "See checkov docs.",
            "",
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
            request_method="STATIC", request_url=endpoint,
            response_status=200, description=snippet[:500] if snippet else title,
        )],
        references=[
            "https://aquasecurity.github.io/tfsec/",
            "https://www.checkov.io/",
        ],
    )
