"""Kubernetes manifest scan — native rules + checkov + kubesec.

Native rules focus on the high-impact misconfigurations that appear in almost
every real-world cluster:
  - containers running as root (no runAsNonRoot / runAsUser: 0)
  - privileged: true
  - hostNetwork / hostPID / hostIPC
  - missing resource limits (DoS risk)
  - ImagePullPolicy: Always for immutable tags
  - Service type: LoadBalancer without explicit allowlist
  - secrets mounted as env instead of file
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from pencheff.config import Severity
from pencheff.core.findings import Evidence, Finding
from pencheff.modules.iac._tool_runner import run_json, tool_available


def scan(path: Path) -> list[Finding]:
    findings: list[Finding] = []
    files: list[Path] = []
    if path.is_dir():
        files = [p for p in path.rglob("*.y*ml") if p.is_file()]
    elif path.is_file():
        files = [path]
    for f in files:
        findings.extend(_native_rules(f))
    if tool_available("checkov") and path.exists():
        findings.extend(_checkov(path))
    return findings


def _native_rules(f: Path) -> list[Finding]:
    out: list[Finding] = []
    try:
        docs = list(yaml.safe_load_all(f.read_text())) or []
    except Exception:  # noqa: BLE001
        return out
    for doc in docs:
        if not isinstance(doc, dict):
            continue
        kind = doc.get("kind", "")
        meta = doc.get("metadata") or {}
        name = meta.get("name", "unnamed")
        loc = f"{f}:{kind}/{name}"
        spec = _pod_spec(doc)
        if spec is None:
            if kind == "Service":
                out.extend(_service_rules(doc, loc))
            continue
        if spec.get("hostNetwork"):
            out.append(_f("Pod uses hostNetwork", loc, Severity.HIGH,
                          "Remove spec.hostNetwork unless absolutely required."))
        if spec.get("hostPID"):
            out.append(_f("Pod uses hostPID", loc, Severity.HIGH,
                          "Remove spec.hostPID."))
        if spec.get("hostIPC"):
            out.append(_f("Pod uses hostIPC", loc, Severity.MEDIUM,
                          "Remove spec.hostIPC."))
        for c in spec.get("containers", []) or []:
            cloc = f"{loc}/container[{c.get('name','?')}]"
            sec = c.get("securityContext") or {}
            if sec.get("privileged"):
                out.append(_f("Container runs privileged", cloc, Severity.CRITICAL,
                              "Set securityContext.privileged: false."))
            if sec.get("runAsUser") == 0 or (not sec.get("runAsNonRoot") and spec.get("securityContext", {}).get("runAsUser") == 0):
                out.append(_f("Container runs as root", cloc, Severity.HIGH,
                              "Set securityContext.runAsNonRoot: true and runAsUser: >=1000."))
            if sec.get("allowPrivilegeEscalation", True) is not False:
                out.append(_f("allowPrivilegeEscalation not disabled", cloc, Severity.MEDIUM,
                              "Set securityContext.allowPrivilegeEscalation: false."))
            caps = (sec.get("capabilities") or {}).get("add") or []
            if "SYS_ADMIN" in caps or "NET_ADMIN" in caps:
                out.append(_f(f"Container adds dangerous capability: {caps}", cloc,
                              Severity.HIGH,
                              "Drop ALL capabilities and only add the minimum required."))
            if not c.get("resources", {}).get("limits"):
                out.append(_f("Container lacks resource limits", cloc, Severity.LOW,
                              "Set resources.limits.cpu and .memory to prevent noisy-neighbour DoS."))
            img = c.get("image", "")
            if img.endswith(":latest") or ":" not in img.rsplit("/", 1)[-1]:
                out.append(_f("Container image uses :latest (or no tag)", cloc,
                              Severity.MEDIUM,
                              "Pin images to an immutable digest (@sha256:...) or semver tag."))
            for e in c.get("env", []) or []:
                vname = (e.get("name") or "").lower()
                if any(k in vname for k in ("password", "secret", "token", "key")) and "value" in e:
                    out.append(_f(f"Plaintext secret in env '{e.get('name')}'", cloc,
                                  Severity.HIGH,
                                  "Use valueFrom.secretKeyRef or external secret manager."))
    return out


def _pod_spec(doc: dict[str, Any]) -> dict[str, Any] | None:
    kind = doc.get("kind", "")
    if kind == "Pod":
        return doc.get("spec")
    if kind in {"Deployment", "StatefulSet", "DaemonSet", "Job", "ReplicaSet"}:
        return ((doc.get("spec") or {}).get("template") or {}).get("spec")
    if kind == "CronJob":
        return (((doc.get("spec") or {}).get("jobTemplate") or {})
                .get("spec", {}).get("template", {}).get("spec"))
    return None


def _service_rules(doc: dict[str, Any], loc: str) -> list[Finding]:
    out: list[Finding] = []
    spec = doc.get("spec") or {}
    if spec.get("type") == "LoadBalancer" and not spec.get("loadBalancerSourceRanges"):
        out.append(_f(
            "LoadBalancer Service exposed without loadBalancerSourceRanges",
            loc,
            Severity.MEDIUM,
            "Restrict loadBalancerSourceRanges to known CIDRs or front the service "
            "with an Ingress + WAF.",
        ))
    return out


def _checkov(path: Path) -> list[Finding]:
    data = run_json("checkov", [
        "-d", str(path), "--framework", "kubernetes",
        "-o", "json", "--quiet", "--compact",
    ], timeout=180)
    out: list[Finding] = []
    results = (data or {}).get("results") or {}
    for item in (results.get("failed_checks") or []):
        sev = {
            "CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH,
            "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW,
        }.get((item.get("severity") or "").upper(), Severity.LOW)
        out.append(_f(
            f"checkov {item.get('check_id')}: {item.get('check_name','')}",
            f"{item.get('file_path','')}:{item.get('resource','')}",
            sev,
            item.get("guideline") or "See checkov docs.",
        ))
    return out


def _f(title: str, endpoint: str, sev: Severity, remediation: str) -> Finding:
    return Finding(
        title=title,
        severity=sev,
        category="misconfiguration",
        owasp_category="A05",
        description=title,
        remediation=remediation,
        endpoint=endpoint,
        evidence=[Evidence(
            request_method="STATIC", request_url=endpoint,
            response_status=200, description=title,
        )],
        references=[
            "https://kubernetes.io/docs/concepts/security/",
            "https://www.cisecurity.org/benchmark/kubernetes",
        ],
    )
