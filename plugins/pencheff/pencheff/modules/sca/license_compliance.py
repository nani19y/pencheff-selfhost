"""License-policy evaluation across discovered dependencies.

The default policy blocks copyleft licenses (AGPL*, GPL-3.0*, SSPL-*) and flags
anything that doesn't match an SPDX identifier in the known map.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from pencheff.config import Severity
from pencheff.core.findings import Evidence, Finding
from pencheff.modules.sca.manifest_parsers import Dep, discover_and_parse


# Minimal SPDX license classification. Expand over time.
PERMISSIVE = {
    "MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC",
    "Zlib", "Unlicense", "0BSD", "Python-2.0", "PSF-2.0",
}
WEAK_COPYLEFT = {"LGPL-2.1", "LGPL-2.1-only", "LGPL-3.0", "LGPL-3.0-only", "MPL-2.0", "EPL-2.0"}
STRONG_COPYLEFT = {
    "GPL-2.0", "GPL-2.0-only", "GPL-3.0", "GPL-3.0-only", "GPL-3.0-or-later",
    "AGPL-3.0", "AGPL-3.0-only", "AGPL-3.0-or-later", "SSPL-1.0",
}


DEFAULT_POLICY = {
    "allowed": sorted(PERMISSIVE | WEAK_COPYLEFT),
    "denied": sorted(STRONG_COPYLEFT),
    "unknown_behavior": "flag",  # flag | allow | deny
}


def load_policy(policy_file: Path | None) -> dict[str, Any]:
    if policy_file and policy_file.exists():
        try:
            return yaml.safe_load(policy_file.read_text()) or DEFAULT_POLICY
        except Exception:  # noqa: BLE001
            return DEFAULT_POLICY
    return DEFAULT_POLICY


def evaluate(
    root: Path, policy_file: Path | None = None
) -> tuple[list[Finding], dict[str, Any]]:
    deps = discover_and_parse(root)
    policy = load_policy(policy_file)
    allowed = set(policy.get("allowed") or [])
    denied = set(policy.get("denied") or [])
    unknown = policy.get("unknown_behavior", "flag")

    findings: list[Finding] = []
    counts = {"allowed": 0, "denied": 0, "unknown": 0, "unspecified": 0}
    for d in deps:
        lic = (d.license or "").strip()
        if not lic:
            counts["unspecified"] += 1
            if unknown == "deny":
                findings.append(_finding(d, lic, Severity.LOW, "unspecified"))
            continue
        # Handle "MIT OR Apache-2.0" by picking first acceptable
        for token in [t.strip() for t in _split_expr(lic)]:
            if token in denied:
                counts["denied"] += 1
                findings.append(_finding(d, token, Severity.HIGH, "denied"))
                break
            if token in allowed:
                counts["allowed"] += 1
                break
        else:
            counts["unknown"] += 1
            if unknown == "flag":
                findings.append(_finding(d, lic, Severity.LOW, "unknown"))
            elif unknown == "deny":
                findings.append(_finding(d, lic, Severity.MEDIUM, "unknown"))
    return findings, {"policy": policy, "counts": counts}


def _split_expr(expr: str) -> list[str]:
    out = []
    for part in expr.replace("(", " ").replace(")", " ").split():
        token = part.strip()
        if token and token.upper() not in {"OR", "AND", "WITH"}:
            out.append(token)
    return out


def _finding(d: Dep, license_id: str, sev: Severity, category: str) -> Finding:
    remediation_map = {
        "denied": (
            f"The {license_id} license is blocked by your org policy. "
            "Replace with a permissively-licensed alternative, negotiate a "
            "commercial license, or remove the dependency."
        ),
        "unknown": (
            f"The license '{license_id}' is not in the allow-list. "
            "Review with legal/compliance and update the policy accordingly."
        ),
        "unspecified": (
            "Package manifest did not declare a license. "
            "Contact the upstream maintainer, inspect source headers, or remove the dependency."
        ),
    }
    return Finding(
        title=f"License policy: {d.name}@{d.version} — {category} ({license_id or 'n/a'})",
        severity=sev,
        category="components",
        owasp_category="A06",
        description=(
            f"Dependency '{d.name}' ({d.ecosystem}@{d.version}) declares license "
            f"'{license_id or 'unspecified'}'. Status vs policy: {category}."
        ),
        remediation=remediation_map.get(category, "Review license."),
        endpoint=d.source_file or d.name,
        parameter=f"{d.ecosystem}:{d.name}@{d.version}",
        evidence=[Evidence(
            request_method="LICENSE",
            request_url=f"local://{d.source_file}",
            response_status=200,
            description=f"Declared license: {license_id or 'unspecified'}",
        )],
        references=[
            "https://spdx.org/licenses/",
            "https://opensource.org/licenses",
        ],
    )
