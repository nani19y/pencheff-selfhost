# pencheff/modules/mcp_scan/fingerprint.py
"""Match an McpManifest (+ launch command) against pinned known-vuln MCP
implementations. Version-pinned and refreshable (advisories.yaml)."""
from __future__ import annotations

import re
from importlib.resources import files

import yaml

from pencheff.config import Severity
from pencheff.core.findings import Finding

from .manifest import McpManifest

_SEV = {
    "critical": Severity.CRITICAL, "high": Severity.HIGH,
    "medium": Severity.MEDIUM, "low": Severity.LOW, "info": Severity.INFO,
}
_VER_RE = re.compile(r"(\d+)\.(\d+)\.(\d+)")
_cache: list[dict] | None = None


def _load() -> list[dict]:
    global _cache
    if _cache is None:
        text = files("pencheff.modules.mcp_scan").joinpath("advisories.yaml").read_text("utf-8")
        _cache = yaml.safe_load(text) or []
    return _cache


def _parse_ver(s: str | None) -> tuple[int, int, int] | None:
    if not s:
        return None
    m = _VER_RE.search(s)
    return (int(m[1]), int(m[2]), int(m[3])) if m else None


def fingerprint(mf: McpManifest, command: list[str] | None) -> list[Finding]:
    cmd_blob = " ".join(command) if command else ""
    haystacks = [mf.server_name or "", cmd_blob, mf.endpoint or ""]
    out: list[Finding] = []
    for adv in _load():
        pat = adv["name_match"]
        matched_in = next((h for h in haystacks if h and re.search(pat, h)), None)
        if not matched_in:
            continue
        below = adv.get("vulnerable_below")
        if below:
            detected = _parse_ver(mf.server_version) or _parse_ver(cmd_blob) or _parse_ver(matched_in)
            want = _parse_ver(below)
            # Only flag when we detected a version AND it is below the fix.
            if detected is None or want is None or detected >= want:
                continue
        out.append(Finding(
            title=adv["title"],
            severity=_SEV.get(adv.get("severity", "high"), Severity.HIGH),
            category="mcp_known_vuln",
            owasp_category="LLM05",
            description=adv["description"],
            remediation=adv["remediation"],
            endpoint=mf.endpoint,
            cwe_id=adv.get("cwe"),
            references=[adv["reference"]] if adv.get("reference") else [],
            metadata={"technique": "mcp:known-vuln", "cve": adv.get("cve"),
                      "cvss": adv.get("cvss"), "matched": matched_in},
        ))
    return out
