"""Browser-extension (CRX/XPI) static analyzer — manifest permission/CSP scoring,
remote-code & DOM-sink detection, hardcoded secrets. Pure-static, no browser."""

from __future__ import annotations

import json
import re
import tempfile
from pathlib import Path

from pencheff.config import Severity
from pencheff.core.findings import Evidence, Finding
from pencheff.modules.client._common import (
    crx_to_zip_bytes,
    iter_text_files,
    safe_unzip,
    secrets_sweep,
)

CATEGORY = "extension_misconfig"

# Permission → (severity, why). Scored by how much reach the permission grants.
_CRITICAL_PERMS = {
    "debugger": "attach the Chrome DevTools debugger to ANY page/extension",
    "<all_urls>": "read/modify data on every site the user visits",
    "cookies": "read/exfiltrate cookies (incl. session tokens)",
    "proxy": "redirect all browser traffic through an attacker proxy",
}
_HIGH_PERMS = {
    "tabs": "read URLs/titles of all open tabs",
    "nativeMessaging": "talk to a native host binary outside the sandbox",
    "management": "enumerate/disable other extensions",
    "history": "read the full browsing history",
    "downloads": "trigger/observe file downloads",
    "webRequestBlocking": "intercept and modify network requests (MV2)",
    "bookmarks": "read all bookmarks",
}
_BROAD_HOST = re.compile(r"^(<all_urls>|\*://\*/?\*?|https?://\*/?\*?|\*://)")

# DOM/JS sinks worth flagging (AST-lite — regex with a non-literal-arg bias).
_SINKS = [
    ("eval()", re.compile(r"\beval\s*\("), "CWE-95",
     "Dynamic code execution via eval()"),
    ("new Function()", re.compile(r"\bnew\s+Function\s*\("), "CWE-95",
     "Dynamic code execution via the Function constructor"),
    ("innerHTML assignment", re.compile(r"\.innerHTML\s*="), "CWE-79",
     "HTML injection sink (.innerHTML)"),
    ("document.write()", re.compile(r"\bdocument\.write(ln)?\s*\("), "CWE-79",
     "HTML injection sink (document.write)"),
    ("remote code load", re.compile(r"""importScripts\s*\(\s*["']https?://|<script[^>]+src\s*=\s*["']https?://"""), "CWE-829",
     "Loads remotely-hosted code — banned under MV3 and a classic supply-chain vector"),
    ("external message handler", re.compile(r"onMessageExternal"), "CWE-749",
     "Accepts messages from other extensions/pages (runtime.onMessageExternal)"),
]


def _has_broad(values) -> bool:
    return any(isinstance(v, str) and _BROAD_HOST.match(v) for v in (values or []))


def unpack_extension(path: str) -> str | None:
    """Unpack a CRX/XPI/ZIP extension to a temp dir; return the dir or None."""
    try:
        raw = Path(path).read_bytes()
    except OSError:
        return None
    zip_bytes = crx_to_zip_bytes(raw)
    if zip_bytes is None:
        return None
    dest = Path(tempfile.mkdtemp(prefix="pencheff_ext_"))
    return safe_unzip(zip_bytes, dest)


def _analyze_manifest(ext_dir: Path, label: str) -> list[Finding]:
    mpath = ext_dir / "manifest.json"
    if not mpath.is_file():
        return [Finding(
            title="No manifest.json — not a valid extension package",
            severity=Severity.INFO, category=CATEGORY, owasp_category="A05",
            description="The archive has no top-level manifest.json.",
            remediation="Upload a Chrome CRX / Firefox XPI / unpacked-extension ZIP.",
            endpoint=str(ext_dir),
        )]
    try:
        m = json.loads(mpath.read_text(encoding="utf-8", errors="replace"))
    except (json.JSONDecodeError, OSError) as e:
        return [Finding(
            title="manifest.json parse error", severity=Severity.LOW,
            category=CATEGORY, owasp_category="A05",
            description=f"Could not parse manifest.json: {e}",
            remediation="Validate the manifest with Mozilla addons-linter.",
            endpoint=str(mpath))]

    findings: list[Finding] = []
    ev = [Evidence(request_method="STATIC", request_url=str(mpath))]
    perms = list(m.get("permissions", []) or [])
    host_perms = list(m.get("host_permissions", []) or [])

    if m.get("manifest_version") == 2:
        findings.append(Finding(
            title="Manifest V2 (deprecated, weaker security model)",
            severity=Severity.MEDIUM, category=CATEGORY, owasp_category="A05",
            description="MV2 permits remote code, blocking webRequest, and a weaker CSP. Chrome is removing MV2 support.",
            remediation="Migrate to Manifest V3.", endpoint=str(mpath),
            parameter="manifest_version", cwe_id="CWE-1104", evidence=ev,
            references=["https://developer.chrome.com/docs/extensions/develop/migrate"]))

    for perm in perms + host_perms:
        if perm in _CRITICAL_PERMS:
            findings.append(Finding(
                title=f"Critical permission: {perm}", severity=Severity.HIGH,
                category=CATEGORY, owasp_category="A01",
                description=f"The extension requests '{perm}' — it can {_CRITICAL_PERMS[perm]}. A compromise (or malicious update) of this extension gives an attacker that capability across the user's browser.",
                remediation=f"Drop '{perm}' unless strictly required; scope host access to specific origins.",
                endpoint=str(mpath), parameter=f"permissions[{perm}]",
                cwe_id="CWE-250", cvss_score=7.1,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N", evidence=ev))
        elif perm in _HIGH_PERMS:
            findings.append(Finding(
                title=f"Sensitive permission: {perm}", severity=Severity.MEDIUM,
                category=CATEGORY, owasp_category="A01",
                description=f"The extension requests '{perm}' — it can {_HIGH_PERMS[perm]}.",
                remediation=f"Confirm '{perm}' is needed; prefer narrower APIs.",
                endpoint=str(mpath), parameter=f"permissions[{perm}]",
                cwe_id="CWE-250", evidence=ev))

    if _has_broad(host_perms) or _has_broad(perms):
        findings.append(Finding(
            title="Broad host access (<all_urls> / *://*/*)", severity=Severity.HIGH,
            category=CATEGORY, owasp_category="A01",
            description="The extension can read and modify content on every website the user visits. This is the single biggest blast-radius for a compromised or malicious extension.",
            remediation="Restrict host_permissions to the specific origins the extension actually needs.",
            endpoint=str(mpath), parameter="host_permissions", cwe_id="CWE-250",
            cvss_score=7.4, cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N",
            evidence=ev))

    # Content-script injection surface.
    for cs in (m.get("content_scripts") or []):
        if _has_broad(cs.get("matches")):
            findings.append(Finding(
                title="Content script injected into all sites", severity=Severity.MEDIUM,
                category=CATEGORY, owasp_category="A03",
                description=f"A content script matches {cs.get('matches')} — it runs in the page context of every site, expanding the XSS/injection surface.",
                remediation="Narrow content_scripts[].matches to required origins.",
                endpoint=str(mpath), parameter="content_scripts[].matches",
                cwe_id="CWE-79", evidence=ev))
            break

    # CSP weaknesses (MV2 string or MV3 object form).
    csp = m.get("content_security_policy")
    csp_text = csp if isinstance(csp, str) else json.dumps(csp or {})
    if re.search(r"unsafe-eval|unsafe-inline|(?<![\w.])http://", csp_text):
        findings.append(Finding(
            title="Weak content_security_policy", severity=Severity.HIGH,
            category=CATEGORY, owasp_category="A05",
            description="The extension CSP permits unsafe-eval / unsafe-inline / http: sources, re-enabling code-injection vectors MV3 is designed to block.",
            remediation="Remove unsafe-eval/unsafe-inline; serve all code from the package over https only.",
            endpoint=str(mpath), parameter="content_security_policy",
            cwe_id="CWE-1336", cvss_score=6.5,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N", evidence=ev))

    # externally_connectable broadness.
    ec = m.get("externally_connectable") or {}
    if _has_broad(ec.get("matches")) or ec.get("ids") == ["*"]:
        findings.append(Finding(
            title="Broad externally_connectable", severity=Severity.MEDIUM,
            category=CATEGORY, owasp_category="A01",
            description="externally_connectable allows any site/extension to message this extension, exposing its message handlers as an attack surface.",
            remediation="Restrict externally_connectable.matches/ids to trusted origins.",
            endpoint=str(mpath), parameter="externally_connectable", cwe_id="CWE-749",
            evidence=ev))
    return findings


def _analyze_code(ext_dir: Path) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[str] = set()
    for p, text in iter_text_files(ext_dir):
        if p.suffix.lower() not in {".js", ".mjs", ".cjs", ".html", ".htm"}:
            continue
        for label, pat, cwe, desc in _SINKS:
            key = f"{label}:{p.name}"
            if key in seen:
                continue
            if pat.search(text):
                seen.add(key)
                sev = Severity.HIGH if label == "remote code load" else Severity.MEDIUM
                findings.append(Finding(
                    title=f"{label} in {p.name}", severity=sev, category=CATEGORY,
                    owasp_category="A03", description=f"{desc}. Found in a shipped script; if reachable with attacker-influenced input it enables code/HTML injection in the extension's privileged context.",
                    remediation="Avoid dynamic code/HTML sinks; use textContent, JSON.parse, and bundle all code locally.",
                    endpoint=str(p), parameter=label, cwe_id=cwe,
                    evidence=[Evidence(request_method="STATIC", request_url=str(p),
                                       description=label)]))
    return findings


def analyze_extension(path: str, source_label: str = "extension") -> list[Finding]:
    ext_dir = unpack_extension(path)
    if ext_dir is None:
        return [Finding(
            title="Unrecognized extension package", severity=Severity.INFO,
            category=CATEGORY, owasp_category="A05",
            description="The artifact is not a CRX, XPI, or ZIP extension package.",
            remediation="Upload a .crx (Chrome/Edge), .xpi (Firefox), or zipped unpacked extension.",
            endpoint=path)]
    root = Path(ext_dir)
    findings = _analyze_manifest(root, source_label)
    findings += _analyze_code(root)
    findings += secrets_sweep(root, "extension_secrets", source_label)
    return findings
