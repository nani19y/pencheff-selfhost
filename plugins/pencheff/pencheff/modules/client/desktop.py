"""Desktop-application static analyzer (spec 002) — Electron webPreferences/fuses,
bundled-dependency hints, hardcoded secrets. Pure-static; the binary is never run.

Coverage is honest by sub-type: Electron (asar/JS) and archive-based apps
(Java JARs, zipped bundles) get real config + secret checks; opaque native
binaries (PE/ELF/Mach-O) get a strings-based secret sweep plus a clear note
that decompiler-grade depth is out of scope for this static pass."""

from __future__ import annotations

import re
import tempfile
from pathlib import Path

from pencheff.config import Severity
from pencheff.core.findings import Evidence, Finding
from pencheff.modules.client._common import (
    MAX_BYTES_PER_FILE,
    safe_unzip,
    secrets_sweep,
)

CATEGORY = "desktop_misconfig"

# Electron webPreferences anti-patterns (regex over JS / asar text). Each
# disables a renderer-sandbox protection.
_ELECTRON_FLAGS = [
    ("nodeIntegration enabled", re.compile(r"nodeIntegration\s*:\s*true"), Severity.HIGH,
     "Renderer has full Node.js access — any XSS becomes RCE on the host.", "CWE-94"),
    ("contextIsolation disabled", re.compile(r"contextIsolation\s*:\s*false"), Severity.HIGH,
     "Preload/page share a JS context — prototype-pollution and bridge tampering become trivial.", "CWE-94"),
    ("sandbox disabled", re.compile(r"sandbox\s*:\s*false"), Severity.MEDIUM,
     "The renderer process is not sandboxed.", "CWE-265"),
    ("webSecurity disabled", re.compile(r"webSecurity\s*:\s*false"), Severity.HIGH,
     "Same-origin policy is turned off in the renderer.", "CWE-942"),
    ("allowRunningInsecureContent", re.compile(r"allowRunningInsecureContent\s*:\s*true"), Severity.MEDIUM,
     "Mixed/insecure content is allowed to load.", "CWE-311"),
]
_SINKS = [
    ("eval()", re.compile(r"\beval\s*\("), "CWE-95"),
    ("child_process exec", re.compile(r"child_process|\.exec(Sync)?\s*\("), "CWE-78"),
    ("shell.openExternal", re.compile(r"shell\.openExternal\s*\("), "CWE-749"),
]
_TEXT_SCAN_EXTS = {".js", ".mjs", ".cjs", ".ts", ".json", ".html", ".asar"}


def _is_zip(raw: bytes) -> bool:
    return raw[:2] == b"PK"


def _sub_type(raw: bytes, root: Path | None) -> str:
    if raw[:2] == b"MZ":
        return "windows_pe"
    if raw[:4] == b"\x7fELF":
        return "elf_native"
    if raw[:4] in (b"\xca\xfe\xba\xbe", b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf"):
        return "macho_native"
    if root is not None:
        if any(root.rglob("*.asar")) or (root / "package.json").is_file():
            return "electron"
        if any(root.rglob("*.class")) or (root / "META-INF" / "MANIFEST.MF").is_file():
            return "java"
        return "archive"
    return "unknown"


def _scan_text_files(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[str] = set()
    count = 0
    for p in sorted(root.rglob("*")):
        if count >= 5000:
            break
        if not p.is_file() or p.suffix.lower() not in _TEXT_SCAN_EXTS:
            continue
        try:
            if p.stat().st_size > MAX_BYTES_PER_FILE:
                continue
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        count += 1
        for label, pat, sev, desc, cwe in _ELECTRON_FLAGS:
            key = f"{label}"
            if key in seen or not pat.search(text):
                continue
            seen.add(key)
            findings.append(Finding(
                title=f"Electron: {label}", severity=sev, category=CATEGORY,
                owasp_category="A05", description=f"{desc} Found in {p.name}.",
                remediation="Follow the Electron Security Checklist: nodeIntegration:false, contextIsolation:true, sandbox:true, webSecurity:true; expose only vetted APIs via contextBridge.",
                endpoint=str(p), parameter=label, cwe_id=cwe,
                cvss_score=8.1 if sev == Severity.HIGH else 5.4,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" if sev == Severity.HIGH else "",
                evidence=[Evidence(request_method="STATIC", request_url=str(p), description=label)],
                references=["https://www.electronjs.org/docs/latest/tutorial/security"]))
        for label, pat, cwe in _SINKS:
            key = f"sink:{label}:{p.name}"
            if key in seen or not pat.search(text):
                continue
            seen.add(key)
            findings.append(Finding(
                title=f"Dangerous call: {label} ({p.name})", severity=Severity.MEDIUM,
                category=CATEGORY, owasp_category="A03",
                description=f"{label} in shipped code; if reachable with attacker-influenced input it can lead to code/command execution on the host.",
                remediation="Avoid dynamic eval and shelling out with untrusted input; validate and use safe APIs.",
                endpoint=str(p), parameter=label, cwe_id=cwe,
                evidence=[Evidence(request_method="STATIC", request_url=str(p), description=label)]))
    return findings


def _electron_version_check(root: Path) -> list[Finding]:
    pkg = root / "package.json"
    if not pkg.is_file():
        return []
    try:
        import json
        data = json.loads(pkg.read_text(encoding="utf-8", errors="replace"))
    except (json.JSONDecodeError, OSError):
        return []
    deps = {**(data.get("dependencies") or {}), **(data.get("devDependencies") or {})}
    ver = deps.get("electron")
    if not ver:
        return []
    m = re.search(r"(\d+)", str(ver))
    major = int(m.group(1)) if m else 0
    if major and major < 28:  # ponytail: static major-version floor, refine against an advisory feed later
        return [Finding(
            title=f"Outdated Electron ({ver})", severity=Severity.MEDIUM,
            category=CATEGORY, owasp_category="A06",
            description=f"The bundle pins Electron {ver}. Older Electron majors ship known Chromium/Node CVEs and lack newer sandbox hardening.",
            remediation="Upgrade to a currently-supported Electron major and rebuild.",
            endpoint=str(pkg), parameter="dependencies.electron", cwe_id="CWE-1104",
            evidence=[Evidence(request_method="STATIC", request_url=str(pkg), description=f"electron@{ver}")])]
    return []


def analyze_desktop(path: str, source_label: str = "desktop app") -> list[Finding]:
    try:
        raw = Path(path).read_bytes()
    except OSError:
        return [Finding(title="Artifact unreadable", severity=Severity.INFO,
                        category=CATEGORY, owasp_category="A05",
                        description="Could not read the uploaded artifact.",
                        remediation="Re-upload the desktop application bundle.", endpoint=path)]

    if _is_zip(raw):
        dest = Path(tempfile.mkdtemp(prefix="pencheff_desktop_"))
        root_str = safe_unzip(raw, dest)
        if root_str is None:
            return [Finding(title="Could not unpack archive", severity=Severity.INFO,
                            category=CATEGORY, owasp_category="A05",
                            description="The artifact looked like a ZIP/JAR but failed to extract.",
                            remediation="Verify the upload is a valid archive.", endpoint=path)]
        root = Path(root_str)
        sub = _sub_type(raw, root)
        findings = _scan_text_files(root)
        findings += _electron_version_check(root)
        findings += secrets_sweep(root, "desktop_secrets", source_label)
        findings.insert(0, Finding(
            title=f"Desktop artifact classified as: {sub}", severity=Severity.INFO,
            category=CATEGORY, owasp_category="A05",
            description=f"Static analysis ran over the unpacked {sub} bundle.",
            remediation="—", endpoint=path, parameter="sub_type"))
        return findings

    # Opaque native binary — strings-based secret sweep only; be honest about depth.
    sub = _sub_type(raw, None)
    dest = Path(tempfile.mkdtemp(prefix="pencheff_desktop_"))
    blob = dest / "strings.txt"
    text = raw.decode("latin-1", errors="ignore")
    printable = re.findall(r"[\x20-\x7e]{6,}", text)
    blob.write_text("\n".join(printable[:200000]), encoding="utf-8")
    findings = secrets_sweep(dest, "desktop_secrets", source_label)
    findings.insert(0, Finding(
        title=f"Native binary ({sub}) — limited static depth", severity=Severity.INFO,
        category=CATEGORY, owasp_category="A05",
        description=f"The artifact is an opaque {sub} binary. This static pass extracts printable strings and sweeps for embedded secrets. Decompiler-grade analysis (checksec hardening flags, capa capabilities, .NET/Java decompilation) is out of scope for this pass.",
        remediation="For deeper coverage, submit a debug/unstripped build or the source archive.",
        endpoint=path, parameter="sub_type"))
    return findings
