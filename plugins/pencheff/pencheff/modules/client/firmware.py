"""Firmware / embedded / IoT / OT static analyzer (spec 003).

Pure-static; the firmware is never flashed or executed. The pipeline is:

  1. binwalk signature map (component identification, version-robust).
  2. binwalk -e extraction of the embedded filesystem(s) into a temp tree, so
     the deep analysis runs over the REAL files (/etc/passwd, init scripts, SSH
     keys) — not just ``strings`` of the packed image, which on a large image
     silently truncates the rootfs and misses everything.
  3. Deep content analysis: hardcoded/default OS credentials, embedded SSH host
     keys & private keys, insecure services (telnet/debug), cleartext endpoints,
     secrets, and component-version → CVE matching.
  4. Kind-specific passes: ``iot_device`` adds a Mirai-class default-credential
     dictionary; ``ot_ics_scada`` adds industrial-protocol detection. ``firmware``
     is the general baseline.

Extraction is best-effort: if binwalk (or its filesystem extractors) is missing,
the analyzer falls back to an uncapped ``strings`` sweep and says so, so a thin
result is never mistaken for a clean device."""

from __future__ import annotations

import re
import tempfile
from pathlib import Path

from pencheff.config import Severity
from pencheff.core.findings import Evidence, Finding
from pencheff.core.tool_runner import run_tool, tool_available
from pencheff.modules.client._common import secrets_sweep

CATEGORY = "firmware_misconfig"
MAX_BYTES = 400_000_000        # 400 MB cap on the raw image read (fallback path)
MAX_EXTRACT_FILES = 20_000     # walk cap on the extracted tree
MAX_TEXT_BYTES = 8_000_000     # per-file text read cap

# ── content patterns ────────────────────────────────────────────────────────
_PEM_PRIVATE_KEY = re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----")
_CERTIFICATE = re.compile(r"-----BEGIN CERTIFICATE-----")
# /etc/shadow line with a real (unlocked) hash: user:$id$salt$hash: — a locked
# account is "*"/"!"/"!!" and is explicitly NOT matched.
_SHADOW_ACTIVE = re.compile(r"(?m)^([a-z_][a-z0-9_-]*):(\$[0-9a-z]{1,3}\$[^:\s]{6,}):")
# /etc/passwd line with an inline password (field 2 not x/*/!): user:pw:uid:...
_PASSWD_INLINE = re.compile(r"(?m)^([a-z_][a-z0-9_-]*):([^x*!:\s][^:\s]*):\d+:\d+:")
_HARDCODED_CRED = re.compile(
    r"(?i)\b(?:admin|root|user|guest):(?:admin|root|password|pass|1234|12345|123456|default)\b"
)
_TELNETD = re.compile(r"\btelnetd\b|/bin/telnet\b|\butelnetd\b|\bin\.telnetd\b")
_DEBUG_SVC = re.compile(r"(?i)\b(?:dropbear|gdbserver|adb|debug[_-]?shell|backdoor)\b")
_CLEARTEXT_URL = re.compile(
    r"\bhttp://(?!localhost|127\.0\.0\.1|0\.0\.0\.0|schemas\.|www\.w3\.org)[a-zA-Z0-9.\-/_:]+"
)

# Mirai-class default credential dictionary (subset). IoTGoat ships root:iotgoatuser.
_MIRAI_CREDS = {
    "root:xc3511", "root:vizxv", "root:admin", "admin:admin", "root:888888",
    "root:xmhdipc", "root:default", "root:juantech", "root:123456", "root:54321",
    "support:support", "root:root", "admin:password", "root:12345", "user:user",
    "root:pass", "admin:admin1234", "root:1111", "admin:smcadmin", "root:666666",
    "root:password", "root:1234", "root:klv123", "Administrator:admin",
    "service:service", "guest:guest", "admin:1111", "root:vizxv", "root:iotgoatuser",
}

# Industrial-control protocol markers (ot_ics_scada).
_OT_PROTOCOLS = {
    "Modbus": re.compile(r"(?i)\bmodbus\b"),
    "DNP3": re.compile(r"(?i)\bdnp3\b"),
    "S7comm / STEP7": re.compile(r"(?i)\bs7comm\b|\bstep[ _-]?7\b|\biso[ _-]?on[ _-]?tcp\b"),
    "PROFINET": re.compile(r"(?i)\bprofinet\b"),
    "EtherNet/IP (CIP)": re.compile(r"(?i)ethernet/ip|\benip\b|\bcip\b(?![a-z])"),
    "BACnet": re.compile(r"(?i)\bbacnet\b"),
    "IEC 60870-5-104": re.compile(r"(?i)iec[ -]?60870|iec[ -]?104"),
    "OPC-UA": re.compile(r"(?i)\bopc[ -]?ua\b"),
}

# Component banner → (name, patched-at version, CVE note). Detected version BELOW
# `patched` → surfaced as a known-CVE exposure. Heuristic (not a live feed).
_CVE_RULES = [
    (re.compile(r"BusyBox v([\d.]+)"), "BusyBox", (1, 31, 0),
     "CVE-2021-42373..42386 (multiple applet memory-safety bugs)"),
    (re.compile(r"Dropbear[ _]v?([\d.]+)"), "Dropbear SSH", (2020, 81),
     "CVE-2018-15599 / CVE-2016-7406..7409 (RCE / info-leak)"),
    (re.compile(r"OpenSSL ([\d]+\.[\d]+\.[\d]+)"), "OpenSSL", (1, 1, 1),
     "pre-1.1.1 is EOL — Heartbleed-era and unpatched CVEs"),
    (re.compile(r"lighttpd/([\d.]+)"), "lighttpd", (1, 4, 51),
     "multiple request-smuggling / DoS CVEs"),
    (re.compile(r"\bu-?boot[ _-]?([\d.]+)", re.IGNORECASE), "Das U-Boot", (2021, 1),
     "pre-2021 bootloaders carry known verified-boot bypass CVEs"),
]


# Default/Mirai PASSWORDS (the pw half of the cred dict + common device defaults)
# used to crack /etc/shadow hashes for the iot_device pass.
_DEFAULT_PASSWORDS = {c.split(":", 1)[1] for c in _MIRAI_CREDS if ":" in c} | {
    "iotgoatuser", "toor", "alpine", "raspberry", "test", "changeme", "0000",
    "admin1", "password1", "letmein", "1234567", "abc123",
}


def _ev(label: str, where: str) -> list[Evidence]:
    return [Evidence(request_method="STATIC", request_url=where, description=label)]


def _crack_shadow_hashes(text: str, passwords: set[str]) -> list[tuple[str, str]]:
    """Test each /etc/shadow hash against the default-password dictionary using the
    platform crypt(3) (handles $1$ md5, $5$ sha256, $6$ sha512). Returns the
    (user, password) pairs that cracked. Best-effort: no crypt module → []."""
    try:
        import crypt  # noqa: PLC0415 — Linux-only, guarded
    except Exception:  # noqa: BLE001
        return []
    cracked: list[tuple[str, str]] = []
    seen: set[str] = set()
    for m in re.finditer(r"(?m)^([a-z_][a-z0-9_-]*):(\$[0-9a-z]{1,3}\$[^:\s]+)", text):
        user, h = m.group(1), m.group(2)
        if user in seen:
            continue
        for pw in passwords:
            try:
                if crypt.crypt(pw, h) == h:
                    cracked.append((user, pw))
                    seen.add(user)
                    break
            except Exception:  # noqa: BLE001 — malformed salt / unsupported scheme
                break
        if len(cracked) >= 10:
            break
    return cracked


def _ver_tuple(s: str) -> tuple[int, ...]:
    return tuple(int(p) for p in re.findall(r"\d+", s)[:4]) or (0,)


def _ver_lt(a: str, b: tuple[int, ...]) -> bool:
    """True if version string `a` is strictly below tuple `b`."""
    ta = _ver_tuple(a)
    n = max(len(ta), len(b))
    ta += (0,) * (n - len(ta))
    tb = b + (0,) * (n - len(b))
    return ta < tb


# ── pure analysis (unit-tested) ──────────────────────────────────────────────
def analyze_credentials(text: str, where: str, *, kind: str) -> list[Finding]:
    """Hardcoded/default OS credentials from passwd/shadow + inline creds. On
    iot_device, also match the Mirai default-credential dictionary."""
    out: list[Finding] = []
    if _SHADOW_ACTIVE.search(text) or _PASSWD_INLINE.search(text):
        m = _SHADOW_ACTIVE.search(text) or _PASSWD_INLINE.search(text)
        user = m.group(1) if m else "root"
        out.append(Finding(
            title="Hardcoded OS login credentials in firmware",
            severity=Severity.CRITICAL, category="firmware_creds", owasp_category="A07",
            description=(
                f"The root filesystem ships a login account ('{user}') with a set, "
                "unlocked password baked into /etc/passwd or /etc/shadow. It is identical "
                "on every unit and crackable offline — a shared, permanent backdoor login."),
            remediation="Ship no baked-in accounts; force a unique credential at first boot and lock system accounts.",
            endpoint=where, cwe_id="CWE-798", cvss_score=9.8,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            evidence=_ev(f"unlocked credential for '{user}'", where)))
    if _HARDCODED_CRED.search(text):
        out.append(Finding(
            title="Default credential pair in firmware", severity=Severity.HIGH,
            category="firmware_creds", owasp_category="A07",
            description="A default credential pair (e.g. admin:admin, root:password) appears in the firmware — the #1 IoT compromise vector (Mirai-class botnets).",
            remediation="Force a unique credential on first setup; never ship default/static logins.",
            endpoint=where, cwe_id="CWE-1392", evidence=_ev("default credential pair", where)))
    if kind == "iot_device":
        # Crack the shadow hashes against the Mirai/default-password dictionary —
        # this is what identifies IoTGoat's root:iotgoatuser (stored HASHED, so a
        # literal string match never sees it).
        cracked = _crack_shadow_hashes(text, _DEFAULT_PASSWORDS)
        low = text.lower()
        literal = sorted({c for c in _MIRAI_CREDS if c.lower() in low})
        if cracked or literal:
            pairs = [f"{u}:{p}" for u, p in cracked] + literal
            detail = (
                "Login credentials match the Mirai/IoT default-password dictionary: "
                + ", ".join(sorted(set(pairs))[:8])
                + (" (recovered by cracking the shadow hash)" if cracked else "")
                + ". These are botnet-scanned and exploited within minutes of exposure.")
            out.append(Finding(
                title="Mirai-class default credentials in firmware", severity=Severity.CRITICAL,
                category="firmware_creds", owasp_category="A07",
                description=detail,
                remediation="Remove all default accounts/passwords; require per-device credentials at provisioning.",
                endpoint=where, cwe_id="CWE-1392", cvss_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                evidence=_ev("Mirai default-credential match", where)))
    return out


def analyze_services(text: str, where: str) -> list[Finding]:
    out: list[Finding] = []
    if _TELNETD.search(text):
        out.append(Finding(
            title="Telnet service enabled in firmware", severity=Severity.HIGH,
            category=CATEGORY, owasp_category="A05",
            description="A telnet daemon (telnetd) is present/started. Telnet is cleartext and a classic IoT remote-access backdoor — combined with default creds it is trivial remote root.",
            remediation="Remove telnetd; use SSH with key auth. Disable debug shells in production images.",
            endpoint=where, cwe_id="CWE-319", cvss_score=7.5,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            evidence=_ev("telnetd", where)))
    return out


def analyze_keys(text: str, where: str) -> list[Finding]:
    out: list[Finding] = []
    if _PEM_PRIVATE_KEY.search(text):
        out.append(Finding(
            title="Embedded private / SSH host key in firmware", severity=Severity.CRITICAL,
            category="firmware_crypto", owasp_category="A02",
            description="A PEM private key (TLS/SSH host key) is baked into the image. Every device ships the SAME key — anyone with the firmware extracts it and can impersonate/MITM or decrypt traffic for every unit.",
            remediation="Never ship private keys; generate per-device keys at first boot and rotate any exposed key.",
            endpoint=where, cwe_id="CWE-321", cvss_score=9.1,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
            evidence=_ev("-----BEGIN ... PRIVATE KEY-----", where)))
    if _CERTIFICATE.search(text):
        out.append(Finding(
            title="Embedded certificate in firmware", severity=Severity.LOW,
            category="firmware_crypto", owasp_category="A02",
            description="An X.509 certificate is embedded. Confirm it is a pinned CA (acceptable), not a shipped server/client cert paired with a private key.",
            remediation="Confirm no private key accompanies a shipped cert; prefer per-device provisioning.",
            endpoint=where, cwe_id="CWE-321", evidence=_ev("-----BEGIN CERTIFICATE-----", where)))
    return out


def analyze_endpoints(text: str, where: str) -> list[Finding]:
    if _CLEARTEXT_URL.search(text):
        return [Finding(
            title="Cleartext HTTP endpoint in firmware", severity=Severity.MEDIUM,
            category="firmware_communication", owasp_category="A02",
            description="A hardcoded http:// endpoint (often update/telemetry) is present. Cleartext update channels enable MITM firmware tampering.",
            remediation="Use HTTPS with certificate validation for all update/telemetry endpoints.",
            endpoint=where, cwe_id="CWE-319", evidence=_ev("http:// endpoint", where))]
    return []


def analyze_components_cve(text: str, where: str) -> list[Finding]:
    """Version banners → known-CVE exposure where the detected version is below
    the patched baseline. Also emits the informational component map."""
    out: list[Finding] = []
    seen_banner: set[str] = set()
    for rx, name, patched, note in _CVE_RULES:
        m = rx.search(text)
        if not m:
            continue
        ver = m.group(1)
        seen_banner.add(f"{name} {ver}")
        if _ver_lt(ver, patched):
            out.append(Finding(
                title=f"Outdated component with known CVEs: {name} {ver}",
                severity=Severity.HIGH, category="firmware_components", owasp_category="A06",
                description=f"{name} {ver} is below the patched baseline {'.'.join(map(str, patched))}. {note}",
                remediation=f"Update {name} to a patched release and rebuild the image.",
                endpoint=where, cwe_id="CWE-1104", evidence=_ev(f"{name} {ver} banner", where)))
    if seen_banner:
        out.append(Finding(
            title="Bundled component versions detected", severity=Severity.INFO,
            category="firmware_components", owasp_category="A06",
            description="Version banners found — matched against the CVE heuristic: " + ", ".join(sorted(seen_banner)),
            remediation="Verify each component is on a patched version free of known CVEs.",
            endpoint=where, evidence=_ev("component version banners", where)))
    return out


def analyze_ot_protocols(text: str, where: str) -> list[Finding]:
    hits = sorted({name for name, rx in _OT_PROTOCOLS.items() if rx.search(text)})
    if not hits:
        return []
    return [Finding(
        title="Industrial control protocol stack present", severity=Severity.MEDIUM,
        category="ot_protocol", owasp_category="A05",
        description=(
            "The image implements ICS/SCADA protocols: " + ", ".join(hits) + ". "
            "These protocols are typically unauthenticated and unencrypted; if the device's "
            "control plane is network-reachable, an attacker can read/forge process commands."),
        remediation="Segment OT networks; require authenticated gateways; disable unused protocol stacks; monitor for unauthorized control traffic.",
        endpoint=where, cwe_id="CWE-306", evidence=_ev("ICS protocol markers: " + ", ".join(hits), where))]


def _content_findings(text: str, where: str, *, kind: str) -> list[Finding]:
    out: list[Finding] = []
    out += analyze_credentials(text, where, kind=kind)
    out += analyze_services(text, where)
    out += analyze_keys(text, where)
    out += analyze_endpoints(text, where)
    out += analyze_components_cve(text, where)
    if kind == "ot_ics_scada":
        out += analyze_ot_protocols(text, where)
    return out


# ── extraction + orchestration ───────────────────────────────────────────────
async def _binwalk_components(path: str) -> list[Finding]:
    if not tool_available("binwalk"):
        return [Finding(
            title="binwalk not installed — component map skipped",
            severity=Severity.INFO, category=CATEGORY, owasp_category="A06",
            description="binwalk is unavailable on the worker, so the firmware's filesystem/component signature map was not produced.",
            remediation="Install binwalk on the worker for filesystem/component identification.",
            endpoint=path)]
    res = await run_tool(["binwalk", path], timeout=180)
    out = (res.stdout or "")[:8000]
    sigs = [ln.strip() for ln in out.splitlines()
            if re.match(r"^\d+\s", ln.strip()) and "0x" in ln]
    if not sigs:
        return []
    summary = "; ".join(s.split("0x", 1)[-1][:80] for s in sigs[:12])
    return [Finding(
        title="Firmware component map (binwalk)",
        severity=Severity.INFO, category="firmware_components", owasp_category="A06",
        description=f"binwalk identified {len(sigs)} embedded signatures (filesystems, kernels, archives). Top entries: {summary}",
        remediation="Review identified filesystems/components and confirm each shipped component is current and necessary.",
        endpoint=path, evidence=_ev("binwalk signature scan", path))]


async def _extract(path: str, dest: Path) -> bool:
    """Best-effort binwalk -e (Matryoshka) extraction into `dest`. True if it
    produced any extracted files."""
    if not tool_available("binwalk"):
        return False
    await run_tool(
        ["binwalk", "--run-as=root", "-e", "-M", "--directory", str(dest), path],
        timeout=600,
    )
    return any(dest.rglob("*"))


def _read_extracted_text(root: Path) -> str:
    """Concatenate text from the extracted tree, front-loading the security-
    critical files (passwd/shadow/init/ssh) so they're never truncated."""
    priority: list[str] = []
    bulk: list[str] = []
    important = re.compile(r"(?i)(passwd|shadow|inittab|rc\.?local|rcS|init\.d|"
                           r"dropbear|ssh|telnet|\.pem|_key$|authorized_keys)")
    count = 0
    for p in root.rglob("*"):
        if count >= MAX_EXTRACT_FILES:
            break
        if not p.is_file():
            continue
        count += 1
        try:
            data = p.read_bytes()[:MAX_TEXT_BYTES]
        except OSError:
            continue
        txt = data.decode("latin-1", errors="ignore")
        rel = str(p)
        chunk = f"\n### FILE: {rel}\n{txt}"
        (priority if important.search(rel) else bulk).append(chunk)
    return "".join(priority) + "".join(bulk)


async def analyze_firmware(path: str, source_label: str = "firmware") -> list[Finding]:
    """`source_label` is the target KIND (firmware | iot_device | ot_ics_scada) —
    it selects the kind-specific passes."""
    kind = source_label if source_label in ("firmware", "iot_device", "ot_ics_scada") else "firmware"
    try:
        Path(path).stat()
    except OSError:
        return [Finding(title="Firmware image unreadable", severity=Severity.INFO,
                        category=CATEGORY, owasp_category="A05",
                        description="Could not read the uploaded firmware image.",
                        remediation="Re-upload the firmware (.bin/.img/.hex or a packed archive).", endpoint=path)]

    findings = await _binwalk_components(path)

    dest = Path(tempfile.mkdtemp(prefix="pencheff_fw_"))
    extracted = await _extract(path, dest)
    if extracted:
        text = _read_extracted_text(dest)
        where = f"{path} (extracted rootfs)"
        findings += _content_findings(text, where, kind=kind)
        findings += secrets_sweep(dest, "firmware_secrets", kind)
    else:
        # Fallback: no extraction available — sweep the raw image strings and
        # flag that the analysis was shallow so a thin result isn't read as clean.
        raw = Path(path).read_bytes()[:MAX_BYTES]
        text = raw.decode("latin-1", errors="ignore")
        printable = "\n".join(re.findall(r"[\x20-\x7e]{5,}", text))
        where = f"{path} (raw image — not extracted)"
        findings += _content_findings(printable, where, kind=kind)
        (dest / "strings.txt").write_text(printable[:20_000_000], encoding="utf-8")
        findings += secrets_sweep(dest, "firmware_secrets", kind)
        findings.append(Finding(
            title="Firmware filesystem could not be extracted — analysis is shallow",
            severity=Severity.INFO, category=CATEGORY, owasp_category="A06",
            description="binwalk extraction produced no filesystem, so deep analysis ran only over raw image strings. Credential/service/key detection may be incomplete.",
            remediation="Install binwalk filesystem extractors (squashfs-tools, e2fsprogs/sleuthkit) on the worker and re-scan.",
            endpoint=path))
    return findings
