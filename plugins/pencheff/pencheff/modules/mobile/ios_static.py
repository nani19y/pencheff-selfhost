"""iOS IPA static analysis — Info.plist ATS, URL schemes, embedded provisioning, binary hardening."""

from __future__ import annotations

import plistlib
import tempfile
import zipfile
from pathlib import Path
from typing import Any

from pencheff.config import Severity
from pencheff.core.findings import Evidence, Finding
from pencheff.core.http_client import PencheffHTTPClient
from pencheff.core.session import PentestSession
from pencheff.core.tool_runner import run_tool, tool_available
from pencheff.modules.base import BaseTestModule


class IOSStaticModule(BaseTestModule):
    """Unzip IPA, parse Info.plist, check ATS / URL schemes / entitlements / binary hardening."""

    name = "ios_static"
    category = "mobile_misconfig"
    owasp_categories = ["M5", "M7", "M8"]
    description = "iOS IPA static checks: Info.plist ATS, URL schemes, embedded provisioning, PIE/canary"

    def get_techniques(self) -> list[str]:
        return [
            "ats_bypass_detection",
            "url_scheme_enumeration",
            "embedded_provisioning_review",
            "pie_canary_check",
        ]

    async def run(
        self,
        session: PentestSession,
        http: PencheffHTTPClient,
        targets: list[str] | None = None,
        config: dict[str, Any] | None = None,
    ) -> list[Finding]:
        cfg = config or {}
        ipa_path = cfg.get("ipa_path")
        if not ipa_path:
            return []

        p = Path(ipa_path)
        if not p.is_file():
            return [Finding(
                title=f"IPA not found: {ipa_path}",
                severity=Severity.INFO,
                category="mobile_misconfig",
                owasp_category="M8",
                description="The IPA file path passed to scan_mobile_static does not exist.",
                remediation="Pass an absolute path to a valid .ipa file.",
                endpoint=ipa_path,
            )]

        try:
            extract_dir = Path(tempfile.mkdtemp(prefix="pencheff-ipa-")).resolve()
            with zipfile.ZipFile(p, "r") as z:
                for member in z.infolist():
                    target = (extract_dir / member.filename).resolve()
                    if not target.is_relative_to(extract_dir):
                        return [Finding(
                            title="Malicious IPA: path traversal in zip entry",
                            severity=Severity.HIGH,
                            category="mobile_misconfig",
                            owasp_category="M8",
                            description=(
                                f"The IPA contains a zip entry that resolves outside the extraction "
                                f"directory: {member.filename!r}. This is a zip-slip pattern often "
                                f"used to overwrite files on the auditor's machine when the IPA is "
                                f"unpacked. Refusing to extract."
                            ),
                            remediation="Do not unpack untrusted IPAs with extractall(). Inspect the file separately or treat the IPA as malicious.",
                            endpoint=ipa_path,
                            parameter=member.filename,
                            cwe_id="CWE-22",
                        )]
                    z.extract(member, extract_dir)
        except zipfile.BadZipFile:
            return [Finding(
                title="Invalid IPA archive",
                severity=Severity.LOW,
                category="mobile_misconfig",
                owasp_category="M8",
                description=f"{ipa_path} is not a valid zip archive.",
                remediation="Verify the file is a real .ipa (an IPA is a renamed zip containing Payload/<name>.app/).",
                endpoint=ipa_path,
            )]

        findings: list[Finding] = []
        payload_dir = extract_dir / "Payload"
        app_bundles = list(payload_dir.glob("*.app")) if payload_dir.exists() else []
        if not app_bundles:
            findings.append(Finding(
                title="IPA missing Payload/*.app bundle",
                severity=Severity.LOW,
                category="mobile_misconfig",
                owasp_category="M8",
                description="The IPA does not contain a Payload/<name>.app/ directory — it may be malformed or stripped.",
                remediation="Verify the source IPA is unmodified and contains a complete app bundle.",
                endpoint=ipa_path,
            ))
            return findings

        app_bundle = app_bundles[0]
        bundle_name = app_bundle.name

        info_plist_path = app_bundle / "Info.plist"
        if info_plist_path.is_file():
            findings.extend(self._check_info_plist(info_plist_path, ipa_path, bundle_name))

        prov_path = app_bundle / "embedded.mobileprovision"
        if prov_path.is_file():
            findings.append(Finding(
                title=f"Embedded provisioning profile present ({bundle_name})",
                severity=Severity.INFO,
                category="mobile_misconfig",
                owasp_category="M8",
                description=(
                    "embedded.mobileprovision is present. This is normal for distribution builds, "
                    "but inspect entitlements (`security cms -D -i embedded.mobileprovision`) to "
                    "confirm the app does not request more entitlements than necessary "
                    "(get-task-allow=true, com.apple.developer.networking.HotspotConfiguration, etc.)."
                ),
                remediation="Review entitlements for least-privilege. Production builds should not have get-task-allow=true (no debugger attach in production).",
                endpoint=str(prov_path.relative_to(extract_dir)),
            ))

        binary_path = self._find_main_binary(app_bundle, bundle_name)
        if binary_path and tool_available("otool"):
            findings.extend(await self._check_binary_hardening(binary_path, ipa_path, bundle_name))

        return findings

    def _check_info_plist(self, plist_path: Path, ipa_path: str, bundle_name: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            with plist_path.open("rb") as f:
                plist = plistlib.load(f)
        except (plistlib.InvalidFileException, OSError, ValueError) as e:
            return [Finding(
                title=f"Cannot parse Info.plist ({bundle_name})",
                severity=Severity.LOW,
                category="mobile_misconfig",
                owasp_category="M8",
                description=f"plistlib could not parse Info.plist: {e}",
                remediation="Verify the IPA is unmodified.",
                endpoint=str(plist_path),
            )]

        ats = plist.get("NSAppTransportSecurity")
        if ats is None:
            findings.append(Finding(
                title=f"No NSAppTransportSecurity declared ({bundle_name})",
                severity=Severity.LOW,
                category="mobile_communication",
                owasp_category="M5",
                description=(
                    "The app does not declare an NSAppTransportSecurity dictionary in Info.plist. "
                    "ATS enforces secure connections by default, but auditors should confirm this "
                    "is intentional and that no compatibility shims have weakened it elsewhere."
                ),
                remediation="Explicitly declare NSAppTransportSecurity with NSAllowsArbitraryLoads=false to make the security posture auditable.",
                endpoint=str(plist_path),
            ))
        else:
            if ats.get("NSAllowsArbitraryLoads") is True:
                findings.append(Finding(
                    title=f"ATS bypass: NSAllowsArbitraryLoads=true ({bundle_name})",
                    severity=Severity.HIGH,
                    category="mobile_communication",
                    owasp_category="M5",
                    description=(
                        "NSAllowsArbitraryLoads=true disables App Transport Security globally. "
                        "The app can connect to any host over HTTP, with any TLS version, and "
                        "any cipher. This is a major regression from iOS defaults — credentials, "
                        "tokens, and PII can be intercepted on hostile networks."
                    ),
                    remediation="Set NSAllowsArbitraryLoads to false. If specific cleartext hosts are unavoidable, list them under NSExceptionDomains with NSExceptionAllowsInsecureHTTPLoads=true scoped to that single host.",
                    endpoint=str(plist_path),
                    parameter="NSAppTransportSecurity.NSAllowsArbitraryLoads",
                    cwe_id="CWE-319",
                    cvss_score=7.5,
                    cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
                    evidence=[Evidence(
                        request_method="STATIC",
                        request_url=str(plist_path),
                        description="NSAppTransportSecurity > NSAllowsArbitraryLoads = true",
                    )],
                ))
            if ats.get("NSAllowsArbitraryLoadsForMedia") is True:
                findings.append(Finding(
                    title=f"ATS bypass for media loads ({bundle_name})",
                    severity=Severity.MEDIUM,
                    category="mobile_communication",
                    owasp_category="M5",
                    description="NSAllowsArbitraryLoadsForMedia=true allows media (AVFoundation) to bypass ATS — media URLs can be served over HTTP.",
                    remediation="Remove NSAllowsArbitraryLoadsForMedia or scope it via NSExceptionDomains.",
                    endpoint=str(plist_path),
                    parameter="NSAppTransportSecurity.NSAllowsArbitraryLoadsForMedia",
                    cwe_id="CWE-319",
                ))
            if ats.get("NSAllowsArbitraryLoadsInWebContent") is True:
                findings.append(Finding(
                    title=f"ATS bypass for WKWebView ({bundle_name})",
                    severity=Severity.MEDIUM,
                    category="mobile_communication",
                    owasp_category="M5",
                    description="NSAllowsArbitraryLoadsInWebContent=true allows WKWebView to load HTTP — JavaScript injection on hostile networks becomes feasible.",
                    remediation="Remove NSAllowsArbitraryLoadsInWebContent or scope via NSExceptionDomains.",
                    endpoint=str(plist_path),
                    parameter="NSAppTransportSecurity.NSAllowsArbitraryLoadsInWebContent",
                    cwe_id="CWE-319",
                ))

        url_types = plist.get("CFBundleURLTypes") or []
        for ut in url_types:
            schemes = ut.get("CFBundleURLSchemes") or []
            for scheme in schemes:
                if not scheme:
                    continue
                findings.append(Finding(
                    title=f"Custom URL scheme: {scheme}://",
                    severity=Severity.LOW,
                    category="mobile_misconfig",
                    owasp_category="M4",
                    description=(
                        f"App registers the {scheme}:// URL scheme. Custom URL schemes are not "
                        f"unique — any other app on the device can claim the same scheme and "
                        f"intercept inbound deep links. If the app uses URL schemes for OAuth "
                        f"callbacks or sensitive data, an attacker app can hijack the flow. "
                        f"Universal Links are the secure replacement."
                    ),
                    remediation="Migrate to Universal Links (associated domains + apple-app-site-association). At minimum, validate the source of inbound URL parameters and never trust them as authenticated.",
                    endpoint=str(plist_path),
                    parameter=f"CFBundleURLTypes.CFBundleURLSchemes={scheme}",
                    cwe_id="CWE-939",
                ))

        return findings

    def _find_main_binary(self, app_bundle: Path, bundle_name: str) -> Path | None:
        candidate = app_bundle / bundle_name.removesuffix(".app")
        if candidate.is_file():
            return candidate
        for child in app_bundle.iterdir():
            if child.is_file() and not child.suffix:
                return child
        return None

    async def _check_binary_hardening(self, binary_path: Path, ipa_path: str, bundle_name: str) -> list[Finding]:
        findings: list[Finding] = []
        res = await run_tool(["otool", "-hv", str(binary_path)], timeout=30)
        if res.returncode != 0:
            return findings
        flags = res.stdout
        if "PIE" not in flags:
            findings.append(Finding(
                title=f"Binary missing PIE flag ({bundle_name})",
                severity=Severity.MEDIUM,
                category="mobile_binary",
                owasp_category="M7",
                description="The Mach-O binary is not Position Independent. ASLR is partially defeated — exploit primitives become more reliable.",
                remediation="Enable PIE in Xcode build settings (it is the default on modern toolchains).",
                endpoint=str(binary_path),
                cwe_id="CWE-693",
                cvss_score=4.3,
                cvss_vector="CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:N",
                evidence=[Evidence(
                    request_method="STATIC",
                    request_url=f"otool -hv {binary_path.name}",
                    description=flags[-500:],
                )],
            ))
        return findings
