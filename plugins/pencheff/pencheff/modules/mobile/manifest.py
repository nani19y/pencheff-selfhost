"""AndroidManifest.xml static analyzer — debuggable, backup, cleartext, exported components."""

from __future__ import annotations

from pathlib import Path
from typing import Any
from xml.etree.ElementTree import Element, ParseError

import defusedxml.ElementTree as ET

from pencheff.config import Severity
from pencheff.core.findings import Evidence, Finding
from pencheff.core.http_client import PencheffHTTPClient
from pencheff.core.session import PentestSession
from pencheff.modules.base import BaseTestModule
from pencheff.modules.mobile import apktool

ANDROID_NS = "{http://schemas.android.com/apk/res/android}"


def _attr(elem: Element, name: str) -> str | None:
    return elem.attrib.get(f"{ANDROID_NS}{name}")


class AndroidManifestModule(BaseTestModule):
    """Decompile APK with apktool, parse AndroidManifest.xml, emit findings."""

    name = "android_manifest"
    category = "mobile_misconfig"
    owasp_categories = ["M8"]
    description = "AndroidManifest.xml static checks: debuggable, backup, cleartext, exported components"

    def get_techniques(self) -> list[str]:
        return [
            "debuggable_flag",
            "allow_backup",
            "cleartext_traffic",
            "exported_components",
            "min_sdk_version",
            "network_security_config",
        ]

    async def run(
        self,
        session: PentestSession,
        http: PencheffHTTPClient,
        targets: list[str] | None = None,
        config: dict[str, Any] | None = None,
    ) -> list[Finding]:
        cfg = config or {}
        apk_path = cfg.get("apk_path")
        if not apk_path:
            return []

        decomp = await apktool.decompile(apk_path)
        if "error" in decomp:
            return [Finding(
                title="apktool not installed — manifest analysis skipped",
                severity=Severity.INFO,
                category="mobile_misconfig",
                owasp_category="M8",
                description=decomp["error"],
                remediation=decomp.get("install_hint", "Install apktool"),
                endpoint=apk_path,
            )]

        out_dir = decomp.get("output_dir")
        if not out_dir:
            return []
        manifest_path = Path(out_dir) / "AndroidManifest.xml"
        if not manifest_path.is_file():
            return []

        try:
            tree = ET.parse(manifest_path)
        except (ParseError, ET.EntitiesForbidden, ET.DTDForbidden, ET.ExternalReferenceForbidden) as e:
            return [Finding(
                title="AndroidManifest.xml parse error",
                severity=Severity.LOW,
                category="mobile_misconfig",
                owasp_category="M8",
                description=f"Could not parse decompiled manifest: {e}",
                remediation="Inspect the manifest manually with `apktool d` output.",
                endpoint=apk_path,
            )]
        root = tree.getroot()
        package = root.attrib.get("package", "<unknown>")
        findings: list[Finding] = []

        app = root.find("application")
        if app is not None:
            if _attr(app, "debuggable") == "true":
                findings.append(Finding(
                    title=f"Debuggable APK ({package})",
                    severity=Severity.HIGH,
                    category="mobile_misconfig",
                    owasp_category="M8",
                    description=(
                        "android:debuggable=\"true\" is set on <application>. Anyone who can "
                        "install the APK can attach a debugger (jdb / Android Studio), inspect "
                        "memory, dump variables, and execute arbitrary code in the app's context. "
                        "Production builds must never ship with this flag enabled."
                    ),
                    remediation="Remove android:debuggable from AndroidManifest.xml or set it to false. Ensure release builds use the release variant in build.gradle.",
                    endpoint=apk_path,
                    parameter="application@android:debuggable",
                    cwe_id="CWE-489",
                    cvss_score=7.4,
                    cvss_vector="CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
                    evidence=[Evidence(
                        request_method="STATIC",
                        request_url=str(manifest_path),
                        description="<application android:debuggable=\"true\" ...>",
                    )],
                    references=["https://developer.android.com/guide/topics/manifest/application-element#debug"],
                ))

            backup_attr = _attr(app, "allowBackup")
            if backup_attr is None or backup_attr == "true":
                findings.append(Finding(
                    title=f"Backup allowed — local data exfiltration ({package})",
                    severity=Severity.MEDIUM,
                    category="mobile_storage",
                    owasp_category="M9",
                    description=(
                        "android:allowBackup is true (or unset and defaults to true on older "
                        "Android). An attacker with adb access (or who tricks the user with a "
                        "rogue USB cable) can run `adb backup` and exfiltrate the app's private "
                        "data — shared_prefs, databases, internal files."
                    ),
                    remediation="Set android:allowBackup=\"false\" in <application>, or supply an explicit android:fullBackupContent / android:dataExtractionRules to whitelist what may be backed up.",
                    endpoint=apk_path,
                    parameter="application@android:allowBackup",
                    cwe_id="CWE-200",
                    cvss_score=5.5,
                    cvss_vector="CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
                    evidence=[Evidence(
                        request_method="STATIC",
                        request_url=str(manifest_path),
                        description=f"android:allowBackup={backup_attr or '(unset, defaults to true)'}",
                    )],
                ))

            if _attr(app, "usesCleartextTraffic") == "true":
                findings.append(Finding(
                    title=f"Cleartext traffic permitted ({package})",
                    severity=Severity.MEDIUM,
                    category="mobile_communication",
                    owasp_category="M5",
                    description=(
                        "android:usesCleartextTraffic=\"true\" allows the app to communicate over "
                        "plain HTTP. Any traffic to such endpoints is interceptable on a hostile "
                        "network (Wi-Fi MitM) — credentials, tokens, PII can be stolen."
                    ),
                    remediation="Remove the attribute (defaults to false on API 28+) and enforce HTTPS for all endpoints. If specific cleartext hosts are unavoidable, use a networkSecurityConfig that whitelists them narrowly.",
                    endpoint=apk_path,
                    parameter="application@android:usesCleartextTraffic",
                    cwe_id="CWE-319",
                    cvss_score=6.5,
                    cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
                    evidence=[Evidence(
                        request_method="STATIC",
                        request_url=str(manifest_path),
                        description="<application android:usesCleartextTraffic=\"true\" ...>",
                    )],
                ))

            if _attr(app, "networkSecurityConfig") is None:
                findings.append(Finding(
                    title=f"No networkSecurityConfig declared ({package})",
                    severity=Severity.LOW,
                    category="mobile_communication",
                    owasp_category="M5",
                    description=(
                        "The app does not declare a networkSecurityConfig. This means it relies on "
                        "platform defaults for trust anchors and cleartext rules — making it harder "
                        "to enforce certificate pinning or to disallow user-installed CAs (commonly "
                        "used for MitM with tools like mitmproxy)."
                    ),
                    remediation="Add a res/xml/network_security_config.xml that pins production certs, disallows user-CAs, and forbids cleartext traffic. Reference it from <application android:networkSecurityConfig>.",
                    endpoint=apk_path,
                    parameter="application@android:networkSecurityConfig",
                    cwe_id="CWE-295",
                    cvss_score=3.7,
                    cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N",
                ))

            for tag in ("activity", "service", "receiver", "provider"):
                for elem in app.findall(tag):
                    exported = _attr(elem, "exported")
                    permission = _attr(elem, "permission")
                    has_intent_filter = elem.find("intent-filter") is not None
                    is_exported = exported == "true" or (exported is None and has_intent_filter)
                    if is_exported and not permission:
                        comp_name = _attr(elem, "name") or "<anonymous>"
                        findings.append(Finding(
                            title=f"Exported {tag} without permission: {comp_name}",
                            severity=Severity.MEDIUM,
                            category="mobile_misconfig",
                            owasp_category="M8",
                            description=(
                                f"<{tag} android:name=\"{comp_name}\"> is exported (either explicitly "
                                f"or implicitly via an <intent-filter>) and is not protected by an "
                                f"android:permission. Any other app on the device can invoke it, "
                                f"potentially triggering privileged operations, leaking data, or "
                                f"providing an entry point for chained attacks (intent redirection, "
                                f"task hijacking, content-provider SQL injection)."
                            ),
                            remediation=f"Either set android:exported=\"false\" if the component is internal-only, or guard it with android:permission=\"<your.signature.permission>\" requiring a signature-level permission.",
                            endpoint=apk_path,
                            parameter=f"{tag}@{comp_name}",
                            cwe_id="CWE-926",
                            cvss_score=5.3,
                            cvss_vector="CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",
                            evidence=[Evidence(
                                request_method="STATIC",
                                request_url=str(manifest_path),
                                description=f"<{tag} name=\"{comp_name}\" exported={exported} permission={permission}>",
                            )],
                        ))

        sdk = root.find("uses-sdk")
        if sdk is not None:
            min_sdk = _attr(sdk, "minSdkVersion")
            if min_sdk and min_sdk.isdigit() and int(min_sdk) < 24:
                findings.append(Finding(
                    title=f"Dangerously low minSdkVersion: {min_sdk} ({package})",
                    severity=Severity.MEDIUM,
                    category="mobile_misconfig",
                    owasp_category="M8",
                    description=(
                        f"minSdkVersion={min_sdk} (Android < 7.0). Older Android versions lack key "
                        f"hardening (network security config defaults, Scoped Storage, modern TLS). "
                        f"Devices on this minimum miss security mitigations and inherit known CVEs."
                    ),
                    remediation="Raise minSdkVersion to at least 24 (Android 7.0) — ideally 28+ — in build.gradle.",
                    endpoint=apk_path,
                    parameter="uses-sdk@minSdkVersion",
                    cwe_id="CWE-1104",
                    cvss_score=4.3,
                    cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N",
                ))

        return findings


async def check_apk(apk_path: str) -> dict[str, Any]:
    """Standalone wrapper for scan_mobile_app MCP tool — no session/http needed."""
    from pencheff.core.session import create_session
    from pencheff.core.http_client import PencheffHTTPClient
    import httpx
    session = create_session(apk_path)
    async with httpx.AsyncClient() as _c:
        http = PencheffHTTPClient(_c)
        findings = await AndroidManifestModule().run(
            session, http, config={"apk_path": apk_path}
        )
    return {
        "findings_count": len(findings),
        "findings": [{"title": f.title, "severity": f.severity.value,
                       "description": f.description} for f in findings],
    }
