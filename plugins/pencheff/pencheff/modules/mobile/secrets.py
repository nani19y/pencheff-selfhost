"""Mobile secrets sweep — regex over jadx-decompiled .java for hardcoded creds, keys, tokens."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from pencheff.config import Severity
from pencheff.core.findings import Evidence, Finding
from pencheff.core.http_client import PencheffHTTPClient
from pencheff.core.session import PentestSession
from pencheff.modules.base import BaseTestModule
from pencheff.modules.mobile import jadx

SECRET_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    ("AWS Access Key ID", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "M1"),
    ("AWS Secret Access Key", re.compile(r"(?i)aws(.{0,20})?(secret|private)?(.{0,20})?(key|access)[\"'\s:=]+[A-Za-z0-9/+=]{40}"), "M1"),
    ("Google API Key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), "M1"),
    ("Firebase URL", re.compile(r"https?://[a-z0-9\-]+\.firebaseio\.com"), "M1"),
    ("Firebase Database (no-auth)", re.compile(r"firebaseio\.com/\.json"), "M1"),
    ("Slack Token", re.compile(r"\bxox[abprs]-[A-Za-z0-9\-]{10,}\b"), "M1"),
    ("GitHub Token", re.compile(r"\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b"), "M1"),
    ("Stripe Secret Key", re.compile(r"\b(sk_live|rk_live)_[A-Za-z0-9]{24,}\b"), "M1"),
    ("Generic JWT", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}+\.[A-Za-z0-9_\-]{10,}+\.[A-Za-z0-9_\-]{10,}+\b"), "M1"),
    ("Hardcoded Password Assignment", re.compile(r"(?i)(password|passwd|pwd)\s*=\s*[\"'][^\"']{4,40}[\"']"), "M1"),
    ("Private Key (PEM)", re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"), "M1"),
    ("Twilio API Key", re.compile(r"\bSK[a-f0-9]{32}\b"), "M1"),
    ("SendGrid API Key", re.compile(r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b"), "M1"),
    ("Mailgun API Key", re.compile(r"\bkey-[a-f0-9]{32}\b"), "M1"),
]

CLEARTEXT_URL = re.compile(r"\bhttp://(?!localhost|127\.0\.0\.1|10\.|192\.168\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|schemas\.|www\.w3\.org|www\.example\.com)[a-zA-Z0-9.\-/_:]+")

MAX_FILES_SCANNED = 5000
MAX_HITS_PER_KIND = 25
MAX_BYTES_PER_FILE = 5_000_000  # 5 MB cap — bounds ReDoS and memory pressure on adversarial inputs


class MobileSecretsModule(BaseTestModule):
    """jadx-decompile the APK and grep for hardcoded secrets, keys, tokens, and cleartext URLs."""

    name = "mobile_secrets"
    category = "mobile_secrets"
    owasp_categories = ["M1", "M5"]
    description = "Hardcoded credentials, API keys, tokens, and cleartext URL detection in decompiled code"

    def get_techniques(self) -> list[str]:
        return [
            "regex_secret_sweep",
            "cleartext_url_detection",
            "private_key_detection",
            "api_token_detection",
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

        decomp = await jadx.recover(apk_path)
        if "error" in decomp:
            return [Finding(
                title="jadx not installed — secrets sweep skipped",
                severity=Severity.INFO,
                category="mobile_secrets",
                owasp_category="M1",
                description=decomp["error"],
                remediation=decomp.get("install_hint", "Install jadx"),
                endpoint=apk_path,
            )]

        out_dir = decomp.get("output_dir")
        if not out_dir:
            return []
        root = Path(out_dir)

        findings: list[Finding] = []
        hits_by_kind: dict[str, int] = {}
        cleartext_hits = 0
        files_scanned = 0

        for path in root.rglob("*.java"):
            if files_scanned >= MAX_FILES_SCANNED:
                break
            files_scanned += 1
            try:
                with path.open("rb") as f:
                    raw = f.read(MAX_BYTES_PER_FILE)
                text = raw.decode("utf-8", errors="replace")
            except OSError:
                continue

            for label, pattern, owasp in SECRET_PATTERNS:
                if hits_by_kind.get(label, 0) >= MAX_HITS_PER_KIND:
                    continue
                for m in pattern.finditer(text):
                    hits_by_kind[label] = hits_by_kind.get(label, 0) + 1
                    line_no = text.count("\n", 0, m.start()) + 1
                    snippet = self._line_snippet(text, m.start())
                    findings.append(Finding(
                        title=f"Hardcoded secret: {label}",
                        severity=Severity.HIGH if "Private Key" in label or "AWS" in label or "Stripe" in label else Severity.MEDIUM,
                        category="mobile_secrets",
                        owasp_category=owasp,
                        description=(
                            f"A {label} appears to be embedded in the app's compiled code. "
                            f"Anyone who downloads the APK can extract this value with `jadx` "
                            f"in seconds and use it to impersonate the app, abuse paid quota, "
                            f"or pivot into backend services."
                        ),
                        remediation=(
                            "Remove the hardcoded secret. Move authentication to a server-side "
                            "exchange (the app authenticates a user, the server holds the API key). "
                            "If a per-app credential is unavoidable, fetch it dynamically over an "
                            "authenticated channel and store in the Android Keystore. Rotate the "
                            "leaked credential immediately."
                        ),
                        endpoint=str(path.relative_to(root)),
                        parameter=f"line:{line_no}",
                        cwe_id="CWE-798",
                        cvss_score=7.5,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                        evidence=[Evidence(
                            request_method="STATIC",
                            request_url=f"{path.relative_to(root)}:{line_no}",
                            description=snippet,
                        )],
                        references=["https://owasp.org/www-project-mobile-top-10/2023-risks/m1-improper-credential-usage"],
                    ))
                    if hits_by_kind[label] >= MAX_HITS_PER_KIND:
                        break

            if cleartext_hits < MAX_HITS_PER_KIND:
                for m in CLEARTEXT_URL.finditer(text):
                    cleartext_hits += 1
                    line_no = text.count("\n", 0, m.start()) + 1
                    snippet = self._line_snippet(text, m.start())
                    findings.append(Finding(
                        title=f"Cleartext URL in code: {m.group()[:60]}",
                        severity=Severity.LOW,
                        category="mobile_communication",
                        owasp_category="M5",
                        description=(
                            f"Hardcoded http:// URL found. Any traffic to this endpoint is "
                            f"sent in plaintext and is interceptable on a hostile network."
                        ),
                        remediation="Use https:// for the endpoint, or remove the URL if dead code. Add the host to networkSecurityConfig if a narrow exception is required.",
                        endpoint=str(path.relative_to(root)),
                        parameter=f"line:{line_no}",
                        cwe_id="CWE-319",
                        cvss_score=4.3,
                        cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
                        evidence=[Evidence(
                            request_method="STATIC",
                            request_url=f"{path.relative_to(root)}:{line_no}",
                            description=snippet,
                        )],
                    ))
                    if cleartext_hits >= MAX_HITS_PER_KIND:
                        break

        return findings

    @staticmethod
    def _line_snippet(text: str, pos: int, width: int = 120) -> str:
        line_start = text.rfind("\n", 0, pos) + 1
        line_end = text.find("\n", pos)
        if line_end == -1:
            line_end = len(text)
        line = text[line_start:line_end].strip()
        if len(line) > width:
            line = line[:width] + "..."
        return line


async def scan_apk(apk_path: str) -> dict[str, Any]:
    """Standalone wrapper for scan_mobile_app MCP tool — no session/http needed."""
    from typing import Any as _Any
    from pencheff.core.session import create_session
    from pencheff.core.http_client import PencheffHTTPClient
    import httpx
    session = create_session(apk_path)
    async with httpx.AsyncClient() as _c:
        http = PencheffHTTPClient(_c)
        findings = await MobileSecretsModule().run(
            session, http, config={"apk_path": apk_path}
        )
    return {
        "findings_count": len(findings),
        "findings": [{"title": f.title, "severity": f.severity.value,
                       "description": f.description} for f in findings],
    }
