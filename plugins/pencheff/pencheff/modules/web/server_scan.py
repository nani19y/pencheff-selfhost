"""Web server exposure scanning backed by the first-party webscan engine."""

from __future__ import annotations

from typing import Any

from pencheff.config import Severity
from pencheff.core.findings import Evidence, Finding
from pencheff.core.http_client import PencheffHTTPClient
from pencheff.core.session import PentestSession
from pencheff.core.webscan import WebFinding, scan
from pencheff.modules.base import BaseTestModule


SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}


class WebServerScanModule(BaseTestModule):
    name = "web_server_scan"
    category = "misconfiguration"
    owasp_categories = ["A05", "A01"]
    description = "Safe first-party web server exposure scanner"

    def get_techniques(self) -> list[str]:
        return [
            "headers",
            "cookies",
            "http_methods",
            "interesting_paths",
            "default_files",
            "disclosure_patterns",
        ]

    async def run(
        self,
        session: PentestSession,
        http: PencheffHTTPClient,
        targets: list[str] | None = None,
        config: dict[str, Any] | None = None,
    ) -> list[Finding]:
        del http
        config = config or {}
        target_urls = targets or [session.target.base_url]
        findings: list[Finding] = []

        for target in target_urls[: config.get("max_targets", 5)]:
            try:
                result = await scan(
                    target,
                    profile=config.get("profile", "standard"),
                    timeout=config.get("timeout", 8.0),
                    verify_ssl=config.get("verify_ssl", False),
                    headers=config.get("headers"),
                    cookie=config.get("cookie"),
                    proxy=config.get("proxy"),
                    concurrency=config.get("concurrency", 10),
                    extra_paths=config.get("extra_paths"),
                    traffic_log=config.get("traffic_log"),
                    check_db=config.get("check_db"),
                    tags=config.get("tags"),
                    tuning=config.get("tuning"),
                    auth_profile=config.get("auth_profile"),
                    suppressions=config.get("suppressions"),
                    request_encoding=config.get("request_encoding", "none"),
                    delay=config.get("delay", 0.0),
                )
            except Exception:
                continue
            findings.extend(_to_finding(item) for item in result.findings)

        return findings


def _to_finding(item: WebFinding) -> Finding:
    severity = SEVERITY_MAP.get(item.severity, Severity.INFO)
    return Finding(
        title=item.title,
        severity=severity,
        category="misconfiguration" if item.check not in {"cookies"} else "auth",
        owasp_category="A05" if item.check not in {"cookies"} else "A07",
        description=f"{item.evidence} Check: {item.check}.",
        remediation=item.remediation or "Review the exposed behavior and restrict it if not required.",
        endpoint=item.url,
        cvss_vector=_cvss_for(severity),
        cvss_score=_score_for(severity),
        cwe_id=_cwe_for(item.check),
        evidence=[Evidence(
            request_method="GET",
            request_url=item.url,
            response_status=item.status_code,
            description=item.evidence,
        )],
        references=(item.references or []) + [f"https://www.cve.org/CVERecord?id={cve}" for cve in (item.cves or [])],
    )


def _score_for(severity: Severity) -> float:
    return {
        Severity.CRITICAL: 9.1,
        Severity.HIGH: 7.5,
        Severity.MEDIUM: 5.3,
        Severity.LOW: 3.1,
        Severity.INFO: 0.0,
    }.get(severity, 0.0)


def _cvss_for(severity: Severity) -> str:
    if severity in {Severity.CRITICAL, Severity.HIGH}:
        return "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N"
    if severity == Severity.MEDIUM:
        return "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"
    if severity == Severity.LOW:
        return "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"
    return "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:N"


def _cwe_for(check: str) -> str:
    return {
        "headers": "CWE-693",
        "cookies": "CWE-614",
        "http_methods": "CWE-749",
        "trace": "CWE-693",
        "directory_listing": "CWE-548",
        "interesting_path": "CWE-552",
        "env_file": "CWE-200",
        "git_config": "CWE-527",
        "backup_artifact": "CWE-530",
        "stack_trace": "CWE-209",
        "fingerprint": "CWE-200",
    }.get(check, "CWE-200")
