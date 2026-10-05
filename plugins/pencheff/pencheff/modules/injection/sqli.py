"""SQL injection testing backed by the first-party sqlprobe engine."""

from __future__ import annotations

from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from pencheff.config import Severity
from pencheff.core.findings import Evidence, Finding
from pencheff.core.http_client import PencheffHTTPClient
from pencheff.core.session import PentestSession
from pencheff.core.sqlprobe import ProbeFinding, assess
from pencheff.modules.base import BaseTestModule
from pencheff.modules.injection import param_names


class SQLiModule(BaseTestModule):
    name = "sqli"
    category = "injection"
    owasp_categories = ["A03"]
    description = "Safe SQL injection testing with error, boolean, time, UNION-shape, and stacked-query probes"

    def get_techniques(self) -> list[str]:
        return ["error", "boolean", "time", "union", "stacked"]

    async def run(
        self,
        session: PentestSession,
        http: PencheffHTTPClient,
        targets: list[str] | None = None,
        config: dict[str, Any] | None = None,
    ) -> list[Finding]:
        del http
        config = config or {}
        endpoints = self._get_target_endpoints(session, targets)
        findings: list[Finding] = []

        for ep in self._cap_endpoints(endpoints, config.get("max_endpoints", 30)):
            url = ep["url"]
            method = ep.get("method", "GET")
            params = param_names(ep.get("params", []))
            data = ep.get("data") or ep.get("body")
            url, data, params = _ensure_parameterized(url, method, data, params)
            if not params:
                continue

            try:
                result = await assess(
                    url,
                    method=method,
                    data=data,
                    parameters=params,
                    techniques=set(config.get("techniques") or ["error", "boolean", "time", "union", "stacked"]),
                    profile=config.get("profile", "standard"),
                    level=config.get("level"),
                    risk=config.get("risk", 2),
                    timeout=config.get("timeout", 8.0),
                    delay=config.get("delay", 2),
                    verify_ssl=config.get("verify_ssl", False),
                    anti_cache=True,
                    traffic_log=config.get("traffic_log"),
                )
            except Exception:
                continue

            for probe_finding in result.findings:
                findings.append(_to_finding(probe_finding, method, url))

        return findings


def _ensure_parameterized(
    url: str,
    method: str,
    data: str | None,
    params: list[str],
) -> tuple[str, str | None, list[str]]:
    parsed = urlparse(url)
    query_names = list(parse_qs(parsed.query, keep_blank_values=True).keys())
    if query_names:
        return url, data, params or query_names
    if method.upper() == "GET" and params:
        query = urlencode({name: "1" for name in params})
        return urlunparse(parsed._replace(query=query)), data, params
    if method.upper() != "GET" and params and not data:
        return urlunparse(parsed._replace(query="")), urlencode({name: "1" for name in params}), params
    if data and not params:
        params = list(parse_qs(data, keep_blank_values=True).keys())
    return url, data, params


def _to_finding(probe: ProbeFinding, method: str, endpoint: str) -> Finding:
    severity = Severity.CRITICAL if probe.technique == "error" else Severity.HIGH
    confidence_note = f"Confidence: {probe.confidence}."
    dbms_note = f" Likely DBMS: {probe.dbms}." if probe.dbms else ""
    return Finding(
        title=f"SQL Injection ({probe.technique.title()} Probe)",
        severity=severity,
        category="injection",
        owasp_category="A03",
        description=(
            f"Pencheff SQLi probe found evidence of SQL injection in parameter "
            f"'{probe.parameter}'. {confidence_note}{dbms_note} {probe.evidence}"
        ),
        remediation="Use parameterized queries or prepared statements. Validate input by type and keep database errors out of responses.",
        endpoint=endpoint,
        parameter=probe.parameter,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        cvss_score=9.1 if severity == Severity.HIGH else 9.8,
        cwe_id="CWE-89",
        evidence=[Evidence(
            request_method=method,
            request_url=probe.url,
            request_body=f"{probe.parameter}={probe.payload}",
            response_status=probe.status_code,
            description=probe.evidence,
        )],
        references=["https://cwe.mitre.org/data/definitions/89.html"],
    )
