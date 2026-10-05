"""High-level wrapper that runs parameter_fuzzer and emits Findings.

This turns the raw FuzzRun results into Findings that fit pencheff's standard
output format. Any ``interesting`` result (status diff, length diff, latency
spike, reflection) becomes a Finding.
"""

from __future__ import annotations

from pencheff.config import Severity
from pencheff.core.findings import Evidence, Finding
from pencheff.modules.fuzzing.parameter_fuzzer import FuzzRun


def findings_from_run(run: FuzzRun) -> list[Finding]:
    out: list[Finding] = []
    url = run.template.get("url", "")
    for r in run.results:
        if not r.interesting:
            continue
        sev = Severity.MEDIUM
        if r.reflected:
            sev = Severity.HIGH
        elif "status-diff" in r.reason and r.status == 500:
            sev = Severity.HIGH
        elif "latency-spike" in r.reason:
            sev = Severity.HIGH  # possible blind-SQLi/SSTI time-based
        out.append(Finding(
            title=f"Fuzz anomaly on '{run.param}' — {r.reason}",
            severity=sev,
            category="injection" if r.reflected else "misconfiguration",
            owasp_category="A03" if r.reflected else "A05",
            description=(
                f"Fuzzing {url} parameter '{run.param}' with payload: {r.payload[:120]}"
                f"\n→ status {r.status}, {r.resp_length} bytes, {r.latency_ms:.0f}ms. Reason: {r.reason}."
            ),
            remediation=(
                "Investigate the differential response manually — it may indicate an injection, "
                "crash path, or authz bypass. Add server-side input validation/encoding."
            ),
            endpoint=url,
            parameter=run.param,
            evidence=[Evidence(
                request_method=run.template.get("method", "GET"),
                request_url=url,
                request_body=r.payload[:500],
                response_status=r.status,
                description=f"Differential fuzz: {r.reason}",
            )],
        ))
    return out
