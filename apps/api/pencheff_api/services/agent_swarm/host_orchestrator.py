"""Network Host / IP orchestrator — live TCP port scan + service-exposure posture.

Minimal server-side implementation of the ``host`` target kind: runs the
pure-Python async port scanner (``pencheff.core.netmap.scan_targets``) against
the target's ``kind_config.hosts`` and turns reachable ports into findings
(exposed data stores / management services / web endpoints). No OS-level
exploitation — that is the deferred OSExploitAgent (sub-project B). This gives
the UI a working, read-only network-exposure scan for a host target.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select

# Data stores that are catastrophic to expose unauthenticated to the internet.
_CRITICAL_SVC = {"Redis", "MongoDB", "Memcached", "Elasticsearch"}
# Remote-access / management / DB services that should never face the internet.
_HIGH_SVC = {
    "SSH", "RDP", "VNC", "SMB", "Telnet", "WinRM", "FTP", "NFS", "RPCBind",
    "NetBIOS", "NetBIOS-NS", "SNMP", "MySQL", "PostgreSQL", "MSSQL", "Oracle",
}
_WEB_PORTS = {80, 443, 8080, 8443, 8888}


def _finding_for_port(host: str, pr: Any) -> dict[str, Any]:
    svc = pr.service or "unknown"
    port = pr.port
    ver = (pr.version or pr.banner or "").strip()
    where = f"{host}:{port}"
    if svc in _CRITICAL_SVC:
        sev, owasp = "critical", "NET-01 Exposed Data Store"
        title = f"Exposed {svc} data store on the internet: {where}"
        desc = (f"A {svc} service is reachable from the public internet on {where}. "
                "These data stores commonly ship with no authentication and allow full data access.")
        rem = f"Bind {svc} to a private interface and restrict access to a trusted CIDR / security group; never expose it publicly."
    elif svc in _HIGH_SVC:
        sev, owasp = "high", "NET-02 Exposed Management Service"
        title = f"{svc} exposed to the internet: {where}"
        desc = f"The {svc} service on {where} accepts connections from any source address (0.0.0.0/0)."
        rem = f"Restrict {svc} to a bastion/VPN CIDR via the host firewall / security group; do not allow 0.0.0.0/0."
    elif port in _WEB_PORTS:
        sev, owasp = "low", "NET-03 Service Exposure"
        title = f"Web service exposed: {where} ({svc})"
        desc = f"An HTTP(S) service is reachable on {where}. Ensure it is intended to be public and hardened."
        rem = "Confirm the endpoint is meant to be public; enforce TLS, security headers, and a WAF as appropriate."
    else:
        sev, owasp = "medium", "NET-03 Service Exposure"
        title = f"Open port exposed to the internet: {where} ({svc})"
        desc = f"Port {port}/tcp ({svc}) on {host} is reachable from the public internet."
        rem = "Close the port or restrict it to trusted source ranges via the host firewall / security group."
    return {
        "title": title, "severity": sev, "category": "network",
        "owasp_category": owasp, "description": desc, "remediation": rem,
        "endpoint": where, "parameter": svc,
        "evidence": {"host": host, "port": port, "service": svc,
                     "banner": ver or None, "protocol": pr.protocol},
    }


def _host_evidence(f: dict[str, Any]) -> list[dict[str, Any]]:
    ev = f.get("evidence") or {}
    detail = {k: v for k, v in ev.items() if v is not None}
    import json
    return [{
        "request_url": f.get("endpoint"),
        "description": f.get("description"),
        "response_body_snippet": json.dumps(detail, indent=2, default=str) if detail else None,
    }]


async def run_host_orchestrator(*, scan_id: str, target: Any, Session: Any,
                                kind_credentials: dict | None = None) -> None:
    """Live TCP port-scan posture check for a host-kind target."""
    from ...db.models import Finding as DbFinding
    from ...db.models import Scan
    from ...events import publish_scan_event
    from ..grader import compute as compute_grade
    from types import SimpleNamespace
    from pencheff.core.netmap import parse_ports, scan_targets

    cfg = dict(target.kind_config or {})
    hosts = [h for h in (cfg.get("hosts") or []) if isinstance(h, str) and h.strip()]

    async def _log(msg: str) -> None:
        async with Session() as db:
            s = (await db.execute(select(Scan).where(Scan.id == scan_id))).scalar_one()
            s.log = (list(s.log or []) + [msg])[-1000:]
            await db.commit()

    await _log(f"[Host] port-scanning {len(hosts)} host(s): {', '.join(hosts) or '(none)'}")
    publish_scan_event(scan_id, {"type": "stage_start", "label": "host: TCP port scan", "pct": None})

    findings: list[dict[str, Any]] = []
    if hosts:
        ports = parse_ports("top-100")
        result = await scan_targets(hosts, ports, banners=True, version_detection=True, timeout=3.0)
        for pr in result.open:
            findings.append(_finding_for_port(pr.host, pr))
        await _log(f"[Host] scanned {result.scanned_count} port(s); {len(result.open)} open; {len(findings)} findings")
        from .trace import finding_lines, log_scan_trace
        await log_scan_trace(Session, scan_id, finding_lines("Host", "host", findings))

    score, grade, _ = compute_grade(
        [SimpleNamespace(severity=f["severity"], suppressed=False, verification_status=None) for f in findings],
        target_kind="host",
    )
    counts = {s: 0 for s in ("critical", "high", "medium", "low", "info")}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    def _clip(v, n):
        return v[:n] if isinstance(v, str) and len(v) > n else v

    async with Session() as db:
        for f in findings:
            db.add(DbFinding(
                scan_id=scan_id,
                title=_clip(f["title"], 500), severity=_clip(f["severity"], 16),
                category=_clip(f["category"], 64), owasp_category=_clip(f["owasp_category"], 32),
                description=f["description"][:4000], remediation=f["remediation"][:4000] or None,
                endpoint=_clip(f["endpoint"], 2048), parameter=_clip(f["parameter"], 200),
                evidence=_host_evidence(f),
            ))
        s = (await db.execute(select(Scan).where(Scan.id == scan_id))).scalar_one()
        s.status = "done"
        s.progress_pct = 100
        s.current_stage = "complete"
        s.finished_at = datetime.now(timezone.utc)
        s.grade = grade
        s.score = score
        s.summary = {**(s.summary or {}), **counts, "kind": "host",
                     "hosts_scanned": len(hosts)}
        await db.commit()

    from .trace import enqueue_validation
    enqueue_validation(scan_id)
    publish_scan_event(scan_id, {"type": "finished", "scan_id": scan_id, "total_findings": len(findings)})
