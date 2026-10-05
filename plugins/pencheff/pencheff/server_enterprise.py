"""Extended scanning MCP tools — registered against the same FastMCP instance.

This module is imported for its side-effects (decorator registration) from
``server.py``. Splitting it out keeps the 3k-line server.py readable.

Tools registered here cover:
  - SCA + SBOM + license workflows
  - IaC + container scanning
  - Network VA
  - Passive proxy + fuzzer
  - ASM + scheduling + integrations
  - YAML policy engine
  - Plugin SDK helpers
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from pencheff.core.session import get_session
from pencheff.server import _require_session, mcp


def _success(payload: dict[str, Any]) -> dict[str, Any]:
    return {"success": True, **payload}


def _error(msg: str, **kw: Any) -> dict[str, Any]:
    return {"success": False, "error": msg, **kw}


# ─── SCA / SBOM / Licenses ────────────────────────────────────────────

@mcp.tool()
async def scan_dependencies(
    session_id: str,
    path: str = ".",
    annotate_reachability: bool = True,
) -> dict[str, Any]:
    """Parse every supported dependency manifest under ``path`` and query OSV.dev for CVEs.

    Findings are enriched with EPSS + CISA KEV when the local CVE feed has been refreshed.
    Set ``annotate_reachability`` to mark findings as low-reachability when the package is
    not imported anywhere in the source tree.
    """
    session = _require_session(session_id)
    root = Path(path)
    if not root.exists():
        return _error(f"Path not found: {path}")

    from pencheff.modules.sca.dependency_scan import DependencyScanModule
    from pencheff.modules.sca.reachability import annotate
    from pencheff.core.http_client import PencheffHTTPClient

    http = PencheffHTTPClient(session)
    mod = DependencyScanModule()
    findings = await mod.run(session, http, config={"path": str(root)})
    if annotate_reachability:
        findings = annotate(findings, root)
    added = session.findings.add_many(findings)
    return _success({
        "findings_added": added,
        "total_findings_generated": len(findings),
        "path": str(root),
    })


@mcp.tool()
async def generate_sbom(
    session_id: str,
    path: str = ".",
    fmt: str = "cyclonedx",
    output_dir: str | None = None,
) -> dict[str, Any]:
    """Generate a CycloneDX 1.5 and/or SPDX 2.3 SBOM from ``path``.

    When ``syft`` is on PATH, we shell out to it; otherwise we use native parsers.
    Writes the SBOM to ``output_dir/<fmt>.json`` when ``output_dir`` is provided.
    """
    _require_session(session_id)
    from pencheff.modules.sca.sbom_generator import generate_sbom as _gen
    root = Path(path)
    if not root.exists():
        return _error(f"Path not found: {path}")
    result = _gen(root, fmt=fmt)
    if output_dir:
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        import json
        for k, v in result["formats"].items():
            (out / f"{k}.json").write_text(json.dumps(v, indent=2))
    return _success({
        "source": result["source"],
        "component_count": result["component_count"],
        "formats_generated": list(result["formats"].keys()),
    })


@mcp.tool()
async def check_licenses(
    session_id: str,
    path: str = ".",
    policy_file: str | None = None,
) -> dict[str, Any]:
    """Evaluate every discovered dependency against a license policy (default is
    permissive-only, denies GPL-3.0/AGPL-3.0/SSPL).
    """
    session = _require_session(session_id)
    from pencheff.modules.sca.license_compliance import evaluate
    root = Path(path)
    if not root.exists():
        return _error(f"Path not found: {path}")
    pol = Path(policy_file) if policy_file else None
    findings, summary = evaluate(root, pol)
    added = session.findings.add_many(findings)
    return _success({
        "findings_added": added,
        "license_counts": summary["counts"],
    })


# ─── IaC / Container ──────────────────────────────────────────────────

@mcp.tool()
async def scan_dockerfile(session_id: str, path: str = ".") -> dict[str, Any]:
    """Scan one or more Dockerfiles with native rules (+ hadolint + trivy if installed)."""
    session = _require_session(session_id)
    from pencheff.modules.iac.dockerfile_scan import scan
    findings = scan(Path(path))
    added = session.findings.add_many(findings)
    return _success({"findings_added": added, "total": len(findings)})


@mcp.tool()
async def scan_kubernetes(session_id: str, path: str = ".") -> dict[str, Any]:
    """Scan Kubernetes YAML manifests (Pods, Deployments, StatefulSets, Services, ...)."""
    session = _require_session(session_id)
    from pencheff.modules.iac.kubernetes_scan import scan
    findings = scan(Path(path))
    added = session.findings.add_many(findings)
    return _success({"findings_added": added, "total": len(findings)})


@mcp.tool()
async def scan_terraform(session_id: str, path: str = ".") -> dict[str, Any]:
    """Scan Terraform files with native rules + checkov + tfsec (when installed)."""
    session = _require_session(session_id)
    from pencheff.modules.iac.terraform_scan import scan
    findings = scan(Path(path))
    added = session.findings.add_many(findings)
    return _success({"findings_added": added, "total": len(findings)})


@mcp.tool()
async def scan_helm(
    session_id: str, chart_path: str, values_file: str | None = None
) -> dict[str, Any]:
    """Render a Helm chart via ``helm template`` and scan the resulting K8s manifests."""
    session = _require_session(session_id)
    from pencheff.modules.iac.helm_scan import scan
    findings = scan(Path(chart_path), Path(values_file) if values_file else None)
    added = session.findings.add_many(findings)
    return _success({"findings_added": added, "total": len(findings)})


@mcp.tool()
async def scan_container_image(
    session_id: str, image_ref: str
) -> dict[str, Any]:
    """Scan a container image reference (tag or digest) via trivy or grype."""
    session = _require_session(session_id)
    from pencheff.modules.iac.container_image_scan import scan
    findings = scan(image_ref)
    added = session.findings.add_many(findings)
    return _success({"findings_added": added, "total": len(findings)})


# ─── Network VA ───────────────────────────────────────────────────────

@mcp.tool()
async def scan_host_vulns(
    session_id: str,
    host: str | None = None,
    ports: str = "top-1000",
) -> dict[str, Any]:
    """Host CVE scan: Pencheff service detection → OSV CVE map → KEV enrichment."""
    session = _require_session(session_id)
    from pencheff.modules.network.host_cve_scan import scan
    findings = scan(host or session.target.base_url, ports)
    added = session.findings.add_many(findings)
    return _success({"findings_added": added, "total": len(findings)})


@mcp.tool()
async def scan_network_misconfig(
    session_id: str, host: str | None = None
) -> dict[str, Any]:
    """Unauthenticated-service misconfig probes: Redis, Mongo, Elastic, Memcached, Docker, MySQL, PG, SNMP."""
    session = _require_session(session_id)
    from pencheff.modules.network.network_misconfig import scan
    target_host = host or session.target.base_url.replace("http://", "").replace("https://", "").split("/")[0]
    findings = await scan(target_host)
    added = session.findings.add_many(findings)
    return _success({"findings_added": added, "total": len(findings), "host": target_host})


@mcp.tool()
async def scan_authenticated_host(
    session_id: str,
    host: str,
    protocol: str = "ssh",
    credentials_ref: str = "default",
    port: int | None = None,
) -> dict[str, Any]:
    """Authenticated host scan — log in via SSH/WinRM, enumerate packages, map to CVEs."""
    session = _require_session(session_id)
    creds = session.credentials.get(credentials_ref)
    if not creds:
        return _error(f"Credential set '{credentials_ref}' not found")

    from pencheff.modules.network.authenticated_host_scan import collect_packages
    from pencheff.modules.network.missing_patches import scan_snapshot

    snap = await collect_packages(host, creds, protocol=protocol, port=port)
    if snap is None:
        return _error(
            f"Could not collect packages over {protocol}. "
            "Verify credentials and that paramiko/pywinrm is installed."
        )
    findings = await scan_snapshot(host, snap)
    added = session.findings.add_many(findings)
    return _success({
        "findings_added": added, "total": len(findings),
        "os_name": snap.os_name, "package_count": len(snap.packages),
    })


@mcp.tool()
async def scan_industrial_protocols(
    session_id: str, host: str | None = None
) -> dict[str, Any]:
    """Check for exposed OT/SCADA protocols (Modbus, BACnet, Siemens S7, EtherNet/IP, DNP3)."""
    session = _require_session(session_id)
    from pencheff.modules.network.industrial_protocol import scan
    target = host or session.target.base_url.replace("http://", "").replace("https://", "").split("/")[0]
    findings = await scan(target)
    added = session.findings.add_many(findings)
    return _success({"findings_added": added, "total": len(findings)})


@mcp.tool()
async def refresh_cve_feed(session_id: str, force: bool = False) -> dict[str, Any]:
    """Download/refresh EPSS and CISA KEV feeds into the local SQLite cache."""
    _require_session(session_id)
    from pencheff.core.cve_feed import get_feed
    feed = get_feed()
    result = await feed.refresh(force=force)
    return _success(result)


# ─── Proxy + fuzzer + passive scan ────────────────────────────────────

@mcp.tool()
async def start_proxy(session_id: str, port: int = 8888) -> dict[str, Any]:
    """Start an intercepting proxy (mitmproxy backend). Point your app at this port to
    passively capture and scan traffic. Returns the listening port + mode."""
    session = _require_session(session_id)
    from pencheff.core.proxy import start_proxy as _start
    st = _start(session, port)
    return _success({"port": st.port, "mode": st.mode, "pid": st.pid})


@mcp.tool()
async def stop_proxy(session_id: str) -> dict[str, Any]:
    """Stop the intercepting proxy and drop its process."""
    _require_session(session_id)
    from pencheff.core.proxy import stop_proxy as _stop
    ok = _stop(session_id)
    return _success({"stopped": ok})


@mcp.tool()
async def get_proxy_traffic(
    session_id: str, since: float | None = None, include_passive_findings: bool = True
) -> dict[str, Any]:
    """Return flows captured by the proxy since ``since`` (unix ts), plus optional
    passive-scanner findings derived from them."""
    session = _require_session(session_id)
    from pencheff.core.proxy import get_traffic, run_passive_on_flows
    flows = get_traffic(session_id, since)
    out: dict[str, Any] = {
        "flows": [
            {
                "method": f.method, "url": f.url, "status": f.status,
                "timestamp": f.timestamp,
                "resp_len": len(f.resp_body or ""),
            } for f in flows
        ],
        "count": len(flows),
    }
    if include_passive_findings and flows:
        findings = run_passive_on_flows(session, flows)
        added = session.findings.add_many(findings)
        out["passive_findings_added"] = added
    return _success(out)


@mcp.tool()
async def fuzz_parameter(
    session_id: str,
    url: str,
    method: str = "GET",
    param: str = "FUZZ",
    wordlist: str = "xss-quick",
    encoders: list[str] | None = None,
    headers: dict[str, str] | None = None,
    body: str | None = None,
    concurrency: int = 8,
) -> dict[str, Any]:
    """Differential fuzzer: iterate a wordlist against a parameter, compare responses,
    emit Findings for anomalies (status-diff, length-diff, latency-spike, reflection)."""
    session = _require_session(session_id)
    from pencheff.modules.fuzzing.parameter_fuzzer import run as fuzz_run
    from pencheff.modules.fuzzing.differential_fuzzer import findings_from_run

    template = {"url": url, "method": method, "headers": headers or {}, "body": body}
    run = await fuzz_run(
        template, param=param, wordlist=wordlist,
        encoders=encoders, concurrency=concurrency,
    )
    findings = findings_from_run(run)
    added = session.findings.add_many(findings)
    return _success({
        "wordlist": wordlist,
        "encoders": list(encoders or []),
        "total_results": len(run.results),
        "interesting": sum(1 for r in run.results if r.interesting),
        "findings_added": added,
    })


@mcp.tool()
async def list_fuzz_wordlists(session_id: str) -> dict[str, Any]:
    """List bundled fuzzer wordlists."""
    _require_session(session_id)
    from pencheff.modules.fuzzing.parameter_fuzzer import list_wordlists
    return _success({"wordlists": list_wordlists()})


@mcp.tool()
async def run_policy(session_id: str, policy_path: str) -> dict[str, Any]:
    """Execute a YAML ScanPolicy (Pencheff automation framework v1)."""
    _require_session(session_id)
    from pencheff.core.policy_engine import load, run
    p = Path(policy_path)
    if not p.exists():
        return _error(f"Policy file not found: {policy_path}")
    policy = load(p)
    result = await run(policy)
    return _success({
        "policy": policy.name,
        "session_id": result.session.id,
        "module_results": result.module_results,
        "assertions": result.assertions,
        "failed": result.failed,
        "findings": result.session.findings.summary(),
    })


# ─── ASM / Scheduling / Integrations / Plugin SDK ─────────────────────

@mcp.tool()
async def asm_discover(
    session_id: str, org: str, root_domain: str
) -> dict[str, Any]:
    """Run passive attack-surface discovery (subfinder + crt.sh + optional Shodan)
    and update the asset inventory for ``org``."""
    _require_session(session_id)
    from pencheff.modules.asm.continuous_discovery import discover
    counts = await discover(org, root_domain)
    return _success(counts)


@mcp.tool()
async def asm_list_assets(
    session_id: str, org: str, asset_type: str | None = None
) -> dict[str, Any]:
    """List assets currently in the inventory for ``org``."""
    _require_session(session_id)
    from pencheff.modules.asm.asset_inventory import list_assets, to_dict
    assets = list_assets(org, asset_type)
    return _success({"count": len(assets), "assets": [to_dict(a) for a in assets]})


@mcp.tool()
async def asm_diff(session_id: str, org: str) -> dict[str, Any]:
    """Diff current inventory against the last snapshot; emit Findings for new assets."""
    session = _require_session(session_id)
    from pencheff.modules.asm.change_detection import snapshot_and_diff
    findings = snapshot_and_diff(org)
    added = session.findings.add_many(findings)
    return _success({"new_assets": len(findings), "findings_added": added})


@mcp.tool()
async def asm_cert_watch(session_id: str, domain: str) -> dict[str, Any]:
    """Review Certificate Transparency logs for recent issuances on ``domain``."""
    session = _require_session(session_id)
    from pencheff.modules.asm.cert_watch import watch
    findings = await watch(domain)
    added = session.findings.add_many(findings)
    return _success({"recent_certs": len(findings), "findings_added": added})


# ─── Integrations ─────────────────────────────────────────────────────

@mcp.tool()
async def export_to_slack(
    session_id: str, webhook_url: str, severity_filter: str = "high"
) -> dict[str, Any]:
    """Post a summary of findings at or above ``severity_filter`` to a Slack webhook."""
    session = _require_session(session_id)
    from pencheff.core.integrations.slack import send
    from pencheff.config import Severity
    order = ["info", "low", "medium", "high", "critical"]
    threshold = order.index(severity_filter) if severity_filter in order else 3
    findings = [
        f for f in session.findings.get_all()
        if order.index(f.severity.value) >= threshold
    ]
    return _success(await send(webhook_url, findings))


@mcp.tool()
async def export_to_teams(
    session_id: str, webhook_url: str, severity_filter: str = "high"
) -> dict[str, Any]:
    """Post findings to a Microsoft Teams incoming webhook (connector)."""
    session = _require_session(session_id)
    from pencheff.core.integrations.teams import send
    order = ["info", "low", "medium", "high", "critical"]
    threshold = order.index(severity_filter) if severity_filter in order else 3
    findings = [f for f in session.findings.get_all() if order.index(f.severity.value) >= threshold]
    return _success(await send(webhook_url, findings))


@mcp.tool()
async def export_to_pagerduty(
    session_id: str, routing_key: str
) -> dict[str, Any]:
    """Create PagerDuty Events API v2 triggers for every critical/high finding."""
    session = _require_session(session_id)
    from pencheff.core.integrations.pagerduty import send
    return _success({"results": await send(routing_key, session.findings.get_all())})


@mcp.tool()
async def export_to_splunk(
    session_id: str, hec_url: str, token: str
) -> dict[str, Any]:
    """Send findings to a Splunk HEC endpoint."""
    session = _require_session(session_id)
    from pencheff.core.integrations.splunk_hec import send
    return _success(await send(hec_url, token, session.findings.get_all()))


@mcp.tool()
async def export_to_discord(
    session_id: str, webhook_url: str, severity_filter: str = "high"
) -> dict[str, Any]:
    """Post findings to a Discord webhook."""
    session = _require_session(session_id)
    from pencheff.core.integrations.discord import send
    order = ["info", "low", "medium", "high", "critical"]
    threshold = order.index(severity_filter) if severity_filter in order else 3
    findings = [f for f in session.findings.get_all() if order.index(f.severity.value) >= threshold]
    return _success(await send(webhook_url, findings))


@mcp.tool()
async def export_to_opsgenie(
    session_id: str, api_key: str
) -> dict[str, Any]:
    """Create Opsgenie alerts for every critical/high finding."""
    session = _require_session(session_id)
    from pencheff.core.integrations.opsgenie import send
    return _success({"results": await send(api_key, session.findings.get_all())})


@mcp.tool()
async def send_webhook(
    session_id: str,
    webhook_url: str,
    hmac_secret: str | None = None,
    severity_filter: str = "medium",
) -> dict[str, Any]:
    """Send a signed, generic webhook with all findings at or above ``severity_filter``.

    The receiver should verify ``X-Pencheff-Signature: sha256=...`` using ``hmac_secret``.
    """
    session = _require_session(session_id)
    from pencheff.core.integrations.webhook_generic import send
    order = ["info", "low", "medium", "high", "critical"]
    threshold = order.index(severity_filter) if severity_filter in order else 2
    findings = [f for f in session.findings.get_all() if order.index(f.severity.value) >= threshold]
    return _success(
        await send(webhook_url, findings, hmac_secret=hmac_secret,
                   metadata={"session_id": session.id, "target": session.target.base_url})
    )


# ─── EPSS + KEV enrichment / risk-ranked report ───────────────────────

@mcp.tool()
async def get_findings_enriched(
    session_id: str,
    severity: str | None = None,
    include_suppressed: bool = False,
) -> dict[str, Any]:
    """Return findings with EPSS + CISA KEV enrichment and a risk-prioritised score."""
    session = _require_session(session_id)
    from pencheff.config import Severity
    from pencheff.reporting.epss_enrichment import enrich_findings_dict

    findings = session.findings.get_all(
        severity=Severity(severity) if severity else None,
        include_suppressed=include_suppressed,
    )
    enriched = enrich_findings_dict(findings)
    enriched.sort(key=lambda f: f.get("risk_score", 0), reverse=True)
    return _success({"count": len(enriched), "findings": enriched})


# ─── Plugin SDK helpers ───────────────────────────────────────────────

@mcp.tool()
async def list_custom_modules(session_id: str) -> dict[str, Any]:
    """List any custom modules auto-discovered from ``~/.pencheff/custom_modules/``."""
    _require_session(session_id)
    from pencheff.modules.base import load_custom_modules, CUSTOM_DIR
    mods = load_custom_modules()
    return _success({
        "custom_dir": str(CUSTOM_DIR),
        "enabled": mods is not None,
        "modules": [
            {"name": m.name, "category": m.category,
             "owasp": m.owasp_categories, "description": m.description}
            for m in mods
        ],
    })
