"""Map ``PolicyModule.name`` to actual module implementations.

Kept separate from ``policy_engine`` so new modules can register themselves
without circular imports.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from pencheff.core.http_client import PencheffHTTPClient
from pencheff.core.session import PentestSession


async def run_module(
    session: PentestSession, mod
) -> dict[str, Any]:
    name = mod.name
    params = mod.params or {}
    http = PencheffHTTPClient(session)
    # Web / injection / auth / authz / client-side / infrastructure / api /
    # business_logic / cloud / file_handling / advanced / websocket / ...
    # — each of these maps to its corresponding ``modules.*`` class.
    registry = _registry()
    handler = registry.get(name)
    if not handler:
        return {"error": f"Unknown module '{name}'"}
    findings = await handler(session, http, params)
    added = session.findings.add_many(findings)
    return {"findings": added, "total": len(findings)}


def _registry():
    from pencheff.modules.sca.dependency_scan import DependencyScanModule
    from pencheff.modules.sca.sbom_generator import generate_sbom
    from pencheff.modules.sca.license_compliance import evaluate as eval_licenses
    from pencheff.modules.iac import dockerfile_scan, kubernetes_scan, terraform_scan
    from pencheff.modules.iac import container_image_scan
    from pencheff.modules.network import host_cve_scan, network_misconfig
    from pencheff.modules.web.passive_scan import scan_response  # dummy

    async def _sca(session, http, params):
        m = DependencyScanModule()
        return await m.run(session, http, config={"path": params.get("path", ".")})

    async def _sbom(session, http, params):
        result = generate_sbom(Path(params.get("path", ".")), params.get("format", "cyclonedx"))
        session.discovered.tech_stack.setdefault("_sbom", []).append(str(result.get("component_count")))
        return []

    async def _licenses(session, http, params):
        f, _ = eval_licenses(Path(params.get("path", ".")),
                             Path(params["policy"]) if params.get("policy") else None)
        return f

    async def _dockerfile(session, http, params):
        return dockerfile_scan.scan(Path(params.get("path", ".")))

    async def _k8s(session, http, params):
        return kubernetes_scan.scan(Path(params.get("path", ".")))

    async def _tf(session, http, params):
        return terraform_scan.scan(Path(params.get("path", ".")))

    async def _img(session, http, params):
        return container_image_scan.scan(params.get("image", ""))

    async def _net(session, http, params):
        return host_cve_scan.scan(params.get("host", session.target.base_url), params.get("ports", "top-1000"))

    async def _net_misconfig(session, http, params):
        return await network_misconfig.scan(params.get("host", session.target.base_url))

    # Bridge into existing web/injection modules by calling their server.py entry points
    async def _existing_scan(name: str):
        async def _run(session, http, params):
            from pencheff import server as srv
            tool = getattr(srv, name, None)
            if not tool or not callable(tool):
                return []
            await tool(session.id, **({k: v for k, v in params.items() if k in {"types"}}))
            return []
        return _run

    registry = {
        "scan_dependencies": _sca,
        "generate_sbom": _sbom,
        "check_licenses": _licenses,
        "scan_dockerfile": _dockerfile,
        "scan_kubernetes": _k8s,
        "scan_terraform": _tf,
        "scan_container_image": _img,
        "scan_host_vulns": _net,
        "scan_network_misconfig": _net_misconfig,
    }
    # Wire existing scan_* module names (best-effort bridge)
    for legacy in (
        "scan_injection", "scan_auth", "scan_authz", "scan_client_side",
        "scan_infrastructure", "scan_api", "scan_business_logic",
        "scan_advanced", "scan_cloud", "scan_file_handling",
        "scan_websocket", "scan_mfa_bypass", "scan_oauth",
        "scan_subdomain_takeover", "scan_waf",
    ):
        import asyncio as _a
        registry[legacy] = _bridge(legacy)
    return registry


def _bridge(name: str):
    async def _run(session, http, params):
        from pencheff import server as srv
        fn = getattr(srv, name, None)
        if not fn:
            return []
        try:
            await fn(session.id, **({k: v for k, v in params.items() if k == "types"}))
        except Exception:  # noqa: BLE001
            return []
        return []
    return _run
