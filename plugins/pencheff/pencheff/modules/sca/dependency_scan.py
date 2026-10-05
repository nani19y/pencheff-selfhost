"""Scan dependency manifests for known CVEs via OSV.dev + EPSS + KEV enrichment."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

from pencheff.config import Severity
from pencheff.core.cve_feed import DepVuln, get_feed
from pencheff.core.findings import Evidence, Finding
from pencheff.core.http_client import PencheffHTTPClient
from pencheff.core.session import PentestSession
from pencheff.modules.base import BaseTestModule
from pencheff.modules.sca.manifest_parsers import Dep, discover_and_parse


class DependencyScanModule(BaseTestModule):
    name = "dependency_scan"
    category = "components"
    owasp_categories = ["A06"]
    description = "Software Composition Analysis against OSV.dev with EPSS/KEV enrichment"

    def get_techniques(self) -> list[str]:
        return ["manifest-parse", "osv-query", "kev-flag", "epss-enrich"]

    async def run(
        self,
        session: PentestSession,
        http: PencheffHTTPClient,
        targets: list[str] | None = None,
        config: dict[str, Any] | None = None,
    ) -> list[Finding]:
        cfg = config or {}
        path = Path(cfg.get("path", "."))
        if not path.exists():
            return []
        deps = discover_and_parse(path)
        findings = await scan_deps(deps, session, scan_root=path)
        return findings


async def scan_deps(
    deps: list[Dep],
    session: PentestSession | None = None,
    scan_root: Path | None = None,
    *,
    nvd_enrich: bool = True,
    ensure_fresh: bool = True,
) -> list[Finding]:
    """Query OSV for each (ecosystem, name, version) and build Findings.

    Freshness model — every scan pulls live CVE data:
      * The EPSS and CISA KEV feeds are refreshed at the top of the
        scan when the local cache is older than ``FEED_CACHE_TTL_HOURS``
        (default 24 h, tunable via PENCHEFF_FEED_TTL_HOURS).
      * Each per-package OSV result is re-fetched when the cached row
        is older than ``OSV_CACHE_TTL_HOURS`` (default 24 h, tunable via
        PENCHEFF_OSV_TTL_HOURS).
      * Set either TTL to ``0`` to force a live fetch on every scan.
      * Network failure on a refresh falls back to the stale row rather
        than dropping findings — the live-data intent fails open.

    When ``nvd_enrich`` is True (default), each CVE-id finding is also
    looked up in NVD 2.0 for CWE / CPE / NVD-CVSS context. NVD lookups
    are cached for ``NVD_CACHE_TTL_DAYS``, so repeat scans of the same
    project do not re-hit the API. Set the env var ``NVD_API_KEY`` to
    raise the rate limit; without it, NVD allows ~5 requests per 30 s.
    """
    feed = get_feed()

    # Refresh the global EPSS / KEV feeds first so every per-package OSV
    # result we look up below carries the latest exploit-prediction and
    # active-exploitation labels. Suppress on failure — the OSV lookup is
    # the load-bearing query; EPSS/KEV are enrichment.
    if ensure_fresh:
        try:
            await feed.ensure_feeds_fresh()
        except Exception:  # noqa: BLE001 — never block a scan on enrichment
            pass

    sem = asyncio.Semaphore(8)

    async def q(d: Dep) -> tuple[Dep, list[DepVuln]]:
        async with sem:
            if not d.name or not d.version or not d.ecosystem:
                return d, []
            return d, await feed.osv_query(d.ecosystem, d.name, d.version)

    results = await asyncio.gather(*(q(d) for d in deps))

    # Collect distinct CVE ids first so we issue one NVD request per CVE
    # even when many dependencies share the same advisory (e.g. lodash
    # CVEs hitting half the npm graph).
    if nvd_enrich:
        cve_ids: set[str] = {
            v.id
            for _dep, vulns in results
            for v in vulns
            if v.id.startswith("CVE-")
        }
        nvd_sem = asyncio.Semaphore(4)

        async def _enrich_one(cve_id: str) -> None:
            async with nvd_sem:
                await feed.nvd_enrich(cve_id)

        await asyncio.gather(*(_enrich_one(c) for c in cve_ids))
        # Re-attach cached NVD data to each DepVuln's CveInfo so the
        # finding builder picks it up without re-querying.
        for _dep, vulns in results:
            for v in vulns:
                if v.cve_info is None and v.id.startswith("CVE-"):
                    v.cve_info = feed.enrich(v.id)
                elif v.cve_info is not None and v.cve_info.nvd is None and v.id.startswith("CVE-"):
                    refreshed = feed.enrich(v.id)
                    v.cve_info.nvd = refreshed.nvd

    findings: list[Finding] = []
    root = scan_root.resolve() if scan_root else None
    for dep, vulns in results:
        rel = _rel_manifest(dep.source_file, root)
        for v in vulns:
            findings.append(_vuln_to_finding(dep, v, manifest_rel=rel))
    return findings


def _rel_manifest(source_file: str, scan_root: Path | None) -> str:
    """Best-effort: compute the manifest path relative to the scan root.

    Falls back to the basename when the path lies outside the root or the
    root is unknown — that still gives the patcher a chance to find the
    file by walking the materialised repo on the API side.
    """
    if not source_file:
        return ""
    p = Path(source_file)
    if scan_root:
        try:
            return str(p.resolve().relative_to(scan_root))
        except (ValueError, OSError):
            pass
    return p.name


def _vuln_to_finding(dep: Dep, v: DepVuln, manifest_rel: str = "") -> Finding:
    sev_label = v.severity.lower() if v.severity else "medium"
    sev = {
        "critical": Severity.CRITICAL, "high": Severity.HIGH,
        "medium": Severity.MEDIUM, "low": Severity.LOW, "info": Severity.INFO,
    }.get(sev_label, Severity.MEDIUM)

    fixed = ", ".join(v.fixed_versions) if v.fixed_versions else "no fixed version published"
    # Pick the lowest fixed version we know about — that's the smallest
    # safe bump. Sorting lexicographically is good enough for OSV's already-
    # filtered list; PEP-440 / SemVer-perfect ordering would require pulling
    # in a parser per ecosystem, which is overkill here.
    fix_version = sorted(v.fixed_versions)[0] if v.fixed_versions else None
    autofix_payload: dict[str, Any] | None = None
    epss = v.cve_info.epss if v.cve_info else None
    epss_pct = v.cve_info.epss_percentile if v.cve_info else None
    kev = bool(v.cve_info.kev) if v.cve_info else False
    nvd = v.cve_info.nvd if v.cve_info else None
    primary_advisory_url = v.cve_info.primary_advisory_url if v.cve_info else None
    cwe_ids = nvd.cwe_ids if nvd else []
    primary_cwe = cwe_ids[0] if cwe_ids else None

    if fix_version and dep.name:
        autofix_payload = {
            "tool": "osv",
            "ecosystem": dep.ecosystem,
            "package": dep.name,
            "current_version": dep.version,
            "fix_version": fix_version,
            "manifest_path": manifest_rel or dep.source_file,
            "advisory_id": v.id,
            # Prioritisation inputs travel alongside the autofix payload so
            # the API side can compute risk_score / SSVC without re-querying
            # the EPSS / KEV feeds.
            "epss": epss,
            "kev": kev,
        }
    kev_note = ""
    epss_note = ""
    if v.cve_info and v.cve_info.kev:
        kev_note = (
            f"\n\n⚠️  This CVE appears on the CISA Known Exploited Vulnerabilities catalog "
            f"({v.cve_info.kev_short_desc or 'actively exploited'}). "
            f"Federal deadline: {v.cve_info.kev_due_date or 'n/a'}."
        )
    if v.cve_info and v.cve_info.epss is not None:
        epss_note = f"\nEPSS score: {v.cve_info.epss:.4f} (higher = more likely to be exploited)."

    # Promote the canonical advisory URL to the front of references so
    # downstream renderers (DOCX, PR comment, web finding card) link to
    # NVD first rather than the OSV record.
    references = list(v.references)
    if primary_advisory_url and primary_advisory_url not in references:
        references = [primary_advisory_url] + references

    # Structured metadata — first-class fields on the finding so the API,
    # autofix, dashboard, and prioritisation engine can read them without
    # parsing the description text.
    metadata: dict[str, Any] = {
        "advisory_id": v.id,
        "ecosystem": dep.ecosystem,
        "package": dep.name,
        "current_version": dep.version,
        "fix_version": fix_version,
        "fixed_versions": list(v.fixed_versions),
        "epss": epss,
        "epss_percentile": epss_pct,
        "kev": kev,
        "kev_short_desc": v.cve_info.kev_short_desc if v.cve_info else None,
        "kev_due_date": v.cve_info.kev_due_date if v.cve_info else None,
        "cwe_ids": cwe_ids,
        "advisory_url": primary_advisory_url,
        "nvd_cvss_score": nvd.nvd_cvss_score if nvd else None,
        "nvd_cvss_vector": nvd.nvd_cvss_vector if nvd else None,
    }

    return Finding(
        title=f"{dep.name} {dep.version} — {v.id}",
        severity=sev,
        category="components",
        owasp_category="A06",
        description=(
            f"The {dep.ecosystem} package '{dep.name}' version {dep.version} is "
            f"vulnerable to {v.id}: {v.summary}{epss_note}{kev_note}"
        ),
        remediation=(
            f"Upgrade {dep.name} to {fixed}. "
            f"Source manifest: {dep.source_file}. "
            f"If upgrade is impossible, apply the mitigations listed in the advisory, "
            f"remove the dependency if unused, or pin a patched fork."
        ),
        endpoint=manifest_rel or dep.source_file or dep.name,
        parameter=f"{dep.ecosystem}:{dep.name}@{dep.version}",
        cvss_vector=v.cvss_vector,
        cvss_score=v.cvss_score,
        evidence=[
            Evidence(
                request_method="OSV",
                request_url=f"osv://{dep.ecosystem}/{dep.name}/{dep.version}",
                response_status=200,
                description=(
                    f"{v.id} affects versions: {', '.join(v.affected_versions) or 'unknown range'}. "
                    f"Fixed in: {fixed}."
                ),
                autofix=autofix_payload,
            )
        ],
        references=references,
        cwe_id=primary_cwe,
        metadata=metadata,
    )
