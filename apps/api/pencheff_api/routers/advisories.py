# SPDX-License-Identifier: AGPL-3.0-or-later
"""Advisory lookup + AI-enriched exploit walkthrough.

Phase 1.1c — sits on top of the bulk-feed cache populated by the
``BulkFeedSource`` registry (RustSec, GoVulnDB, EPSS, KEV) plus the
on-demand OSV / NVD paths in ``CveFeed``.

Endpoints:

* ``GET /advisories/{id}`` — return the cached advisory, NVD
  enrichment when available, AI walkthrough + fix recipe (cached;
  generated on first read), and the on-disk provenance trail.

* ``GET /advisories?package=&ecosystem=`` — list the advisories that
  affect ``package`` in ``ecosystem``. ``ecosystem`` matches OSV
  conventions (``RustSec``, ``Go``, ``PyPI``, ``npm``, …).

The endpoints intentionally avoid touching the SaaS scan tables — the
advisory data lives in the SQLite feed cache, which is shared across
the worker and the API process via the user's home directory. That
keeps the surface clean for both hosted-SaaS and self-hosted
deployments.
"""
from __future__ import annotations

import asyncio
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel

from ..auth.deps import require_scope

router = APIRouter(
    prefix="/advisories",
    tags=["advisories"],
    dependencies=[Depends(require_scope("dependencies:read"))],
)


# ─── Response shapes ────────────────────────────────────────────────


class _Source(BaseModel):
    url: str | None = None
    license: str | None = None
    retrieved_at: str | None = None


class _AiEnrichment(BaseModel):
    exploit_walkthrough: str
    fix_recipe: str
    reachability_signals: list[str]
    references: list[str]
    model: str | None = None
    prompt_version: str
    cached: bool


class AdvisoryOut(BaseModel):
    id: str
    ecosystem: str | None = None
    package: str | None = None
    summary: str | None = None
    severity: str | None = None
    license: str | None = None
    advisory: dict[str, Any]
    nvd: dict[str, Any] | None = None
    epss: float | None = None
    epss_percentile: float | None = None
    kev: bool = False
    ai: _AiEnrichment | None = None
    provenance: list[dict[str, Any]] = []
    sources: list[_Source] = []


class AdvisoryListItem(BaseModel):
    id: str
    ecosystem: str
    package: str | None = None
    summary: str | None = None
    severity: str | None = None
    license: str | None = None


# ─── Helpers ────────────────────────────────────────────────────────


def _get_feed():
    """Lazily import the plugin's CveFeed so the router stays usable
    in environments where the plugin isn't installed (the import would
    blow up at module-load time otherwise)."""
    try:
        from pencheff.core.cve_feed import get_feed
    except ImportError as exc:  # pragma: no cover — only hit in dev
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "Pencheff plugin not installed in this worker — install via "
            "`pip install -e plugins/pencheff`.",
        ) from exc
    return get_feed()


def _build_sources_for(advisory_row: dict[str, Any]) -> list[_Source]:
    """Build the provenance list passed into ``explain_advisory``."""
    out: list[_Source] = []
    license_id = advisory_row.get("license")
    advisory = advisory_row.get("advisory") or {}
    for ref in (advisory.get("references") or [])[:6]:
        if isinstance(ref, dict) and ref.get("url"):
            out.append(_Source(url=ref["url"], license=license_id))
    if not out and license_id:
        out.append(_Source(license=license_id))
    return out


# ─── GET /advisories/{id} ───────────────────────────────────────────


@router.get("/{advisory_id}", response_model=AdvisoryOut)
async def get_advisory(advisory_id: str) -> AdvisoryOut:
    feed = _get_feed()

    # ── Cached bulk-advisory rows ─────────────────────────────────
    # The bulk-feed registry indexes by (ecosystem, advisory_id); we
    # don't know the ecosystem yet, so a one-row scan suffices.
    row = feed.conn.execute(
        "SELECT ecosystem, advisory_id, package, summary, severity, "
        "license, payload_json "
        "FROM bulk_advisories WHERE advisory_id = ? LIMIT 1",
        (advisory_id,),
    ).fetchone()

    if row is None and not advisory_id.startswith("CVE-"):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "advisory not found")

    if row is not None:
        ecosystem, _, package, summary, severity, license_, payload_json = row
        import json as _json
        try:
            advisory = _json.loads(payload_json) if payload_json else {}
        except _json.JSONDecodeError:
            advisory = {}
    else:
        # No cached row but it's a CVE — emit a thin shell so the AI
        # path can still enrich it from NVD on demand.
        ecosystem, package, summary, severity, license_ = (
            None, None, None, None, None,
        )
        advisory = {"id": advisory_id}

    # ── NVD enrichment for CVE ids ────────────────────────────────
    nvd_payload: dict[str, Any] | None = None
    if advisory_id.startswith("CVE-"):
        try:
            nvd = await feed.nvd_enrich(advisory_id)
        except Exception:  # noqa: BLE001 — never block the request
            nvd = None
        if nvd is not None:
            nvd_payload = {
                "cwe_ids": list(nvd.cwe_ids),
                "cpe_uris": list(nvd.cpe_uris),
                "nvd_cvss_score": nvd.nvd_cvss_score,
                "nvd_cvss_severity": nvd.nvd_cvss_severity,
                "primary_url": nvd.primary_url,
                "description": nvd.description,
            }

    # ── EPSS / KEV labels ─────────────────────────────────────────
    info = feed.enrich(advisory_id) if advisory_id.startswith("CVE-") else None
    epss = info.epss if info else None
    epss_pct = info.epss_percentile if info else None
    kev = bool(info.kev) if info else False

    # ── AI enrichment ────────────────────────────────────────────
    ai_payload: _AiEnrichment | None = None
    sources = _build_sources_for({
        "license": license_, "advisory": advisory,
    })
    try:
        # Heavy — push to a worker thread so the event loop stays free.
        from ..services.advisory_ai import explain_advisory
        enrichment = await asyncio.to_thread(
            explain_advisory,
            advisory_id=advisory_id,
            advisory=advisory,
            sources=[s.model_dump() for s in sources],
            nvd_extras=nvd_payload,
            cve_feed=feed,
        )
    except Exception:  # noqa: BLE001 — AI enrichment is optional
        enrichment = None

    if enrichment is not None:
        ai_payload = _AiEnrichment(
            exploit_walkthrough=enrichment.exploit_walkthrough,
            fix_recipe=enrichment.fix_recipe,
            reachability_signals=list(enrichment.reachability_signals),
            references=list(enrichment.references),
            model=enrichment.model,
            prompt_version=enrichment.prompt_version,
            cached=enrichment.cached,
        )

    from ..services.advisory_ai import read_provenance
    provenance = read_provenance(advisory_id)

    return AdvisoryOut(
        id=advisory_id,
        ecosystem=ecosystem,
        package=package,
        summary=summary,
        severity=severity,
        license=license_,
        advisory=advisory,
        nvd=nvd_payload,
        epss=epss,
        epss_percentile=epss_pct,
        kev=kev,
        ai=ai_payload,
        provenance=provenance,
        sources=sources,
    )


# ─── GET /advisories?package=&ecosystem= ────────────────────────────


@router.get("", response_model=list[AdvisoryListItem])
async def list_advisories(
    package: str = Query(..., min_length=1, max_length=200),
    ecosystem: str = Query(..., min_length=1, max_length=64),
) -> list[AdvisoryListItem]:
    feed = _get_feed()
    rows = feed.bulk_advisories_for(ecosystem, package)
    return [
        AdvisoryListItem(
            id=row["advisory_id"],
            ecosystem=ecosystem,
            package=package,
            summary=row.get("summary"),
            severity=row.get("severity"),
            license=row.get("license"),
        )
        for row in rows
    ]
