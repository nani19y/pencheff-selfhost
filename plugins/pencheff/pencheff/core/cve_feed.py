"""CVE / EPSS / CISA KEV feed cache and lookup.

Uses a local SQLite database for fast lookups. Two distinct refresh
paths:

* **Bulk feeds** — EPSS, CISA KEV, and (in Phase 1.1b) RustSec /
  GoVulnDB / distro feeds. Each is a ``BulkFeedSource`` subclass under
  ``pencheff.core.feeds``; the registry at ``feeds/__init__.py``
  drives ``CveFeed.refresh()``. Adding a new bulk source is a
  one-module-plus-one-line-in-REGISTRY change.

* **On-demand queries** — OSV.dev per-package, NVD 2.0 per-CVE. Both
  are kept inline below because the request-per-key pattern is
  fundamentally different from a daily bulk download.

Optional ``NVD_API_KEY`` raises the NVD rate limit from 5/30 s to
50/30 s. Offline scans degrade gracefully — modules emit findings
with empty EPSS / unknown KEV fields when the cache is empty.
"""

from __future__ import annotations

import json
import os
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx

from .feeds import all_sources as _bulk_feed_sources

# Back-compat re-exports for anything that imported the inline URL
# constants by name. The canonical definitions live in the per-source
# modules now.
from .feeds.epss import EPSS_URL  # noqa: F401  — re-export
from .feeds.kev import KEV_URL  # noqa: F401  — re-export

CACHE_DIR = Path.home() / ".pencheff"
CACHE_DB = CACHE_DIR / "cve_cache.db"

OSV_QUERY_URL = "https://api.osv.dev/v1/query"
NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# NVD's enrichment cache lives 14 days — long enough that a re-scanned
# project doesn't re-hit the API but short enough that newly-published
# CWE/CPE links land within a fortnight. Override with PENCHEFF_NVD_TTL_DAYS.
NVD_CACHE_TTL_DAYS = int(os.environ.get("PENCHEFF_NVD_TTL_DAYS", "14"))

# Per-package OSV results are re-fetched if the cached row is older than
# this. Default 24 h: matches OSV.dev's own publish cadence. Override
# with PENCHEFF_OSV_TTL_HOURS=0 to force live every scan.
OSV_CACHE_TTL_HOURS = int(os.environ.get("PENCHEFF_OSV_TTL_HOURS", "24"))

# EPSS + KEV catalogue are refreshed at the start of any scan that finds
# a stale local copy. EPSS publishes daily; KEV updates a few times a
# week. Default 24 h. Override with PENCHEFF_FEED_TTL_HOURS=0 to force
# refresh on every scan.
FEED_CACHE_TTL_HOURS = int(os.environ.get("PENCHEFF_FEED_TTL_HOURS", "24"))


def _connect() -> sqlite3.Connection:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(CACHE_DB)
    # Bulk-feed cache tables: each registered ``BulkFeedSource`` owns
    # its own table; the source declares the schema, ``_connect``
    # applies it. This means a new feed in Phase 1.1b only needs to
    # ship a module under ``pencheff.core.feeds`` — no additions here.
    for source in _bulk_feed_sources():
        if source.schema_sql:
            conn.execute(source.schema_sql)
    # On-demand caches (OSV per-package, NVD per-CVE) stay co-located
    # with the request paths in this module; they are not bulk feeds.
    conn.execute(
        "CREATE TABLE IF NOT EXISTS osv_cache ("
        "ecosystem TEXT, package TEXT, version TEXT, "
        "vulns_json TEXT, cached_at TEXT, "
        "PRIMARY KEY (ecosystem, package, version))"
    )
    conn.execute(
        "CREATE TABLE IF NOT EXISTS nvd_cache ("
        "cve TEXT PRIMARY KEY, payload_json TEXT, cached_at TEXT)"
    )
    # Tracks when each global feed was last refreshed so the SCA module
    # can decide whether to pull a fresh copy at the start of a scan.
    # Per-row tables (osv_cache, nvd_cache) carry their own
    # ``cached_at`` columns and don't need this.
    conn.execute(
        "CREATE TABLE IF NOT EXISTS feed_meta ("
        "feed TEXT PRIMARY KEY, refreshed_at TEXT, row_count INTEGER, error TEXT)"
    )
    conn.commit()
    return conn


@dataclass
class NvdEnrichment:
    """NVD-2.0 fields that OSV does not consistently expose."""

    cve: str
    cwe_ids: list[str] = field(default_factory=list)  # ["CWE-79", "CWE-352"]
    cpe_uris: list[str] = field(default_factory=list)  # vulnerable CPE URIs
    nvd_cvss_score: float | None = None
    nvd_cvss_vector: str | None = None
    nvd_cvss_severity: str | None = None
    primary_url: str | None = None  # the NVD advisory URL
    published: str | None = None
    description: str | None = None


@dataclass
class CveInfo:
    cve: str
    epss: float | None = None
    epss_percentile: float | None = None
    kev: bool = False
    kev_short_desc: str | None = None
    kev_due_date: str | None = None
    # NVD enrichment is loaded lazily — most callers only need EPSS / KEV.
    nvd: NvdEnrichment | None = None

    def risk_multiplier(self) -> float:
        """EPSS × KEV multiplier for risk-ranking."""
        m = 1.0
        if self.epss is not None:
            m *= 1.0 + self.epss
        if self.kev:
            m *= 2.0
        return m

    @property
    def primary_advisory_url(self) -> str | None:
        """Pick the canonical advisory URL for this CVE.

        Order: NVD (when enriched) → standard NVD link by CVE id → KEV
        catalog. Callers that need the OSV / GHSA URL should walk
        ``DepVuln.references`` instead.
        """
        if self.nvd and self.nvd.primary_url:
            return self.nvd.primary_url
        if self.cve.startswith("CVE-"):
            return f"https://nvd.nist.gov/vuln/detail/{self.cve}"
        return None

    @property
    def cwe_ids(self) -> list[str]:
        return list(self.nvd.cwe_ids) if self.nvd else []


@dataclass
class DepVuln:
    """A vulnerability affecting a dependency."""

    id: str  # CVE-YYYY-NNNN or GHSA-...
    summary: str
    severity: str = "unknown"  # critical/high/medium/low/info
    cvss_score: float = 0.0
    cvss_vector: str = ""
    affected_versions: list[str] = field(default_factory=list)
    fixed_versions: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    cve_info: CveInfo | None = None


class CveFeed:
    """Local CVE/EPSS/KEV lookup with network fallback for OSV queries."""

    def __init__(self):
        self.conn = _connect()

    def close(self):
        self.conn.close()

    # ─── Refresh ──────────────────────────────────────────────────────

    async def refresh(self, force: bool = False) -> dict[str, Any]:
        """Refresh every registered ``BulkFeedSource``. Returns a summary.

        The summary keys named after each source carry the row count
        for backward compatibility with callers that read
        ``result["epss"]`` / ``result["kev"]`` directly. ``errors`` is
        a list of ``"<feed>: <message>"`` strings for any source that
        failed; per-feed failure does not abort the loop.
        """
        result: dict[str, Any] = {"errors": []}
        # Single shared async client amortises TLS setup across feeds.
        async with httpx.AsyncClient(timeout=60.0) as client:
            for source in _bulk_feed_sources():
                try:
                    count = await source.refresh(self.conn, client)
                    result[source.name] = count
                    self._record_refresh(source.name, row_count=count, error=None)
                except Exception as exc:  # noqa: BLE001
                    msg = f"{source.name}: {exc}"
                    result.setdefault(source.name, 0)
                    result["errors"].append(msg)
                    # Surface the failure in feed_meta so callers can
                    # distinguish "never refreshed" from "tried recently
                    # and failed".
                    self._record_refresh(source.name, row_count=0, error=msg[:500])
        return result

    # ─── Lookups ──────────────────────────────────────────────────────

    def enrich(self, cve: str) -> CveInfo:
        """Local-only EPSS/KEV lookup. Does not touch the network."""
        info = CveInfo(cve=cve)
        row = self.conn.execute(
            "SELECT epss, percentile FROM epss WHERE cve = ?", (cve,)
        ).fetchone()
        if row:
            info.epss, info.epss_percentile = row[0], row[1]
        row = self.conn.execute(
            "SELECT short_desc, due_date FROM kev WHERE cve = ?", (cve,)
        ).fetchone()
        if row:
            info.kev = True
            info.kev_short_desc, info.kev_due_date = row[0], row[1]
        # If we already cached an NVD enrichment for this CVE, attach it
        # without going to the network. The async ``nvd_enrich`` adds it
        # on demand.
        nvd = self._load_cached_nvd(cve)
        if nvd is not None:
            info.nvd = nvd
        return info

    def _load_cached_nvd(self, cve: str) -> NvdEnrichment | None:
        row = self.conn.execute(
            "SELECT payload_json, cached_at FROM nvd_cache WHERE cve = ?", (cve,)
        ).fetchone()
        if not row:
            return None
        payload, cached_at = row
        try:
            cached_dt = datetime.fromisoformat(cached_at)
        except (TypeError, ValueError):
            return None
        if (datetime.now(timezone.utc) - cached_dt).days > NVD_CACHE_TTL_DAYS:
            return None
        try:
            data = json.loads(payload)
        except json.JSONDecodeError:
            return None
        return NvdEnrichment(**data)

    async def nvd_enrich(self, cve: str) -> NvdEnrichment | None:
        """Fetch CWE / CPE / NVD-CVSS / advisory URL for a single CVE.

        Cached for ``NVD_CACHE_TTL_DAYS``. Returns ``None`` on network
        failure or when the CVE is not in NVD. The ``NVD_API_KEY``
        environment variable raises the rate limit if set.
        """
        if not cve.startswith("CVE-"):
            return None
        cached = self._load_cached_nvd(cve)
        if cached is not None:
            return cached

        headers: dict[str, str] = {}
        if api_key := os.environ.get("NVD_API_KEY"):
            headers["apiKey"] = api_key
        try:
            async with httpx.AsyncClient(timeout=15.0, headers=headers) as client:
                r = await client.get(NVD_CVE_URL, params={"cveId": cve})
                if r.status_code != 200:
                    return None
                data = r.json()
        except Exception:  # noqa: BLE001
            return None

        items = data.get("vulnerabilities") or []
        if not items:
            return None
        cve_obj = (items[0] or {}).get("cve") or {}
        enrichment = _parse_nvd_cve(cve, cve_obj)
        # Cache on success (negative results aren't cached — re-checking
        # NVD is cheap enough and a CVE may land in NVD after first miss).
        self.conn.execute(
            "INSERT OR REPLACE INTO nvd_cache VALUES (?, ?, ?)",
            (
                cve,
                json.dumps(_nvd_to_dict(enrichment)),
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        self.conn.commit()
        return enrichment

    async def osv_query(
        self,
        ecosystem: str,
        package: str,
        version: str,
    ) -> list[DepVuln]:
        """Query OSV.dev for a single package@version.

        The result is cached for ``OSV_CACHE_TTL_HOURS`` (default 24 h) —
        OSV.dev publishes new advisories at most a few times per day, and
        re-querying the entire dependency graph on every scan when the
        upstream answer hasn't changed wastes both API quota and wall
        time. A stale row triggers a live re-fetch; on network failure,
        the stale row is returned rather than blowing up the scan.

        Set ``PENCHEFF_OSV_TTL_HOURS=0`` to force a live fetch on every
        single scan.
        """
        row = self.conn.execute(
            "SELECT vulns_json, cached_at FROM osv_cache "
            "WHERE ecosystem=? AND package=? AND version=?",
            (ecosystem, package, version),
        ).fetchone()
        if row and not _is_stale(row[1], hours=OSV_CACHE_TTL_HOURS):
            return [DepVuln(**v) for v in _decode_cached(row[0], self)]

        body = {
            "version": version,
            "package": {"name": package, "ecosystem": ecosystem},
        }
        vulns: list[DepVuln] = []
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                r = await client.post(OSV_QUERY_URL, json=body)
                r.raise_for_status()
                data = r.json()
            for v in data.get("vulns", []):
                sev = _osv_severity(v)
                cve_id = _primary_id(v)
                info = self.enrich(cve_id) if cve_id.startswith("CVE-") else None
                vulns.append(DepVuln(
                    id=cve_id,
                    summary=v.get("summary", "")[:500],
                    severity=sev[0],
                    cvss_score=sev[1],
                    cvss_vector=sev[2],
                    affected_versions=_affected_versions(v),
                    fixed_versions=_fixed_versions(v),
                    references=[r.get("url", "") for r in v.get("references", [])][:5],
                    cve_info=info,
                ))
        except Exception:  # noqa: BLE001
            # Network failure on a stale-cache refresh — fall back to the
            # stale row rather than dropping all SCA findings for the
            # affected package. The "live" intent fails open, not closed.
            if row:
                return [DepVuln(**v) for v in _decode_cached(row[0], self)]
            return []

        self.conn.execute(
            "INSERT OR REPLACE INTO osv_cache VALUES (?, ?, ?, ?, datetime('now'))",
            (ecosystem, package, version, _encode_for_cache(vulns)),
        )
        self.conn.commit()
        return vulns

    # ─── Per-scan freshness guarantee ─────────────────────────────────

    def _feed_is_stale(self, feed: str, *, hours: int) -> bool:
        """True when the named feed has never been refreshed, or was
        refreshed more than ``hours`` hours ago."""
        row = self.conn.execute(
            "SELECT refreshed_at FROM feed_meta WHERE feed = ?", (feed,)
        ).fetchone()
        if not row:
            return True
        return _is_stale(row[0], hours=hours)

    def _record_refresh(self, feed: str, *, row_count: int, error: str | None) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO feed_meta VALUES (?, ?, ?, ?)",
            (
                feed,
                datetime.now(timezone.utc).isoformat(),
                row_count,
                error,
            ),
        )
        self.conn.commit()

    async def ensure_feeds_fresh(
        self, *, max_age_hours: int | None = None
    ) -> dict[str, Any]:
        """Refresh every registered bulk feed when its cache is past TTL.

        Called by ``scan_deps`` at the start of every dependency scan so
        each finding's EPSS / KEV (and 1.1b RustSec / GoVulnDB / …)
        labels reflect the latest available upstream data — without
        paying the full refresh cost on every scan when the cache is
        already current.

        Returns a status summary keyed per-feed so callers can log what
        happened. The legacy keys ``epss_refreshed``,
        ``epss_age_hours``, ``kev_refreshed``, ``kev_age_hours`` stay
        on the response for back-compat with the previous shape; new
        feeds add their own ``<name>_refreshed`` / ``<name>_age_hours``
        rows. Does not raise on network failure — a stale-but-not-dead
        cache is better than a broken scan.
        """
        ttl = FEED_CACHE_TTL_HOURS if max_age_hours is None else max_age_hours
        sources = _bulk_feed_sources()
        out: dict[str, Any] = {"errors": []}
        for src in sources:
            out[f"{src.name}_refreshed"] = False
            out[f"{src.name}_age_hours"] = _age_hours(self._last_refresh(src.name))

        if all(not self._feed_is_stale(s.name, hours=ttl) for s in sources):
            return out

        # ``refresh()`` walks every source and records feed_meta itself —
        # we just need to surface the per-source result on the return
        # shape.
        try:
            result = await self.refresh()
        except Exception as exc:  # noqa: BLE001
            out["errors"].append(f"refresh: {exc}")
            return out
        for src in sources:
            count = result.get(src.name, 0)
            if count:
                out[f"{src.name}_refreshed"] = True
        for e in result.get("errors", []):
            out["errors"].append(e)
        return out

    def _last_refresh(self, feed: str) -> str | None:
        row = self.conn.execute(
            "SELECT refreshed_at FROM feed_meta WHERE feed = ?", (feed,)
        ).fetchone()
        return row[0] if row else None

    # ─── Bulk advisory lookups (RustSec / GoVulnDB / future distros) ──

    def bulk_advisories_for(
        self,
        ecosystem: str,
        package: str,
    ) -> list[dict[str, Any]]:
        """Return cached OSV-format advisories that name ``package`` in
        the given ``ecosystem``.

        Reads from the shared ``bulk_advisories`` table populated by
        every ``OsvBulkSource`` subclass (RustSec, GoVulnDB, and
        Phase 1.1b's distro / ecosystem feeds). Each row's
        ``payload_json`` is the verbatim OSV advisory; the caller can
        feed it through the same ``_osv_severity`` /
        ``_affected_versions`` helpers used for live OSV queries.

        Lookup is case-insensitive on package name to match how OSV
        publishes (e.g. ``serde`` and ``Serde`` both resolve).
        """
        rows = self.conn.execute(
            "SELECT advisory_id, summary, severity, license, payload_json "
            "FROM bulk_advisories WHERE ecosystem = ? AND lower(package) = lower(?)",
            (ecosystem, package),
        ).fetchall()
        out: list[dict[str, Any]] = []
        for advisory_id, summary, severity, license_, payload_json in rows:
            try:
                payload = json.loads(payload_json) if payload_json else {}
            except json.JSONDecodeError:
                payload = {}
            out.append({
                "advisory_id": advisory_id,
                "summary": summary,
                "severity": severity,
                "license": license_,
                "advisory": payload,
            })
        return out

    def bulk_advisories_count(self, ecosystem: str | None = None) -> int:
        """Diagnostic — how many bulk-advisory rows are cached.

        Pass ``ecosystem=None`` for the grand total, or a specific
        ecosystem string (``RustSec``, ``Go``) to scope.
        """
        if ecosystem is None:
            row = self.conn.execute(
                "SELECT COUNT(*) FROM bulk_advisories"
            ).fetchone()
        else:
            row = self.conn.execute(
                "SELECT COUNT(*) FROM bulk_advisories WHERE ecosystem = ?",
                (ecosystem,),
            ).fetchone()
        return int(row[0]) if row else 0


def _encode_for_cache(vulns: list[DepVuln]) -> str:
    out = []
    for v in vulns:
        d = {k: getattr(v, k) for k in (
            "id", "summary", "severity", "cvss_score", "cvss_vector",
            "affected_versions", "fixed_versions", "references",
        )}
        out.append(d)
    return json.dumps(out)


def _decode_cached(raw: str, feed: CveFeed) -> list[dict[str, Any]]:
    out = []
    for d in json.loads(raw):
        if d.get("id", "").startswith("CVE-"):
            d["cve_info"] = feed.enrich(d["id"])
        out.append(d)
    return out


def _primary_id(v: dict[str, Any]) -> str:
    for a in v.get("aliases", []):
        if a.startswith("CVE-"):
            return a
    return v.get("id", "")


def _osv_severity(v: dict[str, Any]) -> tuple[str, float, str]:
    """Extract (severity_label, cvss_score, cvss_vector)."""
    for s in v.get("severity", []):
        if s.get("type", "").startswith("CVSS_V"):
            vec = s.get("score", "")
            score = _cvss_score_from_vector(vec)
            label = _label_for_score(score)
            return label, score, vec
    # Fallback to database_specific.severity
    for aff in v.get("affected", []):
        db = aff.get("database_specific", {})
        sev = (db.get("severity") or "").lower()
        if sev in {"critical", "high", "medium", "low"}:
            return sev, _score_for_label(sev), ""
    return "medium", 5.0, ""


def _cvss_score_from_vector(vec: str) -> float:
    """Best-effort parse — real CVSS calc lives in reporting/cvss.py."""
    # OSV often embeds the numeric score at the end, e.g. "CVSS:3.1/... " or pure "8.8"
    parts = vec.strip().split("/")
    for p in parts:
        try:
            return float(p)
        except ValueError:
            continue
    try:
        return float(vec)
    except (ValueError, TypeError):
        return 5.0


def _label_for_score(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score >= 0.1:
        return "low"
    return "info"


def _score_for_label(label: str) -> float:
    return {"critical": 9.5, "high": 7.5, "medium": 5.0, "low": 2.5}.get(label, 5.0)


def _affected_versions(v: dict[str, Any]) -> list[str]:
    out = []
    for aff in v.get("affected", []):
        for r in aff.get("ranges", []):
            for ev in r.get("events", []):
                if "introduced" in ev:
                    out.append(f">={ev['introduced']}")
                if "fixed" in ev:
                    out.append(f"<{ev['fixed']}")
    return out


def _fixed_versions(v: dict[str, Any]) -> list[str]:
    out = []
    for aff in v.get("affected", []):
        for r in aff.get("ranges", []):
            for ev in r.get("events", []):
                if "fixed" in ev:
                    out.append(ev["fixed"])
    return list(dict.fromkeys(out))


# ─── Freshness helpers ────────────────────────────────────────────────


def _is_stale(timestamp: str | None, *, hours: int) -> bool:
    """True when ``timestamp`` is older than ``hours`` ago, or unparseable.

    ``hours = 0`` is treated as "always stale" — the env-var override
    (PENCHEFF_OSV_TTL_HOURS=0) lets operators force live every scan.
    """
    if hours <= 0:
        return True
    if not timestamp:
        return True
    try:
        cached = datetime.fromisoformat(timestamp)
    except (TypeError, ValueError):
        return True
    if cached.tzinfo is None:
        cached = cached.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - cached).total_seconds() / 3600.0 > hours


def _age_hours(timestamp: str | None) -> float | None:
    """Return how many hours ago ``timestamp`` was, or None if unset."""
    if not timestamp:
        return None
    try:
        cached = datetime.fromisoformat(timestamp)
    except (TypeError, ValueError):
        return None
    if cached.tzinfo is None:
        cached = cached.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - cached).total_seconds() / 3600.0


# ─── NVD parser helpers ───────────────────────────────────────────────


def _parse_nvd_cve(cve_id: str, cve_obj: dict[str, Any]) -> NvdEnrichment:
    """Project the verbose NVD 2.0 CVE object into ``NvdEnrichment``.

    NVD's response shape:
      {
        "id": "CVE-2024-1234",
        "descriptions": [{"lang": "en", "value": "..."}],
        "weaknesses": [{"description": [{"value": "CWE-79"}]}],
        "configurations": [{"nodes": [{"cpeMatch": [{"criteria": "cpe:2.3:..."}]}]}],
        "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": ...}}]},
        "references": [{"url": "..."}],
        "published": "2024-01-15T00:00:00.000",
      }
    """
    cwes: list[str] = []
    for w in cve_obj.get("weaknesses", []) or []:
        for d in w.get("description", []) or []:
            value = (d.get("value") or "").strip()
            if value.startswith("CWE-") and value not in cwes:
                cwes.append(value)

    cpe_uris: list[str] = []
    for cfg in cve_obj.get("configurations", []) or []:
        for node in cfg.get("nodes", []) or []:
            for match in node.get("cpeMatch", []) or []:
                if not match.get("vulnerable"):
                    continue
                uri = match.get("criteria")
                if uri and uri not in cpe_uris:
                    cpe_uris.append(uri)
                if len(cpe_uris) >= 25:
                    break

    score, vector, severity = _extract_nvd_cvss(cve_obj.get("metrics") or {})

    description: str | None = None
    for d in cve_obj.get("descriptions", []) or []:
        if d.get("lang") == "en":
            description = (d.get("value") or "").strip() or None
            break

    return NvdEnrichment(
        cve=cve_id,
        cwe_ids=cwes,
        cpe_uris=cpe_uris,
        nvd_cvss_score=score,
        nvd_cvss_vector=vector,
        nvd_cvss_severity=severity,
        primary_url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        published=cve_obj.get("published"),
        description=description,
    )


def _extract_nvd_cvss(metrics: dict[str, Any]) -> tuple[float | None, str | None, str | None]:
    """Pick the highest-precedence CVSS score from NVD's metrics block.

    Order: v3.1 → v3.0 → v2.0. NVD usually publishes v3.1 — fall through
    only matters for legacy CVEs.
    """
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        rows = metrics.get(key) or []
        for row in rows:
            data = row.get("cvssData") or {}
            score = data.get("baseScore")
            vector = data.get("vectorString")
            severity = data.get("baseSeverity") or row.get("baseSeverity")
            if score is None:
                continue
            try:
                return float(score), vector, (severity or "").lower() or None
            except (TypeError, ValueError):
                continue
    return None, None, None


def _nvd_to_dict(e: NvdEnrichment) -> dict[str, Any]:
    return {
        "cve": e.cve,
        "cwe_ids": list(e.cwe_ids),
        "cpe_uris": list(e.cpe_uris),
        "nvd_cvss_score": e.nvd_cvss_score,
        "nvd_cvss_vector": e.nvd_cvss_vector,
        "nvd_cvss_severity": e.nvd_cvss_severity,
        "primary_url": e.primary_url,
        "published": e.published,
        "description": e.description,
    }


# ─── Singleton helpers ────────────────────────────────────────────────

_feed: CveFeed | None = None


def get_feed() -> CveFeed:
    global _feed
    if _feed is None:
        _feed = CveFeed()
    return _feed
