# SPDX-License-Identifier: AGPL-3.0-or-later
"""Shared base for OSV-zip-format bulk advisory feeds.

The OSV.dev project mirrors every ecosystem-specific advisory database
as a single ZIP of OSV-format JSON files at:

    https://osv-vulnerabilities.storage.googleapis.com/<ECOSYSTEM>/all.zip

That uniform shape is the right plug-in for ``BulkFeedSource``:
download the ZIP once per TTL, walk the JSON entries, fan out into a
shared ``bulk_advisories`` cache table keyed by (ecosystem, package).

Subclasses only need to declare:

* ``name``, ``license``, ``ecosystem`` — identity + attribution.
* ``zip_url`` — the OSV mirror URL for this ecosystem.

Concrete subclasses live in ``feeds/rustsec.py``, ``feeds/govulndb.py``
(and Phase 1.1b/1.1+: ``ghsa.py``, ``redhat.py``, ``ubuntu.py``,
``debian.py``, ``alpine.py``, ``npm.py``, ``maven.py``, …).

The shared cache table is created once at first connection by
``CveFeed._connect`` from the schema declared on the *first* OSV-bulk
source the registry walks — every subsequent OSV-bulk source returns
the same ``schema_sql`` string, which is a no-op on the second
``CREATE TABLE IF NOT EXISTS``.
"""
from __future__ import annotations

import io
import json
import sqlite3
import zipfile
from typing import TYPE_CHECKING

from .base import BulkFeedSource

if TYPE_CHECKING:
    import httpx


_BULK_ADVISORIES_SCHEMA = (
    "CREATE TABLE IF NOT EXISTS bulk_advisories ("
    "ecosystem TEXT NOT NULL, "
    "advisory_id TEXT NOT NULL, "
    "package TEXT, "
    "summary TEXT, "
    "severity TEXT, "
    "license TEXT, "
    "payload_json TEXT, "
    "cached_at TEXT, "
    "PRIMARY KEY (ecosystem, advisory_id))"
)


class OsvBulkSource(BulkFeedSource):
    """Bulk OSV-zip refresh skeleton.

    Subclasses set ``name``, ``license``, ``ecosystem``, ``zip_url``.
    """

    ecosystem: str = ""
    zip_url: str = ""
    schema_sql = _BULK_ADVISORIES_SCHEMA

    async def refresh(
        self,
        conn: sqlite3.Connection,
        client: "httpx.AsyncClient",
    ) -> int:
        if not self.zip_url or not self.ecosystem:
            raise ValueError(
                f"OsvBulkSource {self.name!r} missing zip_url / ecosystem",
            )
        r = await client.get(self.zip_url)
        r.raise_for_status()

        rows: list[tuple[str, str, str | None, str | None, str | None, str, str, str]] = []
        from datetime import datetime, timezone
        now_iso = datetime.now(timezone.utc).isoformat()

        with zipfile.ZipFile(io.BytesIO(r.content)) as zf:
            for member in zf.namelist():
                if not member.endswith(".json"):
                    continue
                try:
                    data = json.loads(zf.read(member))
                except (json.JSONDecodeError, KeyError):
                    continue
                advisory_id = data.get("id")
                if not advisory_id:
                    continue
                summary = (data.get("summary") or "")[:500]
                package = _first_package(data)
                severity = _first_severity_label(data)
                rows.append((
                    self.ecosystem,
                    advisory_id,
                    package,
                    summary,
                    severity,
                    self.license,
                    json.dumps(data),
                    now_iso,
                ))

        # Wipe + reload the per-ecosystem slice so removed advisories
        # don't strand stale rows. Other ecosystems' rows are untouched.
        conn.execute(
            "DELETE FROM bulk_advisories WHERE ecosystem = ?",
            (self.ecosystem,),
        )
        conn.executemany(
            "INSERT OR REPLACE INTO bulk_advisories VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            rows,
        )
        conn.commit()
        return len(rows)


def _first_package(advisory: dict) -> str | None:
    """Pull the first ``affected[].package.name`` if any.

    OSV advisories declare each affected package under ``affected[]``;
    callers want a quick package-string for the per-package index.
    Returns ``None`` when the advisory is unaffected by any specific
    package (rare for ecosystem feeds).
    """
    for aff in advisory.get("affected", []) or []:
        pkg = (aff.get("package") or {}).get("name")
        if pkg:
            return str(pkg)
    return None


def _first_severity_label(advisory: dict) -> str | None:
    """Best-effort severity label.

    OSV's ``severity[]`` carries CVSS vectors; ``database_specific``
    sometimes carries a categorical label. Returns ``None`` when
    neither is set — callers fall back to scoring the CVSS vector.
    """
    for s in advisory.get("severity", []) or []:
        if s.get("type", "").startswith("CVSS_V"):
            return "scored"  # caller will compute score from the vector
    db_specific = advisory.get("database_specific") or {}
    sev = (db_specific.get("severity") or "").lower()
    if sev in {"critical", "high", "medium", "low"}:
        return sev
    return None
