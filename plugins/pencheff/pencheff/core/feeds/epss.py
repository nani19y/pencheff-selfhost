# SPDX-License-Identifier: AGPL-3.0-or-later
"""FIRST EPSS feed — daily exploit-prediction scores.

License: CC-BY-4.0 (attribution required; surfaced via ``self.license``
and on every per-row consumer in the ``BulkFeedSource`` contract).

Source: https://www.first.org/epss/data_stats — published daily as a
gzip'd CSV at the URL below. The orchestrator refreshes when the local
cache row is older than ``PENCHEFF_FEED_TTL_HOURS`` (default 24h).
"""
from __future__ import annotations

import csv
import gzip
import io
import sqlite3
from typing import TYPE_CHECKING

from .base import BulkFeedSource

if TYPE_CHECKING:
    import httpx


EPSS_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"


class EpssSource(BulkFeedSource):
    name = "epss"
    license = "CC-BY-4.0"
    schema_sql = (
        "CREATE TABLE IF NOT EXISTS epss ("
        "cve TEXT PRIMARY KEY, epss REAL, percentile REAL, updated_at TEXT)"
    )

    async def refresh(
        self,
        conn: sqlite3.Connection,
        client: "httpx.AsyncClient",
    ) -> int:
        r = await client.get(EPSS_URL)
        r.raise_for_status()
        buf = gzip.decompress(r.content).decode()
        reader = csv.DictReader(io.StringIO(buf), skipinitialspace=True)
        rows: list[tuple[str, float, float, str]] = []
        for row in reader:
            cve = row.get("cve", "")
            if not cve.startswith("CVE-"):
                continue
            try:
                epss = float(row.get("epss", 0))
                pct = float(row.get("percentile", 0))
            except (TypeError, ValueError):
                continue
            rows.append((cve, epss, pct, ""))
        conn.executemany(
            "INSERT OR REPLACE INTO epss VALUES (?, ?, ?, ?)", rows
        )
        conn.commit()
        return len(rows)
