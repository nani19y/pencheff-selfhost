# SPDX-License-Identifier: AGPL-3.0-or-later
"""CISA Known Exploited Vulnerabilities catalogue.

License: U.S. public domain (CISA publishes the catalogue without
copyright restriction; ``license`` reflects that). Source:
https://www.cisa.gov/known-exploited-vulnerabilities-catalog
"""
from __future__ import annotations

import sqlite3
from typing import TYPE_CHECKING

from .base import BulkFeedSource

if TYPE_CHECKING:
    import httpx


KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)


class KevSource(BulkFeedSource):
    name = "kev"
    license = "Public Domain"
    schema_sql = (
        "CREATE TABLE IF NOT EXISTS kev ("
        "cve TEXT PRIMARY KEY, vendor TEXT, product TEXT, "
        "short_desc TEXT, required_action TEXT, due_date TEXT)"
    )

    async def refresh(
        self,
        conn: sqlite3.Connection,
        client: "httpx.AsyncClient",
    ) -> int:
        r = await client.get(KEV_URL)
        r.raise_for_status()
        data = r.json()
        rows = [
            (
                v.get("cveID", ""),
                v.get("vendorProject", ""),
                v.get("product", ""),
                v.get("shortDescription", ""),
                v.get("requiredAction", ""),
                v.get("dueDate", ""),
            )
            for v in data.get("vulnerabilities", [])
            if v.get("cveID")
        ]
        # KEV is a "current state" catalogue — wipe + reload so removed
        # entries actually drop out of the local cache.
        conn.execute("DELETE FROM kev")
        conn.executemany(
            "INSERT INTO kev VALUES (?, ?, ?, ?, ?, ?)", rows
        )
        conn.commit()
        return len(rows)
