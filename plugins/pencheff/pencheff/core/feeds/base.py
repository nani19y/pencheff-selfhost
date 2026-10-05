# SPDX-License-Identifier: AGPL-3.0-or-later
"""Pluggable bulk-refresh feed protocol.

The ``CveFeed`` originally hard-coded EPSS and KEV refresh inline. This
module extracts the contract so Phase 1.1b can drop in RustSec
(CC0), GoVulnDB (BSD-3), GHSA, and distro feeds (RedHat / Ubuntu /
Debian / Alpine) without touching ``cve_feed.py`` itself.

Two shapes exist in the wild:

* **Bulk-refresh** — EPSS, KEV, RustSec, GoVulnDB-bulk, distro feeds.
  A single download fans out into per-CVE / per-package rows. This
  module covers that shape.
* **On-demand query** — OSV (per-package), NVD (per-CVE). These are
  fundamentally different and stay in ``cve_feed.py``.

A new bulk-refresh source needs three things:

1. A subclass of ``BulkFeedSource`` with a unique ``name``, the
   upstream ``license`` (for per-row attribution), and the SQLite
   ``schema_sql`` for its cache table.
2. An ``async refresh(conn, client)`` that downloads the upstream
   bytes, parses them, and writes rows into its cache table. It should
   return the number of rows written.
3. Registration in ``feeds/__init__.py`` so the registry picks it up.

The ``CveFeed`` orchestrator then iterates the registry on
``refresh()`` and ``ensure_feeds_fresh()``.
"""
from __future__ import annotations

import abc
import sqlite3
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # avoid the runtime httpx import on `from feeds.base import …`
    import httpx


class BulkFeedSource(abc.ABC):
    """Contract for a bulk-refresh CVE / advisory data feed.

    Subclasses must override:

    * ``name`` — short identifier (``epss``, ``kev``, ``rustsec``, …).
      Used as the row key in ``feed_meta`` and as the lookup namespace
      for callers.
    * ``license`` — SPDX license id of the upstream data
      (``CC-BY-4.0``, ``Public Domain``, ``CC0-1.0``, etc.). Surfaced
      on every consumed advisory so attribution requirements are
      preservable.
    * ``schema_sql`` — the ``CREATE TABLE IF NOT EXISTS …`` for this
      feed's cache table. Run once at connection bootstrap.
    * ``refresh(conn, client)`` — fetch upstream bytes, parse, write
      rows; return the number of rows written.
    """

    name: str = ""
    license: str = ""
    schema_sql: str = ""

    @abc.abstractmethod
    async def refresh(
        self,
        conn: sqlite3.Connection,
        client: "httpx.AsyncClient",
    ) -> int:
        """Refresh this feed's cache. Return the number of rows written.

        Implementations must:

        * Be idempotent (safe to call repeatedly).
        * Use ``INSERT OR REPLACE`` (or ``DELETE`` + bulk insert) so a
          partial refresh doesn't strand stale rows.
        * Raise on hard failure — the orchestrator records the error
          on ``feed_meta`` and continues with the next feed.

        ``conn`` is the shared SQLite connection; the feed must commit
        before returning. ``client`` is a shared async HTTP client to
        amortise TCP / TLS setup across feeds.
        """
        raise NotImplementedError
