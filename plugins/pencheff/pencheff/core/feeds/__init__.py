# SPDX-License-Identifier: AGPL-3.0-or-later
"""Bulk-refresh feed source registry.

Each entry in ``REGISTRY`` is a ``BulkFeedSource`` subclass instance.
The ``CveFeed`` orchestrator iterates this list during
``refresh()`` / ``ensure_feeds_fresh()``; adding a new feed source is
a one-line append to ``REGISTRY`` plus a new module under this
package.

Adding a source:

1. Create ``feeds/<name>.py`` with a ``BulkFeedSource`` subclass.
2. Append the class instance below.
3. Add the upstream's license to ``THIRD_PARTY_NOTICES.md`` (the
   auto-generator picks it up from ``self.license``).
"""
from __future__ import annotations

from .base import BulkFeedSource
from .epss import EpssSource
from .govulndb import GoVulnDbSource
from .kev import KevSource
from .rustsec import RustSecSource

REGISTRY: list[BulkFeedSource] = [
    # Per-CVE enrichment feeds
    EpssSource(),
    KevSource(),
    # Per-package OSV-zip feeds (Phase 1.1b — share the
    # ``bulk_advisories`` cache table via ``OsvBulkSource``)
    RustSecSource(),
    GoVulnDbSource(),
]


def all_sources() -> list[BulkFeedSource]:
    """Return the canonical bulk-feed registry."""
    return list(REGISTRY)


__all__ = [
    "BulkFeedSource",
    "EpssSource",
    "KevSource",
    "RustSecSource",
    "GoVulnDbSource",
    "REGISTRY",
    "all_sources",
]
