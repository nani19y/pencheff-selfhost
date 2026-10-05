# SPDX-License-Identifier: AGPL-3.0-or-later
"""RustSec advisory database.

Upstream: https://github.com/rustsec/advisory-db (CC0-1.0 licensed —
public-domain-dedicated, no attribution required, but we still record
``license`` so downstream consumers know).

We pull from the OSV.dev mirror's per-ecosystem ZIP at:

    https://osv-vulnerabilities.storage.googleapis.com/RustSec/all.zip

Same shape as every other ``OsvBulkSource``; one extra config field
(``ecosystem``) and one URL.
"""
from __future__ import annotations

from ._osv_bulk_source import OsvBulkSource


class RustSecSource(OsvBulkSource):
    name = "rustsec"
    license = "CC0-1.0"
    ecosystem = "RustSec"
    zip_url = "https://osv-vulnerabilities.storage.googleapis.com/RustSec/all.zip"
