# SPDX-License-Identifier: AGPL-3.0-or-later
"""Go Vulnerability Database (GoVulnDB).

Upstream: https://pkg.go.dev/vuln (BSD-3-Clause licensed; the Go team's
own attribution applies to advisory text). OSV.dev mirrors the catalog
as a per-ecosystem ZIP at:

    https://osv-vulnerabilities.storage.googleapis.com/Go/all.zip
"""
from __future__ import annotations

from ._osv_bulk_source import OsvBulkSource


class GoVulnDbSource(OsvBulkSource):
    name = "govulndb"
    license = "BSD-3-Clause"
    ecosystem = "Go"
    zip_url = "https://osv-vulnerabilities.storage.googleapis.com/Go/all.zip"
