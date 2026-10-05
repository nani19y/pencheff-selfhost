# pencheff_api/services/security_lake/lake_query.py
from __future__ import annotations

import io
from typing import Any

import duckdb
import pyarrow.parquet as pq
from pyiceberg.expressions import EqualTo

from .lake_writer import build_catalog


def _org_arrow(settings: Any, org_id: str):
    """Scan the org's partition into an Arrow table. Empty table if none/missing."""
    catalog = build_catalog(settings)
    identifier = f"{settings.lake_namespace}.{settings.lake_table}"
    try:
        table = catalog.load_table(identifier)
    except Exception:  # noqa: BLE001 — table not created yet => no findings
        return None
    # Coerce to str: org_id is a StringType column, but callers may hand us a
    # uuid.UUID (raw SQL rows) which pyiceberg can't bind to a string predicate.
    return table.scan(row_filter=EqualTo("org_id", str(org_id))).to_arrow()


def _con(arrow):
    con = duckdb.connect()
    con.register("findings", arrow)
    return con


_LATEST_CTE = """
WITH ranked AS (
    SELECT *, row_number() OVER (PARTITION BY finding_uid ORDER BY time DESC) AS rn
    FROM findings
),
latest AS (SELECT * FROM ranked WHERE rn = 1)
"""


def query_findings(settings: Any, *, org_id: str, source: str | None = None,
                   severity_id: int | None = None, status_id: int | None = None,
                   asset_id: str | None = None, limit: int = 100,
                   offset: int = 0) -> tuple[list[dict], int]:
    """Current-state findings (latest event per finding_uid), org-scoped + filtered."""
    arrow = _org_arrow(settings, org_id)
    if arrow is None or arrow.num_rows == 0:
        return [], 0
    con = _con(arrow)
    where = ["(? IS NULL OR source = ?)", "(? IS NULL OR severity_id = ?)",
             "(? IS NULL OR status_id = ?)", "(? IS NULL OR asset_id = ?)"]
    params = [source, source, severity_id, severity_id,
              status_id, status_id, asset_id, asset_id]
    clause = " AND ".join(where)
    total = con.execute(
        f"{_LATEST_CTE} SELECT count(*) FROM latest WHERE {clause}", params
    ).fetchone()[0]
    rows = con.execute(
        f"""{_LATEST_CTE}
        SELECT finding_uid, class_uid, source, severity_id, status_id, asset_id,
               time, dt, ocsf_json
        FROM latest WHERE {clause}
        ORDER BY severity_id DESC, time DESC
        LIMIT ? OFFSET ?""",
        params + [limit, offset],
    ).to_arrow_table().to_pylist()
    for r in rows:
        r["org_id"] = org_id
    return rows, int(total)


def query_trends(settings: Any, *, org_id: str) -> list[dict]:
    """Distinct findings observed per day (+ high/critical subset), org-scoped."""
    arrow = _org_arrow(settings, org_id)
    if arrow is None or arrow.num_rows == 0:
        return []
    con = _con(arrow)
    rows = con.execute(
        """SELECT dt,
                  count(DISTINCT finding_uid) AS open_findings,
                  count(DISTINCT CASE WHEN severity_id >= 4 THEN finding_uid END)
                      AS high_critical
           FROM findings GROUP BY dt ORDER BY dt"""
    ).to_arrow_table().to_pylist()
    return rows


def query_correlate(settings: Any, *, org_id: str, min_assets: int = 2) -> list[dict]:
    """CVEs present on >= min_assets distinct assets in the org (current state)."""
    arrow = _org_arrow(settings, org_id)
    if arrow is None or arrow.num_rows == 0:
        return []
    con = _con(arrow)
    rows = con.execute(
        f"""{_LATEST_CTE}
        SELECT json_extract_string(ocsf_json, '$.vulnerabilities[0].cve.uid') AS cve,
               count(DISTINCT asset_id) AS assets,
               count(DISTINCT finding_uid) AS findings
        FROM latest
        WHERE json_extract_string(ocsf_json, '$.vulnerabilities[0].cve.uid') IS NOT NULL
        GROUP BY cve HAVING count(DISTINCT asset_id) >= ?
        ORDER BY assets DESC, cve""",
        [min_assets],
    ).to_arrow_table().to_pylist()
    return rows


def export_org_ndjson(settings: Any, *, org_id: str, source: str | None = None) -> str:
    """The org's current-state OCSF events as NDJSON (one event per line).

    SIEM-ready (Splunk/Sentinel ingest NDJSON directly). Org-scoped server-side;
    latest event per finding_uid.
    """
    arrow = _org_arrow(settings, org_id)
    if arrow is None or arrow.num_rows == 0:
        return ""
    con = _con(arrow)
    rows = con.execute(
        f"""{_LATEST_CTE}
        SELECT ocsf_json FROM latest
        WHERE (? IS NULL OR source = ?)
        ORDER BY finding_uid""",
        [source, source],
    ).fetchall()
    return "\n".join(r[0] for r in rows)


def export_org_parquet(settings: Any, *, org_id: str, source: str | None = None) -> bytes:
    """The org's current-state lake rows as a Parquet blob (lake-to-lake / Spark)."""
    arrow = _org_arrow(settings, org_id)
    if arrow is None or arrow.num_rows == 0:
        return b""
    con = _con(arrow)
    table = con.execute(
        f"""{_LATEST_CTE}
        SELECT finding_uid, org_id, class_uid, source, severity_id, status_id,
               asset_id, time, dt, ocsf_json
        FROM latest
        WHERE (? IS NULL OR source = ?)
        ORDER BY finding_uid""",
        [source, source],
    ).to_arrow_table()
    buf = io.BytesIO()
    pq.write_table(table, buf)
    return buf.getvalue()
