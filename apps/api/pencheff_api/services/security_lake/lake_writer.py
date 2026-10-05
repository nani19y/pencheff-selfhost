# pencheff_api/services/security_lake/lake_writer.py
from __future__ import annotations

from typing import Any

import pyarrow as pa
from pyiceberg.catalog import Catalog
from pyiceberg.catalog.sql import SqlCatalog

from .lake_schema import LAKE_SCHEMA, LAKE_PARTITION_SPEC


def build_local_catalog(*, uri: str, warehouse: str) -> Catalog:
    """A SQLite-backed Iceberg catalog over a local filesystem warehouse (dev/tests)."""
    return SqlCatalog("pencheff", uri=uri, warehouse=warehouse)


def _s3_props(settings: Any) -> dict:
    """R2 (S3-compatible) FileIO props, when R2 object storage is configured.

    Verified against Cloudflare R2 (2026-06-13): ``s3.region='auto'`` + the R2 S3
    endpoint + access keys let pyiceberg read/write the warehouse on R2.
    """
    props: dict = {}
    endpoint = getattr(settings, "r2_endpoint_url", None)
    akid = getattr(settings, "r2_access_key_id", None)
    secret = getattr(settings, "r2_secret_access_key", None)
    if endpoint:
        props["s3.endpoint"] = endpoint
        props["s3.region"] = "auto"
    if akid:
        props["s3.access-key-id"] = akid
    if secret:
        props["s3.secret-access-key"] = secret
    return props


def build_catalog(settings: Any) -> Catalog:
    """Build the configured Iceberg catalog.

    - ``sql`` (default, prod): a SQL catalog (SQLite locally, **Postgres in prod**
      via ``lake_catalog_uri``) whose warehouse may be local (``file://``) or
      **R2** (``s3://…`` + the ``r2_*`` creds → S3 FileIO). This is the prod path:
      Postgres holds the catalog pointer, R2 durably stores metadata + data.
    - ``rest``: an Iceberg REST catalog (e.g. R2 Data Catalog) — supported but not
      used by default (needs the separate R2 Data Catalog permission).
    """
    if settings.lake_catalog_type == "rest":
        from pyiceberg.catalog.rest import RestCatalog
        props = {"uri": settings.lake_catalog_uri, "warehouse": settings.lake_warehouse}
        if settings.lake_catalog_token:
            props["token"] = settings.lake_catalog_token
        props.update(_s3_props(settings))
        return RestCatalog("pencheff", **props)
    # sql catalog (SQLite/Postgres) + local-or-R2 warehouse
    props = {"uri": settings.lake_catalog_uri, "warehouse": settings.lake_warehouse}
    props.update(_s3_props(settings))
    return SqlCatalog("pencheff", **props)


class LakeWriter:
    """Appends OCSF rows to the Iceberg findings table. Append-only; one snapshot per batch."""

    def __init__(self, catalog: Catalog, *, namespace: str, table: str):
        self._catalog = catalog
        self._namespace = namespace
        self._table = table
        self._identifier = f"{namespace}.{table}"

    def ensure_table(self) -> None:
        self._catalog.create_namespace_if_not_exists(self._namespace)
        self._catalog.create_table_if_not_exists(
            self._identifier, schema=LAKE_SCHEMA, partition_spec=LAKE_PARTITION_SPEC,
        )

    def load_table(self):
        return self._catalog.load_table(self._identifier)

    def append_rows(self, rows: list[dict]) -> int:
        """Append rows as one Iceberg snapshot. Empty input is a no-op. Returns count."""
        if not rows:
            return 0
        tbl = self.load_table()
        tbl.append(pa.Table.from_pylist(rows, schema=tbl.schema().as_arrow()))
        return len(rows)
