# pencheff_api/services/security_lake/lake_schema.py
from __future__ import annotations

import datetime as _dt
import json

from pyiceberg.schema import Schema
from pyiceberg.types import NestedField, StringType, IntegerType, LongType
from pyiceberg.partitioning import PartitionSpec, PartitionField
from pyiceberg.transforms import IdentityTransform

# Hybrid layout: typed partition/query columns + the full OCSF event as JSON.
LAKE_SCHEMA = Schema(
    NestedField(1, "org_id", StringType(), required=True),
    NestedField(2, "class_uid", IntegerType(), required=True),
    NestedField(3, "source", StringType(), required=True),
    NestedField(4, "finding_uid", StringType(), required=True),
    NestedField(5, "time", LongType(), required=True),
    NestedField(6, "dt", StringType(), required=True),
    NestedField(7, "severity_id", IntegerType(), required=True),
    NestedField(8, "ocsf_json", StringType(), required=True),
    NestedField(9, "asset_id", StringType(), required=True),
    NestedField(10, "status_id", IntegerType(), required=True),
)

LAKE_PARTITION_SPEC = PartitionSpec(
    PartitionField(source_id=1, field_id=1000, transform=IdentityTransform(), name="org_id"),
    PartitionField(source_id=2, field_id=1001, transform=IdentityTransform(), name="class_uid"),
    PartitionField(source_id=6, field_id=1002, transform=IdentityTransform(), name="dt"),
)


def dt_from_ms(time_ms: int) -> str:
    """UTC calendar date (YYYY-MM-DD) used as the daily partition key."""
    return _dt.datetime.fromtimestamp(time_ms / 1000, tz=_dt.timezone.utc).strftime("%Y-%m-%d")


def to_lake_row(event: dict, *, org_id: str, source: str, asset_id: str) -> dict:
    """Project a validated OCSF event into one Iceberg row (hybrid layout)."""
    uid = (event.get("finding_info") or {}).get("uid")
    if not uid:
        raise ValueError("OCSF event missing finding_info.uid; mapper must set it")
    return {
        "org_id": org_id,
        "class_uid": event["class_uid"],
        "source": source,
        "finding_uid": uid,
        "time": event["time"],
        "dt": dt_from_ms(event["time"]),
        "severity_id": event["severity_id"],
        "ocsf_json": json.dumps(event, separators=(",", ":")),
        "asset_id": asset_id,
        "status_id": event["status_id"],
    }
