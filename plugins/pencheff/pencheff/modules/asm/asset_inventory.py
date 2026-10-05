"""Asset inventory storage. Small SQLite index keyed by (org, asset_type, value).

Kept separate from the main scan session so discoveries survive across runs and
can be diffed over time.
"""

from __future__ import annotations

import json
import sqlite3
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

INV_DB = Path.home() / ".pencheff" / "asm_inventory.db"


@dataclass
class Asset:
    type: str  # domain | subdomain | ip | port | url | cert | tech
    value: str
    metadata: dict[str, Any] = field(default_factory=dict)
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)


def _connect() -> sqlite3.Connection:
    INV_DB.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(INV_DB)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS assets ("
        "org TEXT NOT NULL, type TEXT NOT NULL, value TEXT NOT NULL, "
        "metadata TEXT NOT NULL DEFAULT '{}', "
        "first_seen REAL NOT NULL, last_seen REAL NOT NULL, "
        "PRIMARY KEY (org, type, value))"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_assets_org_type ON assets(org, type)"
    )
    conn.commit()
    return conn


def upsert(org: str, asset: Asset) -> str:
    """Insert or update. Returns ``'new'`` | ``'updated'``."""
    conn = _connect()
    try:
        row = conn.execute(
            "SELECT first_seen FROM assets WHERE org=? AND type=? AND value=?",
            (org, asset.type, asset.value),
        ).fetchone()
        now = time.time()
        if row:
            conn.execute(
                "UPDATE assets SET last_seen=?, metadata=? "
                "WHERE org=? AND type=? AND value=?",
                (now, json.dumps(asset.metadata), org, asset.type, asset.value),
            )
            conn.commit()
            return "updated"
        conn.execute(
            "INSERT INTO assets VALUES (?, ?, ?, ?, ?, ?)",
            (org, asset.type, asset.value, json.dumps(asset.metadata),
             asset.first_seen, asset.last_seen),
        )
        conn.commit()
        return "new"
    finally:
        conn.close()


def list_assets(org: str, asset_type: str | None = None) -> list[Asset]:
    conn = _connect()
    try:
        if asset_type:
            rows = conn.execute(
                "SELECT type, value, metadata, first_seen, last_seen "
                "FROM assets WHERE org=? AND type=? ORDER BY last_seen DESC",
                (org, asset_type),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT type, value, metadata, first_seen, last_seen "
                "FROM assets WHERE org=? ORDER BY last_seen DESC",
                (org,),
            ).fetchall()
    finally:
        conn.close()
    return [
        Asset(type=r[0], value=r[1], metadata=json.loads(r[2]),
              first_seen=r[3], last_seen=r[4])
        for r in rows
    ]


def snapshot(org: str) -> dict[str, list[Asset]]:
    out: dict[str, list[Asset]] = {}
    for a in list_assets(org):
        out.setdefault(a.type, []).append(a)
    return out


def to_dict(a: Asset) -> dict[str, Any]:
    return asdict(a)
