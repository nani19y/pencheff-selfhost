"""SQLite-backed engagement store.

Mirrors the schema from
https://github.com/0xSteph/pentest-ai-agents/blob/HEAD/db/schema.sql
verbatim, but driven by stdlib ``sqlite3`` (no shell deps, cross-platform).

Tables: engagements, hosts, services, vulns, credentials, chains,
session_log, schema_version.

Default DB path: ``~/.pencheff/engagements.db`` (override with
``PENCHEFF_ENGAGEMENT_DB``).
"""

from __future__ import annotations

import json
import os
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

SCHEMA_VERSION = 1

SCHEMA_SQL = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY,
    applied_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS engagements (
    id TEXT PRIMARY KEY,
    client TEXT,
    type TEXT,
    scope TEXT,
    start_date TEXT,
    end_date TEXT,
    status TEXT DEFAULT 'active',
    notes TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS hosts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id TEXT NOT NULL REFERENCES engagements(id),
    ip TEXT,
    hostname TEXT,
    os TEXT,
    role TEXT,
    status TEXT DEFAULT 'alive',
    notes TEXT,
    discovered_by TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now')),
    UNIQUE(engagement_id, ip, hostname)
);

CREATE TABLE IF NOT EXISTS services (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER NOT NULL REFERENCES hosts(id),
    port INTEGER NOT NULL,
    protocol TEXT DEFAULT 'tcp',
    service TEXT,
    version TEXT,
    banner TEXT,
    state TEXT DEFAULT 'open',
    notes TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    UNIQUE(host_id, port, protocol)
);

CREATE TABLE IF NOT EXISTS vulns (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER REFERENCES hosts(id),
    service_id INTEGER REFERENCES services(id),
    engagement_id TEXT NOT NULL REFERENCES engagements(id),
    title TEXT NOT NULL,
    severity TEXT NOT NULL,
    cvss REAL,
    cve TEXT,
    description TEXT,
    evidence_file TEXT,
    status TEXT DEFAULT 'unconfirmed',
    poc_output TEXT,
    mitre_id TEXT,
    found_by TEXT,
    confirmed_by TEXT,
    notes TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS credentials (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id TEXT NOT NULL REFERENCES engagements(id),
    host_id INTEGER REFERENCES hosts(id),
    username TEXT,
    secret TEXT,
    secret_type TEXT,
    domain TEXT,
    source TEXT,
    access_level TEXT,
    valid INTEGER DEFAULT 1,
    notes TEXT,
    found_by TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    UNIQUE(engagement_id, username, domain, secret_type, host_id)
);

CREATE TABLE IF NOT EXISTS chains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id TEXT NOT NULL REFERENCES engagements(id),
    name TEXT NOT NULL,
    score INTEGER,
    status TEXT DEFAULT 'identified',
    steps TEXT,
    mitre_ids TEXT,
    notes TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS session_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id TEXT NOT NULL REFERENCES engagements(id),
    agent TEXT,
    action TEXT,
    summary TEXT,
    detail TEXT,
    created_at TEXT DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_hosts_engagement ON hosts(engagement_id);
CREATE INDEX IF NOT EXISTS idx_vulns_engagement ON vulns(engagement_id);
CREATE INDEX IF NOT EXISTS idx_vulns_severity ON vulns(severity);
CREATE INDEX IF NOT EXISTS idx_vulns_status ON vulns(status);
CREATE INDEX IF NOT EXISTS idx_creds_engagement ON credentials(engagement_id);
CREATE INDEX IF NOT EXISTS idx_chains_engagement ON chains(engagement_id);
CREATE INDEX IF NOT EXISTS idx_session_log_engagement ON session_log(engagement_id);
"""


def default_db_path() -> Path:
    override = os.environ.get("PENCHEFF_ENGAGEMENT_DB")
    if override:
        return Path(override).expanduser()
    return Path.home() / ".pencheff" / "engagements.db"


class EngagementDB:
    """Thin Python wrapper around the source repo's findings DB schema."""

    def __init__(self, path: Path | str | None = None):
        self.path = Path(path).expanduser() if path else default_db_path()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._migrate()

    @contextmanager
    def _conn(self):
        conn = sqlite3.connect(str(self.path))
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def _migrate(self) -> None:
        with self._conn() as c:
            c.executescript(SCHEMA_SQL)
            row = c.execute(
                "SELECT version FROM schema_version ORDER BY version DESC LIMIT 1"
            ).fetchone()
            if not row:
                c.execute(
                    "INSERT INTO schema_version(version) VALUES (?)", (SCHEMA_VERSION,)
                )

    # ── Engagements ────────────────────────────────────────────────
    def init_engagement(
        self,
        client: str,
        engagement_type: str = "external",
        scope: str | dict | None = None,
        notes: str = "",
        engagement_id: str | None = None,
    ) -> str:
        eid = engagement_id or uuid.uuid4().hex
        scope_str = json.dumps(scope) if isinstance(scope, dict) else (scope or "")
        with self._conn() as c:
            c.execute(
                "INSERT INTO engagements(id, client, type, scope, start_date, status, notes) "
                "VALUES (?, ?, ?, ?, ?, 'active', ?)",
                (eid, client, engagement_type, scope_str, _now(), notes),
            )
        return eid

    def list_engagements(self) -> list[dict[str, Any]]:
        with self._conn() as c:
            rows = c.execute(
                "SELECT * FROM engagements ORDER BY created_at DESC"
            ).fetchall()
            return [dict(r) for r in rows]

    def show(self, engagement_id: str) -> dict[str, Any] | None:
        with self._conn() as c:
            row = c.execute(
                "SELECT * FROM engagements WHERE id=?", (engagement_id,)
            ).fetchone()
            if not row:
                return None
            data = dict(row)
            data["hosts"] = [dict(r) for r in c.execute(
                "SELECT * FROM hosts WHERE engagement_id=?", (engagement_id,)
            ).fetchall()]
            data["vulns"] = [dict(r) for r in c.execute(
                "SELECT * FROM vulns WHERE engagement_id=? ORDER BY severity",
                (engagement_id,),
            ).fetchall()]
            data["credentials"] = [dict(r) for r in c.execute(
                "SELECT * FROM credentials WHERE engagement_id=?", (engagement_id,)
            ).fetchall()]
            data["chains"] = [dict(r) for r in c.execute(
                "SELECT * FROM chains WHERE engagement_id=?", (engagement_id,)
            ).fetchall()]
            data["session_log"] = [dict(r) for r in c.execute(
                "SELECT * FROM session_log WHERE engagement_id=? ORDER BY created_at",
                (engagement_id,),
            ).fetchall()]
            return data

    def close_engagement(self, engagement_id: str, status: str = "completed") -> None:
        with self._conn() as c:
            c.execute(
                "UPDATE engagements SET status=?, end_date=?, updated_at=? WHERE id=?",
                (status, _now(), _now(), engagement_id),
            )

    # ── Hosts / services ────────────────────────────────────────────
    def add_host(
        self,
        engagement_id: str,
        ip: str | None = None,
        hostname: str | None = None,
        os: str | None = None,
        role: str | None = None,
        notes: str = "",
        discovered_by: str = "",
    ) -> int:
        with self._conn() as c:
            try:
                cur = c.execute(
                    "INSERT INTO hosts(engagement_id, ip, hostname, os, role, notes, discovered_by) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (engagement_id, ip, hostname, os, role, notes, discovered_by),
                )
                return cur.lastrowid or 0
            except sqlite3.IntegrityError:
                row = c.execute(
                    "SELECT id FROM hosts WHERE engagement_id=? AND ip IS ? AND hostname IS ?",
                    (engagement_id, ip, hostname),
                ).fetchone()
                return row["id"] if row else 0

    def add_service(
        self,
        host_id: int,
        port: int,
        protocol: str = "tcp",
        service: str | None = None,
        version: str | None = None,
        banner: str | None = None,
        notes: str = "",
    ) -> int:
        with self._conn() as c:
            try:
                cur = c.execute(
                    "INSERT INTO services(host_id, port, protocol, service, version, banner, notes) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (host_id, port, protocol, service, version, banner, notes),
                )
                return cur.lastrowid or 0
            except sqlite3.IntegrityError:
                row = c.execute(
                    "SELECT id FROM services WHERE host_id=? AND port=? AND protocol=?",
                    (host_id, port, protocol),
                ).fetchone()
                return row["id"] if row else 0

    # ── Vulns ───────────────────────────────────────────────────────
    def add_vuln(
        self,
        engagement_id: str,
        title: str,
        severity: str,
        *,
        host_id: int | None = None,
        service_id: int | None = None,
        cvss: float | None = None,
        cve: str | None = None,
        description: str = "",
        evidence_file: str | None = None,
        status: str = "unconfirmed",
        poc_output: str = "",
        mitre_id: str | list[str] | None = None,
        found_by: str = "",
        notes: str = "",
    ) -> int:
        if isinstance(mitre_id, list):
            mitre_id = ",".join(mitre_id)
        with self._conn() as c:
            cur = c.execute(
                "INSERT INTO vulns(host_id, service_id, engagement_id, title, severity, cvss, cve, "
                "description, evidence_file, status, poc_output, mitre_id, found_by, notes) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    host_id, service_id, engagement_id, title, severity, cvss, cve,
                    description, evidence_file, status, poc_output, mitre_id, found_by, notes,
                ),
            )
            return cur.lastrowid or 0

    # ── Credentials ─────────────────────────────────────────────────
    def add_credential(
        self,
        engagement_id: str,
        username: str | None = None,
        secret: str | None = None,
        secret_type: str = "password",
        domain: str | None = None,
        host_id: int | None = None,
        source: str = "",
        access_level: str = "",
        valid: bool = True,
        found_by: str = "",
        notes: str = "",
    ) -> int:
        with self._conn() as c:
            try:
                cur = c.execute(
                    "INSERT INTO credentials(engagement_id, host_id, username, secret, secret_type, "
                    "domain, source, access_level, valid, notes, found_by) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (engagement_id, host_id, username, secret, secret_type, domain,
                     source, access_level, 1 if valid else 0, notes, found_by),
                )
                return cur.lastrowid or 0
            except sqlite3.IntegrityError:
                return 0

    # ── Chains ──────────────────────────────────────────────────────
    def add_chain(
        self,
        engagement_id: str,
        name: str,
        steps: list[str] | str,
        score: int = 0,
        mitre_ids: list[str] | str | None = None,
        status: str = "identified",
        notes: str = "",
    ) -> int:
        steps_str = json.dumps(steps) if isinstance(steps, list) else steps
        if isinstance(mitre_ids, list):
            mitre_ids = ",".join(mitre_ids)
        with self._conn() as c:
            cur = c.execute(
                "INSERT INTO chains(engagement_id, name, score, status, steps, mitre_ids, notes) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (engagement_id, name, score, status, steps_str, mitre_ids, notes),
            )
            return cur.lastrowid or 0

    def list_chains(self, engagement_id: str) -> list[dict[str, Any]]:
        with self._conn() as c:
            rows = c.execute(
                "SELECT * FROM chains WHERE engagement_id=? ORDER BY score DESC",
                (engagement_id,),
            ).fetchall()
            return [dict(r) for r in rows]

    # ── Session log / handoff ──────────────────────────────────────
    def log(
        self,
        engagement_id: str,
        agent: str,
        action: str,
        summary: str = "",
        detail: str | dict | None = None,
    ) -> int:
        if isinstance(detail, dict):
            detail = json.dumps(detail)
        with self._conn() as c:
            cur = c.execute(
                "INSERT INTO session_log(engagement_id, agent, action, summary, detail) "
                "VALUES (?, ?, ?, ?, ?)",
                (engagement_id, agent, action, summary, detail or ""),
            )
            return cur.lastrowid or 0

    def handoff(
        self,
        engagement_id: str,
        from_agent: str,
        to_agent: str,
        payload: dict | str,
    ) -> int:
        body = json.dumps(payload) if isinstance(payload, dict) else payload
        return self.log(
            engagement_id,
            agent=from_agent,
            action="handoff",
            summary=f"{from_agent} → {to_agent}",
            detail=body,
        )

    def session_log(self, engagement_id: str) -> list[dict[str, Any]]:
        with self._conn() as c:
            rows = c.execute(
                "SELECT * FROM session_log WHERE engagement_id=? ORDER BY created_at",
                (engagement_id,),
            ).fetchall()
            return [dict(r) for r in rows]

    # ── Export ──────────────────────────────────────────────────────
    def export_markdown(self, engagement_id: str) -> str:
        data = self.show(engagement_id)
        if not data:
            return f"# Engagement {engagement_id} not found\n"
        lines = [
            f"# Engagement: {data.get('client', 'unknown')} ({engagement_id})",
            f"- Type: {data.get('type', '')}",
            f"- Status: {data.get('status', '')}",
            f"- Scope: {data.get('scope', '') or '(none)'}",
            "",
            f"## Hosts ({len(data['hosts'])})",
        ]
        for h in data["hosts"]:
            lines.append(f"- {h.get('ip') or ''} {h.get('hostname') or ''} — {h.get('os') or 'unknown'}")
        lines.append("")
        lines.append(f"## Vulnerabilities ({len(data['vulns'])})")
        for v in data["vulns"]:
            lines.append(
                f"- **[{v.get('severity', '?').upper()}]** {v.get('title', '')} "
                f"(CVSS {v.get('cvss') or 'n/a'}, MITRE {v.get('mitre_id') or 'n/a'})"
            )
        lines.append("")
        lines.append(f"## Chains ({len(data['chains'])})")
        for ch in data["chains"]:
            lines.append(f"- **{ch.get('name', '')}** (score {ch.get('score', 0)}): {ch.get('steps', '')}")
        lines.append("")
        lines.append(f"## Credentials ({len(data['credentials'])})")
        for cred in data["credentials"]:
            lines.append(f"- {cred.get('username', '')}@{cred.get('domain', '') or 'local'} ({cred.get('secret_type', '')})")
        lines.append("")
        lines.append("## Session log")
        for r in data["session_log"]:
            lines.append(f"- `{r.get('created_at', '')}` **{r.get('agent', '')}**: {r.get('action', '')} — {r.get('summary', '')}")
        return "\n".join(lines) + "\n"


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
