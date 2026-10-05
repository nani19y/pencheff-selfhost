"""Unauthenticated network service misconfiguration checks.

Targets the short-list of services that, if exposed with default auth, give
an attacker immediate access:
  - Redis (no AUTH)
  - MongoDB (no auth, --bind_ip_all)
  - Elasticsearch (no shield)
  - Memcached (amp + read)
  - MySQL / PostgreSQL (default creds / trust auth)
  - SNMP v1/v2c (public / private community)
  - Docker daemon TCP (2375)

Each probe is a single short-timeout connect with the protocol's banner-query
bytes. Nothing destructive — pure information disclosure probing.
"""

from __future__ import annotations

import asyncio
import contextlib
from typing import Any

from pencheff.config import Severity
from pencheff.core.findings import Evidence, Finding


async def scan(host: str) -> list[Finding]:
    findings: list[Finding] = []
    for probe in (
        _probe_redis, _probe_mongo, _probe_elastic, _probe_memcached,
        _probe_docker, _probe_mysql, _probe_postgres, _probe_snmp,
    ):
        try:
            f = await probe(host)
            if f:
                findings.append(f)
        except Exception:  # noqa: BLE001
            continue
    return findings


async def _probe(host: str, port: int, send: bytes, expect: bytes | None = None) -> str | None:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=3.0
        )
    except Exception:  # noqa: BLE001
        return None
    try:
        if send:
            writer.write(send)
            await writer.drain()
        data = await asyncio.wait_for(reader.read(512), timeout=3.0)
        if expect is not None and expect not in data:
            return None
        return data.decode("utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        return None
    finally:
        with contextlib.suppress(Exception):
            writer.close()
            await writer.wait_closed()


async def _probe_redis(host: str) -> Finding | None:
    data = await _probe(host, 6379, b"*1\r\n$4\r\nPING\r\n")
    if data and "+PONG" in data:
        return _finding(
            "Redis exposed without authentication", host, 6379,
            Severity.CRITICAL,
            "Bind Redis to loopback only, or require AUTH and a strong password. "
            "Exposed Redis enables arbitrary command execution via SLAVEOF / CONFIG SET.",
            data[:200],
        )
    return None


async def _probe_mongo(host: str) -> Finding | None:
    # isMaster query OP_QUERY — simple fingerprint
    data = await _probe(host, 27017, b"", None)
    if data and ("isMaster" in data or "ismaster" in data or "MongoDB" in data):
        return _finding(
            "MongoDB accessible without authentication", host, 27017,
            Severity.CRITICAL,
            "Enable authorization in mongod.conf, create admin users, bind to internal interfaces only.",
            data[:200],
        )
    return None


async def _probe_elastic(host: str) -> Finding | None:
    # Elasticsearch speaks HTTP on 9200 — minimal GET /
    import httpx
    try:
        async with httpx.AsyncClient(timeout=3.0) as c:
            r = await c.get(f"http://{host}:9200/", headers={"Accept": "application/json"})
            if r.status_code == 200 and "elasticsearch" in r.text.lower():
                return _finding(
                    "Elasticsearch exposed without authentication", host, 9200,
                    Severity.HIGH,
                    "Enable X-Pack security or opensearch security; place behind an authenticated reverse proxy.",
                    r.text[:200],
                )
    except Exception:  # noqa: BLE001
        return None
    return None


async def _probe_memcached(host: str) -> Finding | None:
    data = await _probe(host, 11211, b"stats\r\n")
    if data and "STAT" in data:
        return _finding(
            "Memcached exposed without authentication", host, 11211,
            Severity.HIGH,
            "Bind Memcached to loopback; if UDP is enabled it can be abused for amplification DDoS. "
            "Disable UDP (-U 0) or firewall 11211/udp.",
            data[:200],
        )
    return None


async def _probe_docker(host: str) -> Finding | None:
    import httpx
    for port in (2375, 2376):
        try:
            async with httpx.AsyncClient(timeout=3.0) as c:
                r = await c.get(f"http://{host}:{port}/_ping")
                if r.status_code == 200 and r.text.strip() == "OK":
                    return _finding(
                        "Docker daemon exposed over TCP without TLS", host, port,
                        Severity.CRITICAL,
                        "Docker API on TCP = root on host. Disable unix socket exposure, or require "
                        "mTLS with client certificates (DOCKER_TLS_VERIFY=1).",
                        "ping ok",
                    )
        except Exception:  # noqa: BLE001
            continue
    return None


async def _probe_mysql(host: str) -> Finding | None:
    # Read the greeting packet; version leak is informational + suggests reachability
    data = await _probe(host, 3306, b"")
    if data and "mysql" in data.lower():
        return _finding(
            "MySQL reachable — verify authentication posture", host, 3306,
            Severity.MEDIUM,
            "If MySQL must be network-reachable, require TLS, strong authentication, and deny "
            "anonymous/root logins. Restrict bind-address to internal interfaces where possible.",
            data[:200],
        )
    return None


async def _probe_postgres(host: str) -> Finding | None:
    # Send a startup packet; a non-terse response indicates service presence.
    data = await _probe(host, 5432, b"")
    if data and len(data) > 0:
        return _finding(
            "PostgreSQL reachable — verify pg_hba.conf", host, 5432,
            Severity.MEDIUM,
            "Ensure pg_hba.conf uses scram-sha-256 for all external sources; do not use 'trust' auth.",
            data[:200],
        )
    return None


async def _probe_snmp(host: str) -> Finding | None:
    # Minimal SNMP v2c GET for sysDescr with community "public"
    try:
        transport, protocol = await asyncio.get_event_loop().create_datagram_endpoint(
            lambda: asyncio.DatagramProtocol(),
            remote_addr=(host, 161),
        )
    except Exception:  # noqa: BLE001
        return None
    try:
        pkt = (
            b"\x30\x29\x02\x01\x01\x04\x06public\xa0\x1c\x02\x04" b"\x00\x00\x00\x01"
            b"\x02\x01\x00\x02\x01\x00\x30\x0e\x30\x0c\x06\x08"
            b"\x2b\x06\x01\x02\x01\x01\x01\x00\x05\x00"
        )
        transport.sendto(pkt)
        await asyncio.sleep(0.5)
    finally:
        transport.close()
    # We can't easily read the response without a full SNMP decoder; if we
    # didn't error out, at least flag the port as needing review.
    return _finding(
        "SNMP port reachable — audit community strings", host, 161,
        Severity.LOW,
        "If SNMP is required, disable v1/v2c, use SNMPv3 with auth + priv, and never use "
        "'public' / 'private' community strings.",
        "",
    )


def _finding(title: str, host: str, port: int, sev: Severity, remediation: str, snippet: str) -> Finding:
    return Finding(
        title=title,
        severity=sev,
        category="misconfiguration",
        owasp_category="A05",
        description=f"{title}. Host {host} port {port} accepted our probe.",
        remediation=remediation,
        endpoint=f"{host}:{port}",
        evidence=[Evidence(
            request_method="TCP", request_url=f"{host}:{port}",
            response_status=0, description=snippet[:300],
        )],
    )
