"""Continuous discovery: subfinder + crt.sh (+ optional shodan/censys).

Run periodically (e.g. from Celery Beat) to refresh the asset inventory for
an organisation's root domain. No active scanning — strictly passive enumeration.
"""

from __future__ import annotations

import json
import os
import subprocess  # noqa: S404 — only runs allowlisted tools
from typing import Any

import httpx

from pencheff.modules.asm import asset_inventory


async def discover(org: str, root_domain: str) -> dict[str, int]:
    """Return a count summary; writes results into the local inventory."""
    counts: dict[str, int] = {"subdomains": 0, "certs": 0, "shodan_hosts": 0}

    subs = set(_subfinder(root_domain))
    subs |= set(await _crtsh(root_domain))
    for s in subs:
        res = asset_inventory.upsert(
            org, asset_inventory.Asset(type="subdomain", value=s,
                                       metadata={"discovery": "passive"})
        )
        counts["subdomains"] += 1 if res == "new" else 0

    for cert in await _crt_certs(root_domain):
        res = asset_inventory.upsert(
            org, asset_inventory.Asset(type="cert", value=cert["name"],
                                       metadata=cert)
        )
        counts["certs"] += 1 if res == "new" else 0

    for host in await _shodan(root_domain):
        res = asset_inventory.upsert(
            org, asset_inventory.Asset(type="ip", value=host["ip"],
                                       metadata=host)
        )
        counts["shodan_hosts"] += 1 if res == "new" else 0

    return counts


def _subfinder(domain: str) -> list[str]:
    try:
        p = subprocess.run(  # noqa: S603
            ["subfinder", "-d", domain, "-silent", "-json"],
            capture_output=True, text=True, timeout=120, check=False,
        )
    except (FileNotFoundError, subprocess.SubprocessError):
        return []
    out: list[str] = []
    for line in p.stdout.splitlines():
        try:
            obj = json.loads(line)
            if obj.get("host"):
                out.append(obj["host"])
        except json.JSONDecodeError:
            line = line.strip()
            if line:
                out.append(line)
    return out


# Common two-label eTLDs — guards against expanding e.g. ``foo.example.co.uk``
# to ``%.co.uk`` (which would return every UK-hosted cert and either time out
# or be refused by crt.sh). Not exhaustive; covers the common cases.
_MULTI_LEVEL_TLDS: frozenset[str] = frozenset({
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "net.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.nz", "net.nz", "org.nz", "ac.nz",
    "com.br", "net.br", "org.br",
    "co.in", "net.in", "org.in", "ac.in",
    "co.jp", "ne.jp", "or.jp", "ac.jp",
    "com.sg", "org.sg", "edu.sg",
    "com.hk", "org.hk", "edu.hk",
    "co.za", "org.za",
    "com.mx",
    "com.tr", "org.tr",
})


def _queries_for(domain: str) -> list[str]:
    """Expand the user-entered domain into multiple crt.sh query strings.

    crt.sh's ``%.example.com`` returns only _subdomains_ of example.com. For
    ``miatest.example.com`` we also want the exact host, the apex, and
    sibling subdomains of the apex — otherwise a host with no sub-sub-domains
    looks empty even when the broader org has plenty of certificates.
    """
    parts = [p for p in domain.split(".") if p]
    queries: list[str] = [f"%.{domain}", domain]

    if len(parts) > 2:
        last_two = ".".join(parts[-2:])
        # Skip apex expansion if the "apex" is actually a known multi-level
        # eTLD — expanding to ``%.co.uk`` etc. is nonsensical and the query
        # would time out.
        apex = (
            ".".join(parts[-3:])
            if last_two in _MULTI_LEVEL_TLDS and len(parts) >= 3
            else last_two
        )
        if apex != domain:
            queries.extend([f"%.{apex}", apex])

    # De-dup while preserving order.
    seen: set[str] = set()
    return [q for q in queries if not (q in seen or seen.add(q))]


async def _crtsh_fetch(
    query: str, retries: int = 2, timeout: float = 20.0
) -> list[dict[str, Any]]:
    """Fetch a single crt.sh query. 404 means "no results"; 502/503/429 are retried."""
    import asyncio
    backoff = 1.5
    async with httpx.AsyncClient(
        timeout=timeout, headers={"User-Agent": "pencheff-asm/1.0"}
    ) as client:
        for attempt in range(retries + 1):
            try:
                r = await client.get(
                    f"https://crt.sh/?q={query}&output=json"
                )
            except Exception:  # noqa: BLE001 — network/DNS transient
                if attempt < retries:
                    await asyncio.sleep(backoff ** attempt)
                    continue
                return []
            if r.status_code == 404:
                # crt.sh returns 404 when zero certs match — not an error.
                return []
            if r.status_code in {429, 502, 503}:
                if attempt < retries:
                    await asyncio.sleep(backoff ** attempt)
                    continue
                return []
            if r.status_code != 200:
                return []
            try:
                return r.json() or []
            except Exception:  # noqa: BLE001
                return []
    return []


async def _crtsh(domain: str) -> list[str]:
    """Return unique hostnames from crt.sh matching ``domain`` or its apex."""
    out: set[str] = set()
    for q in _queries_for(domain):
        rows = await _crtsh_fetch(q)
        for row in rows:
            for name in (row.get("name_value") or "").splitlines():
                name = name.strip().lstrip("*.")
                if name and not name.startswith("-"):
                    out.add(name)
    return sorted(out)


async def _crt_certs(domain: str) -> list[dict[str, Any]]:
    """Return cert metadata from crt.sh matching ``domain`` or its apex (capped at 200)."""
    out: list[dict[str, Any]] = []
    seen_serials: set[str] = set()
    for q in _queries_for(domain):
        rows = await _crtsh_fetch(q)
        for row in rows:
            serial = row.get("serial_number", "")
            if serial and serial in seen_serials:
                continue
            seen_serials.add(serial)
            out.append({
                "name": row.get("common_name", ""),
                "issuer": row.get("issuer_name", ""),
                "not_before": row.get("not_before", ""),
                "not_after": row.get("not_after", ""),
                "serial": serial,
            })
            if len(out) >= 200:
                return out
    return out


async def _shodan(domain: str) -> list[dict[str, Any]]:
    key = os.environ.get("SHODAN_API_KEY")
    if not key:
        return []
    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            r = await client.get(
                "https://api.shodan.io/shodan/host/search",
                params={"key": key, "query": f"hostname:{domain}", "limit": 100},
            )
        if r.status_code != 200:
            return []
        data = r.json()
    except Exception:  # noqa: BLE001
        return []
    return [
        {"ip": m.get("ip_str"), "port": m.get("port"), "product": m.get("product")}
        for m in data.get("matches", [])
    ]
