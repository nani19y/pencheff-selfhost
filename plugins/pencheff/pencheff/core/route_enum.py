"""Built-in route / path enumeration.

Probes a target for the paths in
``pencheff/data/route_wordlist.txt`` (curated ~120-entry list of common
admin / config / backup / API endpoints). HEAD-then-GET, considers the
target's own SPA fallback signature so we don't emit a finding for every
catch-all route on a single-page app.

Falls back to ``ffuf`` via ``run_security_tool`` when a real wordlist is
provided via ``--wordlist``.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

from pencheff.config import Severity
from pencheff.core.findings import Evidence, Finding
from pencheff.core.http_client import PencheffHTTPClient

_DEFAULT_WORDLIST = Path(__file__).resolve().parents[1] / "data" / "route_wordlist.txt"


# Paths whose presence is a security signal regardless of HTTP body match
_SENSITIVE_PATTERNS = {
    ".env", ".git/", ".svn/", ".DS_Store", ".htaccess", ".htpasswd",
    "phpinfo", "wp-config", "actuator/heapdump", "actuator/env",
    "config.php", "configuration.php", "backup.zip", "backup.sql",
    "db.sql", "dump.sql",
}


async def enumerate(
    base_url: str,
    *,
    session: Any | None = None,
    http: PencheffHTTPClient | None = None,
    wordlist: str | None = None,
    concurrency: int = 20,
    timeout: float = 8.0,
) -> tuple[list[str], list[Finding]]:
    """Probe a list of paths against ``base_url``.

    Returns ``(discovered_paths, findings)``. ``discovered_paths`` are the
    URL strings that returned a 2xx/3xx (excluding SPA catch-alls).
    ``findings`` are the security-relevant hits.
    """
    paths_path = Path(wordlist).expanduser() if wordlist else _DEFAULT_WORDLIST
    if not paths_path.exists():
        return [], []
    paths = [p.strip() for p in paths_path.read_text().splitlines() if p.strip() and not p.startswith("#")]

    own_http = http is None
    if own_http:
        # late import — avoid cycle
        from pencheff.core.http_client import PencheffHTTPClient as _Cli
        http = _Cli(session)

    discovered: list[str] = []
    findings: list[Finding] = []
    spa_sig = getattr(getattr(session, "target", None), "fallback_signature", None) if session else None

    sem = asyncio.Semaphore(concurrency)

    async def probe(path: str) -> None:
        url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
        async with sem:
            try:
                resp = await http.client.get(url, follow_redirects=False, timeout=timeout)
            except Exception:
                return
        status = resp.status_code
        body = resp.text or ""
        # SPA fallback: a known signature → not a real route
        if spa_sig and status == 200:
            try:
                if spa_sig.matches(body):
                    return
            except Exception:
                pass
        if status not in (200, 201, 202, 204, 301, 302, 401, 403):
            return
        # status ∈ {401,403} still indicates the path EXISTS
        discovered.append(url)

        sensitive = any(s in path.lower() for s in _SENSITIVE_PATTERNS)
        if sensitive and status in (200, 301, 302):
            findings.append(Finding(
                title=f"Sensitive Path Exposed: /{path}",
                severity=Severity.HIGH,
                category="exposure",
                owasp_category="A05",
                description=(
                    f"The path /{path} returned HTTP {status} — typically only "
                    "present on misconfigured or backup-leaking servers."
                ),
                remediation=(
                    "Remove the file from the web root, or block via web server "
                    "configuration (e.g. `location ~ /\\.git { deny all; }`)."
                ),
                endpoint=url,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                cvss_score=7.5,
                cwe_id="CWE-538",
                evidence=[Evidence(
                    request_method="GET",
                    request_url=url,
                    response_status=status,
                    response_body_snippet=body[:300],
                    description=f"Sensitive path returned HTTP {status}",
                )],
            ))
        elif status in (200, 301, 302) and any(
            kw in path.lower() for kw in ("admin", "actuator", "swagger", "graphql",
                                            "phpmyadmin", "adminer", "console", "debug")
        ):
            findings.append(Finding(
                title=f"Administrative / debug interface reachable: /{path}",
                severity=Severity.MEDIUM,
                category="exposure",
                owasp_category="A05",
                description=(
                    f"The path /{path} returned HTTP {status}. "
                    "Administrative or debug interfaces should not be public."
                ),
                remediation=(
                    "Restrict access by IP allow-list, place behind authenticated "
                    "VPN, or remove from production. Verify with `pencheff webhunt`."
                ),
                endpoint=url,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
                cvss_score=6.5,
                cwe_id="CWE-284",
                evidence=[Evidence(
                    request_method="GET",
                    request_url=url,
                    response_status=status,
                    description=f"Admin/debug path returned HTTP {status}",
                )],
            ))

    await asyncio.gather(*(probe(p) for p in paths))

    if own_http:
        try:
            await http.close()
        except Exception:
            pass

    return sorted(set(discovered)), findings
