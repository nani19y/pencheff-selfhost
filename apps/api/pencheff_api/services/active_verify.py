"""Active verification — probe each finding's endpoint and confirm whether
something of value can actually be extracted, suppressing the false positives.

Runs deterministically (no LLM) for every plan. Slots between the rule-based
SPA-404 pre-filter and the (Pro+) LLM classification step in the scan pipeline.

Outcomes per finding:

  * **confirmed**  — probe extracted concrete evidence of exploitability.
    The probe response is appended to ``Finding.evidence`` and
    ``recheck_status`` is set to ``"active_verify_confirmed"``. The
    ``verification_status`` is *deliberately* left as ``"unverified"`` so
    a human still sees it on the unverified queue and confirms — automated
    tools should not auto-promote findings to ``true_positive``.

  * **no_value**   — probe confirmed nothing exploitable comes back from
    the endpoint. The finding is suppressed with
    ``suppress_reason = "active_verification_no_value"`` and
    ``verification_status = "false_positive"``.

  * **inconclusive** — probe couldn't run (network error, timeout, missing
    endpoint/parameter, finding's category has no probe). The finding is
    left untouched.

Safety: all probes are read-only. The strongest action is a ``SLEEP(3)``
clause for time-based confirmation. No destructive payloads.
"""

from __future__ import annotations

import asyncio
import base64
import logging
import re
import time
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker

from ..db.models import Finding as DbFinding, Scan, Target
from .credentials import decrypt_credentials

log = logging.getLogger(__name__)

# Per-probe HTTP timeout (seconds). Generous because some probes need a
# baseline + SLEEP(3) round-trip.
_PROBE_TIMEOUT_S = 6.0
# Hard cap for the whole verification pass across all findings in a scan.
_TOTAL_BUDGET_S = 90.0
# Truncate response bodies before scanning / persisting.
_MAX_RESPONSE_BYTES = 64 * 1024
# Time-based payloads sleep for this many seconds; threshold for confirming
# the sleep actually executed.
_SLEEP_S = 3.0
_SLEEP_DELTA_THRESHOLD_S = 2.5

# ---------------------------------------------------------------- typing

ProbeVerdict = str  # "confirmed" | "no_value" | "inconclusive"
ProbeOutcome = tuple[ProbeVerdict, dict[str, Any] | str | None]
ProbeFn = Callable[[httpx.AsyncClient, DbFinding, str, dict[str, str]], Awaitable[ProbeOutcome]]

# ---------------------------------------------------------------- helpers


def _auth_headers_from_creds(creds: dict | None) -> dict[str, str]:
    """Build request headers from the decrypted target credentials.

    Mirrors ``CredentialSet.inject_into_headers`` in the plugin so probes
    speak the same auth as the original scan.
    """
    if not isinstance(creds, dict):
        return {}
    h: dict[str, str] = {}
    token = creds.get("token")
    username = creds.get("username")
    password = creds.get("password")
    if token:
        h["Authorization"] = f"Bearer {token}"
    elif username and password:
        raw = f"{username}:{password}"
        h["Authorization"] = "Basic " + base64.b64encode(raw.encode()).decode()
    if creds.get("api_key"):
        h["X-API-Key"] = creds["api_key"]
    if creds.get("cookie"):
        h["Cookie"] = creds["cookie"]
    for k, v in (creds.get("custom_headers") or {}).items():
        if isinstance(k, str) and isinstance(v, str):
            h[k] = v
    return h


def _set_param(url: str, param: str, value: str) -> str:
    """Replace or set a query parameter on a URL, preserving everything else."""
    parsed = urlparse(url)
    qs = parse_qsl(parsed.query, keep_blank_values=True)
    seen = False
    new_qs: list[tuple[str, str]] = []
    for k, v in qs:
        if k == param and not seen:
            new_qs.append((k, value))
            seen = True
        else:
            new_qs.append((k, v))
    if not seen:
        new_qs.append((param, value))
    return urlunparse(parsed._replace(query=urlencode(new_qs, doseq=True)))


def _truncate(text: str, n: int = 2000) -> str:
    return text if len(text) <= n else text[:n] + "…"


def _trunc_body(r: httpx.Response) -> str:
    body = r.text or ""
    return body if len(body) <= _MAX_RESPONSE_BYTES else body[:_MAX_RESPONSE_BYTES]


# Regexes for value-extraction markers ────────────────────────────────────────

# Database-error fragments that strongly indicate the endpoint is reflecting
# raw DB errors back into the response — i.e. SQL injection is exploitable.
_SQL_ERROR_RE = re.compile(
    r"(SQL syntax|mysql_fetch|MySqlClient\.|PostgreSQL.*ERROR|psql:|"
    r"\bORA-\d{4,5}\b|SQLSTATE|sqlite3?\.OperationalError|"
    r"Microsoft.*ODBC.*SQL Server|System\.Data\.SqlClient|"
    r"Warning.*\Wmysqli?_|Unclosed quotation mark|"
    r"unterminated quoted string)",
    re.IGNORECASE,
)

# Tokens commonly leaked in cloud-metadata SSRF / IMDS responses. (We don't
# probe IMDS directly here — too noisy — but if the original scanner already
# captured a body, these would have been caught upstream.)

# Markers that distinguish a real config / dotfile from a SPA fallback.
_DOTENV_RE = re.compile(
    r"^\s*[A-Z][A-Z0-9_]+\s*=\s*\S",  # KEY=value lines
    re.MULTILINE,
)
_GITCONFIG_RE = re.compile(
    r"\[(?:core|remote\s+\"|branch\s+\"|user)\b",
    re.IGNORECASE,
)
_HTACCESS_RE = re.compile(
    r"(?:\b(?:RewriteEngine|RewriteRule|Order\s+(?:allow|deny))\b|<Files\b)",
    re.IGNORECASE,
)
_SPA_FALLBACK_RE = re.compile(
    r"<!doctype html|<html|404|not\s+found|page\s+does\s+not\s+exist",
    re.IGNORECASE,
)


# ---------------------------------------------------------------- probes


async def _probe_sqli(
    client: httpx.AsyncClient,
    f: DbFinding,
    base_url: str,
    headers: dict[str, str],
) -> ProbeOutcome:
    """Confirm SQL injection with an error-based probe followed by a
    time-based probe if needed."""
    if not f.endpoint or not f.parameter:
        return ("inconclusive", None)

    # Error-based: stray quote should provoke a database error if the
    # endpoint is concatenating user input into a query.
    err_url = _set_param(f.endpoint, f.parameter, "pencheff'sqli")
    try:
        r = await client.get(err_url, headers=headers)
    except httpx.HTTPError:
        return ("inconclusive", None)
    body = _trunc_body(r)
    match = _SQL_ERROR_RE.search(body)
    if match:
        return ("confirmed", {
            "active_verify": True,
            "request_method": "GET",
            "request_url": err_url,
            "response_status": r.status_code,
            "response_body_snippet": _truncate(body),
            "description": (
                f"Active verification: SQL error fragment matched "
                f"({match.group(0)!r}) when injecting a stray quote into "
                f"parameter {f.parameter!r}. The endpoint is reflecting "
                f"database errors — strongly indicates exploitable SQLi."
            ),
        })

    # Time-based: SLEEP(N) and compare against a baseline GET.
    baseline_url = _set_param(f.endpoint, f.parameter, "1")
    sleep_payload = f"1' AND SLEEP({int(_SLEEP_S)})-- "
    sleep_url = _set_param(f.endpoint, f.parameter, sleep_payload)
    try:
        t0 = time.monotonic()
        await client.get(baseline_url, headers=headers)
        baseline_dt = time.monotonic() - t0
        t1 = time.monotonic()
        rs = await client.get(sleep_url, headers=headers)
        sleep_dt = time.monotonic() - t1
    except httpx.HTTPError:
        return ("inconclusive", None)

    if sleep_dt - baseline_dt >= _SLEEP_DELTA_THRESHOLD_S:
        return ("confirmed", {
            "active_verify": True,
            "request_method": "GET",
            "request_url": sleep_url,
            "response_status": rs.status_code,
            "response_body_snippet": _truncate(_trunc_body(rs)),
            "description": (
                f"Active verification: time-based SQLi confirmed. "
                f"Baseline {baseline_dt:.2f}s; SLEEP({int(_SLEEP_S)}) "
                f"{sleep_dt:.2f}s (delta {sleep_dt - baseline_dt:+.2f}s). "
                f"The database executed the injected SLEEP clause."
            ),
        })

    return ("no_value", (
        f"Probed {f.parameter!r} with a stray quote and a SLEEP({int(_SLEEP_S)}) "
        f"payload. No SQL error fragments in the response body, and the time "
        f"delta {sleep_dt - baseline_dt:+.2f}s is within network noise. The "
        f"endpoint does not appear to interpret the injected SQL."
    ))


async def _probe_cmdi(
    client: httpx.AsyncClient,
    f: DbFinding,
    base_url: str,
    headers: dict[str, str],
) -> ProbeOutcome:
    """Time-based OS command-injection confirmation."""
    if not f.endpoint or not f.parameter:
        return ("inconclusive", None)

    baseline_url = _set_param(f.endpoint, f.parameter, "x")
    payload = f"x;sleep {int(_SLEEP_S)};"
    sleep_url = _set_param(f.endpoint, f.parameter, payload)
    try:
        t0 = time.monotonic()
        await client.get(baseline_url, headers=headers)
        baseline_dt = time.monotonic() - t0
        t1 = time.monotonic()
        rs = await client.get(sleep_url, headers=headers)
        sleep_dt = time.monotonic() - t1
    except httpx.HTTPError:
        return ("inconclusive", None)

    if sleep_dt - baseline_dt >= _SLEEP_DELTA_THRESHOLD_S:
        return ("confirmed", {
            "active_verify": True,
            "request_method": "GET",
            "request_url": sleep_url,
            "response_status": rs.status_code,
            "response_body_snippet": _truncate(_trunc_body(rs)),
            "description": (
                f"Active verification: time-based command injection confirmed. "
                f"Baseline {baseline_dt:.2f}s; payload with `;sleep "
                f"{int(_SLEEP_S)};` {sleep_dt:.2f}s (delta "
                f"{sleep_dt - baseline_dt:+.2f}s). The shell executed the "
                f"injected sleep."
            ),
        })

    return ("no_value", (
        f"Probed {f.parameter!r} with `;sleep {int(_SLEEP_S)};` and the time "
        f"delta {sleep_dt - baseline_dt:+.2f}s is within noise. The endpoint "
        f"does not appear to pass user input to a shell."
    ))


async def _probe_ssti(
    client: httpx.AsyncClient,
    f: DbFinding,
    base_url: str,
    headers: dict[str, str],
) -> ProbeOutcome:
    """Server-side template injection: ``{{7*7}}`` should evaluate to ``49``."""
    if not f.endpoint or not f.parameter:
        return ("inconclusive", None)

    # Use a uniquely-shaped marker so a literal-reflected payload doesn't
    # accidentally match. ``49`` alone is too common; we also assert the
    # raw expression is *not* present (i.e. it actually got evaluated).
    payloads = ["{{7*7}}", "${7*7}", "<%= 7*7 %>"]
    for payload in payloads:
        url = _set_param(f.endpoint, f.parameter, payload)
        try:
            r = await client.get(url, headers=headers)
        except httpx.HTTPError:
            continue
        body = _trunc_body(r)
        if "49" in body and payload not in body:
            return ("confirmed", {
                "active_verify": True,
                "request_method": "GET",
                "request_url": url,
                "response_status": r.status_code,
                "response_body_snippet": _truncate(body),
                "description": (
                    f"Active verification: server-side template injection "
                    f"confirmed. Payload {payload!r} was evaluated to '49' "
                    f"in the response body (the literal expression is no "
                    f"longer present)."
                ),
            })

    return ("no_value", (
        f"Probed {f.parameter!r} with template-engine arithmetic payloads "
        f"({', '.join(payloads)}). None evaluated server-side; the parameter "
        f"is not reaching a template renderer."
    ))


async def _probe_open_redirect(
    client: httpx.AsyncClient,
    f: DbFinding,
    base_url: str,
    headers: dict[str, str],
) -> ProbeOutcome:
    """Confirm open redirect by checking the ``Location`` header points
    off-origin to attacker-controlled host."""
    if not f.endpoint or not f.parameter:
        return ("inconclusive", None)
    redirect_target = "https://example.com/pencheff-or-probe"
    url = _set_param(f.endpoint, f.parameter, redirect_target)
    try:
        # Don't follow — we want to see the Location header itself.
        r = await client.get(url, headers=headers)
    except httpx.HTTPError:
        return ("inconclusive", None)
    if 300 <= r.status_code < 400:
        loc = r.headers.get("location") or r.headers.get("Location") or ""
        try:
            host = urlparse(loc).netloc.lower()
        except Exception:
            host = ""
        if host == "example.com":
            return ("confirmed", {
                "active_verify": True,
                "request_method": "GET",
                "request_url": url,
                "response_status": r.status_code,
                "response_headers": {"location": loc},
                "description": (
                    f"Active verification: open redirect confirmed. "
                    f"Parameter {f.parameter!r} controls the Location "
                    f"header, which now points to {loc!r} — an "
                    f"attacker-supplied host."
                ),
            })
    return ("no_value", (
        f"Probed {f.parameter!r} with redirect_target={redirect_target!r}. "
        f"The endpoint did not return a 3xx redirect to the attacker-supplied "
        f"host (status {r.status_code}). Parameter does not control the "
        f"redirect target."
    ))


async def _probe_xss(
    client: httpx.AsyncClient,
    f: DbFinding,
    base_url: str,
    headers: dict[str, str],
) -> ProbeOutcome:
    """Reflected-XSS check: a unique token containing HTML metacharacters
    should appear unescaped in the response body."""
    if not f.endpoint or not f.parameter:
        return ("inconclusive", None)
    token = f"pencheff{int(time.time())}"
    payload = f"<{token}>"
    url = _set_param(f.endpoint, f.parameter, payload)
    try:
        r = await client.get(url, headers=headers)
    except httpx.HTTPError:
        return ("inconclusive", None)
    body = _trunc_body(r)
    if payload in body:
        return ("confirmed", {
            "active_verify": True,
            "request_method": "GET",
            "request_url": url,
            "response_status": r.status_code,
            "response_body_snippet": _truncate(body),
            "description": (
                f"Active verification: reflected XSS confirmed. The literal "
                f"payload {payload!r} appears unescaped in the response body. "
                f"Angle brackets are not being HTML-encoded — an attacker "
                f"can inject script tags through {f.parameter!r}."
            ),
        })
    # If the payload is reflected but escaped, that's safe — call it out.
    if token in body:
        return ("no_value", (
            f"The token {token!r} was reflected, but the angle brackets in "
            f"{payload!r} were HTML-encoded (or stripped) in the response. "
            f"The parameter is reflected but not exploitable as XSS."
        ))
    return ("no_value", (
        f"Probed {f.parameter!r} with marker payload {payload!r}. The token "
        f"was not reflected in the response body — the parameter is not "
        f"echoed into the HTML output."
    ))


async def _probe_cors(
    client: httpx.AsyncClient,
    f: DbFinding,
    base_url: str,
    headers: dict[str, str],
) -> ProbeOutcome:
    """Confirm exploitable CORS misconfiguration: an attacker origin must be
    allowed *and* credentials must flow."""
    if not f.endpoint:
        return ("inconclusive", None)
    attacker = "https://attacker.example"
    probe_headers = dict(headers)
    probe_headers["Origin"] = attacker
    try:
        r = await client.get(f.endpoint, headers=probe_headers)
    except httpx.HTTPError:
        return ("inconclusive", None)
    aco = r.headers.get("access-control-allow-origin", "")
    acc = r.headers.get("access-control-allow-credentials", "").lower()
    if (aco == attacker or aco == "*") and acc == "true":
        return ("confirmed", {
            "active_verify": True,
            "request_method": "GET",
            "request_url": f.endpoint,
            "response_status": r.status_code,
            "response_headers": {
                "access-control-allow-origin": aco,
                "access-control-allow-credentials": acc,
            },
            "description": (
                f"Active verification: exploitable CORS misconfiguration "
                f"confirmed. Endpoint reflects attacker origin "
                f"({aco!r}) AND allows credentials — an attacker page can "
                f"read authenticated responses cross-origin."
            ),
        })
    return ("no_value", (
        f"Probed CORS with Origin: {attacker!r}. ACAO={aco!r}, "
        f"ACAC={acc!r}. The endpoint does not allow attacker-origin "
        f"credentialed reads — not exploitable."
    ))


async def _probe_sensitive_file(
    client: httpx.AsyncClient,
    f: DbFinding,
    base_url: str,
    headers: dict[str, str],
) -> ProbeOutcome:
    """Confirm a sensitive-file finding actually serves real file content
    (not a SPA index.html or generic 404 served with a 200 status)."""
    endpoint = f.endpoint
    if not endpoint:
        return ("inconclusive", None)
    try:
        r = await client.get(endpoint, headers=headers)
    except httpx.HTTPError:
        return ("inconclusive", None)
    body = _trunc_body(r)
    title_lower = (f.title or "").lower()
    matched = None
    if ".env" in endpoint.lower() or ".env" in title_lower:
        if _DOTENV_RE.search(body):
            matched = "dotenv KEY=VALUE pattern"
    if matched is None and (".git" in endpoint.lower() or ".git" in title_lower):
        if _GITCONFIG_RE.search(body):
            matched = "git config section header"
    if matched is None and ".htaccess" in endpoint.lower():
        if _HTACCESS_RE.search(body):
            matched = "Apache RewriteRule / Files directive"

    if matched:
        return ("confirmed", {
            "active_verify": True,
            "request_method": "GET",
            "request_url": endpoint,
            "response_status": r.status_code,
            "response_body_snippet": _truncate(body),
            "description": (
                f"Active verification: sensitive-file exposure confirmed. "
                f"Response body matches {matched} — real file content is "
                f"being served at {endpoint!r}."
            ),
        })

    # No category-specific marker matched. If the body looks like a SPA
    # fallback or generic 404, suppress confidently.
    if _SPA_FALLBACK_RE.search(body) or r.status_code >= 400:
        return ("no_value", (
            f"GET {endpoint} returned status {r.status_code} with a "
            f"SPA-fallback / 404-style body. No sensitive file content was "
            f"served — the original 'accessible path' finding is the "
            f"single-page-app HTTP-200 trap, not a real exposure."
        ))
    return ("inconclusive", None)


# Probe registry ────────────────────────────────────────────────────────────
# Order matters — the first matching entry wins. Each entry is
# ``(matcher, probe_fn)`` where ``matcher(finding) -> bool``.

_PROBES: list[tuple[Callable[[DbFinding], bool], ProbeFn]] = [
    (
        lambda f: f.category == "injection" and "SQL Injection" in (f.title or ""),
        _probe_sqli,
    ),
    (
        lambda f: f.category == "injection"
        and "OS Command Injection" in (f.title or ""),
        _probe_cmdi,
    ),
    (
        lambda f: f.category == "injection"
        and "Server-Side Template Injection" in (f.title or ""),
        _probe_ssti,
    ),
    (
        lambda f: f.category == "open_redirect"
        or "Open Redirect" in (f.title or ""),
        _probe_open_redirect,
    ),
    (lambda f: f.category == "xss", _probe_xss),
    (
        lambda f: f.category == "misconfiguration"
        and "CORS" in (f.title or "").upper(),
        _probe_cors,
    ),
    (
        lambda f: any(
            tok in (f.endpoint or "").lower() or tok in (f.title or "").lower()
            for tok in (".env", ".git", ".htaccess")
        ),
        _probe_sensitive_file,
    ),
]


def _find_probe(f: DbFinding) -> ProbeFn | None:
    for matcher, fn in _PROBES:
        try:
            if matcher(f):
                return fn
        except Exception:  # never let a matcher crash the scan
            continue
    return None


# ---------------------------------------------------------------- entrypoint


async def active_verify(
    *,
    scan_id: str,
    db_session_factory: async_sessionmaker,
) -> None:
    """Probe each unsuppressed finding and either suppress as a false positive
    or append confirming evidence. Runs deterministically; no LLM."""
    started = time.monotonic()

    # One-shot snapshot read so we don't hold a session across probes.
    async with db_session_factory() as db:
        scan = (
            await db.execute(select(Scan).where(Scan.id == scan_id))
        ).scalar_one_or_none()
        if scan is None:
            return
        target = (
            await db.execute(select(Target).where(Target.id == scan.target_id))
        ).scalar_one_or_none()
        if target is None:
            return
        rows: list[DbFinding] = (
            await db.execute(
                select(DbFinding).where(
                    DbFinding.scan_id == scan_id,
                    DbFinding.suppressed.is_(False),
                )
            )
        ).scalars().all()
        creds = decrypt_credentials(target.credentials_encrypted)
        base_url = target.base_url
        finding_ids = [(r.id, r.category, r.title, r.endpoint, r.parameter) for r in rows]

    if not finding_ids:
        return

    auth_headers = _auth_headers_from_creds(creds)
    timeout = httpx.Timeout(_PROBE_TIMEOUT_S, connect=3.0)

    confirmed = 0
    suppressed = 0
    skipped = 0
    inconclusive = 0

    async with httpx.AsyncClient(
        timeout=timeout,
        follow_redirects=False,
        verify=False,  # targets are user-controlled; cert validation is out of scope here
        headers={"User-Agent": "Pencheff-ActiveVerify/1.0"},
    ) as client:
        for fid, _cat, _title, _endpoint, _param in finding_ids:
            if time.monotonic() - started > _TOTAL_BUDGET_S:
                log.info(
                    "active_verify: budget exhausted after %d findings",
                    confirmed + suppressed + inconclusive,
                )
                break
            # Re-read the row (in a fresh session) so we have a hydrated object.
            async with db_session_factory() as db:
                f = (
                    await db.execute(select(DbFinding).where(DbFinding.id == fid))
                ).scalar_one_or_none()
                if f is None or f.suppressed:
                    continue
                # Detach (we only need read-only attributes for the probe).
                f_snapshot = f
                db.expunge(f_snapshot)

            probe = _find_probe(f_snapshot)
            if probe is None:
                skipped += 1
                continue

            try:
                outcome = await probe(client, f_snapshot, base_url, auth_headers)
            except (httpx.HTTPError, asyncio.TimeoutError) as exc:
                log.debug("active_verify probe error on %s: %s", fid, exc)
                outcome = ("inconclusive", None)
            except Exception as exc:  # noqa: BLE001 — never let a probe break a scan
                log.exception("active_verify probe crashed on %s: %s", fid, exc)
                outcome = ("inconclusive", None)

            verdict, payload = outcome

            if verdict == "no_value":
                async with db_session_factory() as db:
                    fresh = (
                        await db.execute(
                            select(DbFinding).where(DbFinding.id == fid)
                        )
                    ).scalar_one()
                    fresh.suppressed = True
                    fresh.suppress_reason = "active_verification_no_value"
                    fresh.suppress_notes = (
                        str(payload) if payload else "active probe found no exploitable signal"
                    )[:2000]
                    fresh.verification_status = "false_positive"
                    fresh.last_rechecked_at = datetime.now(timezone.utc)
                    fresh.recheck_status = "active_verify_false_positive"
                    await db.commit()
                suppressed += 1

            elif verdict == "confirmed" and isinstance(payload, dict):
                async with db_session_factory() as db:
                    fresh = (
                        await db.execute(
                            select(DbFinding).where(DbFinding.id == fid)
                        )
                    ).scalar_one()
                    existing = list(fresh.evidence or [])
                    existing.append(payload)
                    fresh.evidence = existing
                    fresh.last_rechecked_at = datetime.now(timezone.utc)
                    fresh.recheck_status = "active_verify_confirmed"
                    # Note: verification_status intentionally left untouched
                    # ("unverified") so a human still confirms.
                    await db.commit()
                confirmed += 1

            else:
                inconclusive += 1

    log.info(
        "active_verify: confirmed=%d suppressed=%d inconclusive=%d skipped=%d in %.1fs",
        confirmed,
        suppressed,
        inconclusive,
        skipped,
        time.monotonic() - started,
    )
