"""First-party web server exposure scanner.

This is a non-destructive web exposure assessor for authorized targets. It
checks server metadata, security headers, cookies, HTTP methods, common
exposed files, backup artifacts, default pages, directory listings, and
lightweight disclosure patterns. It does not exploit vulnerabilities or brute
force paths.
"""

from __future__ import annotations

import asyncio
import csv
import html
import json
import re
import secrets
import sys
import time
from dataclasses import asdict, dataclass, field
from io import StringIO
from pathlib import Path
from typing import Any, Iterable
import shutil
from urllib.parse import quote, urljoin, urlparse

import httpx

from pencheff.core.spa_detector import _body_hash as _spa_body_hash


SECURITY_HEADERS = {
    "strict-transport-security": ("medium", "Missing HSTS header on HTTPS response."),
    "content-security-policy": ("medium", "Missing Content-Security-Policy header."),
    "x-content-type-options": ("low", "Missing X-Content-Type-Options header."),
    "x-frame-options": ("medium", "Missing X-Frame-Options header."),
    "referrer-policy": ("low", "Missing Referrer-Policy header."),
    "permissions-policy": ("low", "Missing Permissions-Policy header."),
}

INFORMATION_HEADERS = {
    "server": "Server header exposes web server details.",
    "x-powered-by": "X-Powered-By exposes framework/runtime details.",
    "x-aspnet-version": "ASP.NET version header exposes framework details.",
    "x-generator": "Generator header exposes application details.",
}

DEFAULT_CHECK_DB = Path(__file__).with_name("webscan_checks.json")
USER_CHECK_DB = Path.home() / ".pencheff" / "webscan_checks.json"

INTERESTING_PATHS = {
    "quick": [
        "/robots.txt", "/sitemap.xml", "/.well-known/security.txt",
        "/server-status", "/phpinfo.php", "/.env", "/.git/config",
    ],
    "standard": [
        "/admin/", "/backup/", "/backups/", "/old/", "/test/", "/dev/",
        "/.svn/entries", "/.hg/hgrc", "/config.php.bak", "/web.config",
        "/WEB-INF/web.xml", "/crossdomain.xml", "/clientaccesspolicy.xml",
        "/actuator", "/actuator/env", "/actuator/health",
        "/wp-config.php.bak", "/composer.json", "/package.json",
    ],
    "deep": [
        "/debug/", "/console/", "/manager/html", "/jmx-console/",
        "/login.action", "/solr/admin/", "/elasticsearch/", "/_cat/indices",
        "/.DS_Store", "/id_rsa", "/id_rsa.pub", "/database.sql",
        "/dump.sql", "/backup.zip", "/backup.tar.gz", "/www.zip",
        "/appsettings.json", "/appsettings.Production.json",
        "/swagger.json", "/swagger/v1/swagger.json", "/openapi.json",
    ],
}

DANGEROUS_METHODS = {"PUT", "DELETE", "TRACE", "CONNECT", "PATCH"}

DISCLOSURE_PATTERNS = [
    ("directory_listing", re.compile(r"<title>Index of /|Directory listing for", re.I), "Directory listing appears enabled."),
    ("phpinfo", re.compile(r"<title>phpinfo\(\)|PHP Version", re.I), "phpinfo-style diagnostic page exposed."),
    ("stack_trace", re.compile(r"Traceback \(most recent call last\)|Exception Details|stack trace", re.I), "Application stack trace disclosed."),
    ("spring_actuator", re.compile(r'"(?:activeProfiles|propertySources|_links)"', re.I), "Spring actuator data exposed."),
    ("git_config", re.compile(r"\[core\]\s+repositoryformatversion", re.I), "Git configuration exposed."),
    ("env_file", re.compile(r"(?m)^(?:APP_KEY|SECRET_KEY|DATABASE_URL|AWS_ACCESS_KEY_ID)=", re.I), "Environment-style secrets file exposed."),
    ("backup_artifact", re.compile(r"(?:PK\x03\x04|-- MySQL dump|PostgreSQL database dump)", re.I), "Backup or dump artifact may be exposed."),
]


@dataclass(slots=True)
class WebFinding:
    url: str
    check: str
    severity: str
    title: str
    evidence: str
    status_code: int | None = None
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    cves: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)


@dataclass(slots=True)
class WebScanResult:
    target: str
    profile: str
    findings: list[WebFinding]
    requests_sent: int
    elapsed_sec: float
    evidence_path: str | None = None


@dataclass(slots=True)
class WebCheck:
    id: str
    path: str
    match: str
    title: str
    severity: str = "info"
    check: str = "check_db"
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    cves: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    profiles: list[str] = field(default_factory=list)


async def scan(
    target: str,
    *,
    profile: str = "standard",
    timeout: float = 8.0,
    verify_ssl: bool = False,
    headers: dict[str, str] | None = None,
    cookie: str | None = None,
    proxy: str | None = None,
    concurrency: int = 10,
    extra_paths: list[str] | None = None,
    traffic_log: str | None = None,
    check_db: list[str] | None = None,
    tags: list[str] | None = None,
    tuning: list[str] | None = None,
    auth_profile: str | None = None,
    suppressions: list[str] | None = None,
    request_encoding: str = "none",
    delay: float = 0.0,
) -> WebScanResult:
    started = time.monotonic()
    base = _normalize_target(target)
    auth_headers, auth_cookie = load_auth_profile(auth_profile)
    request_headers = {**auth_headers, **dict(headers or {})}
    request_headers.setdefault("User-Agent", "Mozilla/5.0 (compatible; PencheffWebScan/0.1)")
    if cookie or auth_cookie:
        cookie = cookie or auth_cookie
        request_headers["Cookie"] = cookie

    client_kwargs: dict[str, Any] = {
        "timeout": httpx.Timeout(timeout),
        "verify": verify_ssl,
        "follow_redirects": True,
        "headers": request_headers,
    }
    if proxy:
        client_kwargs["proxy"] = proxy

    findings: list[WebFinding] = []
    requests_sent = 0
    checks = load_checks(check_db, profile=profile, tags=tags, tuning=tuning)
    suppression_rules = load_suppressions(suppressions)

    async with httpx.AsyncClient(**client_kwargs) as client:
        root = await _safe_request(client, "GET", base, traffic_log, delay=delay)
        requests_sent += 1
        if root is None:
            # Connectivity miss is a *scan status*, not a vulnerability.
            # Skip emitting a Finding row — the scanner just records
            # nothing for this host. Surfaces in the scan log via the
            # caller's own progress reporting.
            return WebScanResult(base, profile, findings, requests_sent, time.monotonic() - started, traffic_log)

        # Probe two random non-existent paths to establish a SPA-fallback
        # signature. Single-page apps return 200 with index.html for every
        # unknown path, which would otherwise fire "Interesting Path
        # Exposed" findings for every entry in INTERESTING_PATHS. Without
        # this, the path-existence check below cannot distinguish a real
        # 200 from a catch-all 200.
        spa_sig, probe_requests = await _probe_spa_fallback(client, base, traffic_log, delay=delay)
        requests_sent += probe_requests

        selected_tuning = set(tuning or [])
        if not selected_tuning or "headers" in selected_tuning:
            findings.extend(_header_findings(base, root))
        if not selected_tuning or "disclosure" in selected_tuning:
            findings.extend(_body_findings(str(root.url), root))
        if not selected_tuning or "versions" in selected_tuning:
            findings.extend(_version_findings(str(root.url), root))

        if not selected_tuning or "methods" in selected_tuning:
            method_findings, method_requests = await _method_checks(client, base, traffic_log, delay=delay)
            findings.extend(method_findings)
            requests_sent += method_requests

        paths = _paths_for_profile(profile, extra_paths)
        paths.extend(check.path for check in checks)
        paths = list(dict.fromkeys(paths))
        sem = asyncio.Semaphore(max(1, concurrency))

        async def check_path(path: str) -> tuple[int, list[WebFinding]]:
            async with sem:
                encoded_path = _encode_path(path, request_encoding)
                url = urljoin(base.rstrip("/") + "/", encoded_path.lstrip("/"))
                resp = await _safe_request(client, "GET", url, traffic_log, delay=delay)
                if resp is None:
                    return 1, []
                # If the response is indistinguishable from the SPA
                # catch-all baseline, the path doesn't really exist —
                # skip both interesting-path emission and check-db
                # body matching to avoid false positives.
                if _matches_spa_fallback(resp, spa_sig):
                    return 1, []
                path_findings = _check_db_findings(path, resp, checks)
                if not selected_tuning or selected_tuning.intersection({"files", "backup", "admin", "disclosure"}):
                    path_findings = _path_findings(path, resp) + path_findings
                return 1, path_findings

        for sent, path_findings in await asyncio.gather(*(check_path(path) for path in paths)):
            requests_sent += sent
            findings.extend(path_findings)

    findings = _apply_suppressions(_dedupe_findings(findings), suppression_rules)
    return WebScanResult(base, profile, findings, requests_sent, time.monotonic() - started, traffic_log)


@dataclass(frozen=True)
class _SpaSig:
    status: int
    body_hash: str | None
    body_length: int


async def _probe_spa_fallback(
    client: httpx.AsyncClient,
    base: str,
    traffic_log: str | None,
    delay: float = 0.0,
) -> tuple[_SpaSig | None, int]:
    """Establish a fingerprint for what a non-existent path looks like.

    Probes two random paths that no real router would have routes for. If
    both responses agree (status, body hash, body length), the agreed
    signature is returned and used to suppress false-positive findings on
    SPA targets that serve index.html for unknown paths. Returns
    ``(None, n)`` when probes diverge or the network fails — preserving
    historical scanner behavior.
    """
    probes: list[_SpaSig] = []
    requests = 0
    for _ in range(2):
        probe_path = f"_pencheff_probe_{secrets.token_hex(12)}"
        probe_url = urljoin(base.rstrip("/") + "/", probe_path)
        pr = await _safe_request(client, "GET", probe_url, traffic_log, delay=delay)
        requests += 1
        if pr is None:
            continue
        body = pr.text or ""
        probes.append(_SpaSig(
            status=pr.status_code,
            body_hash=_spa_body_hash(body) if body else None,
            body_length=len(body),
        ))
    if len(probes) < 2:
        return None, requests
    a, b = probes[0], probes[1]
    if a.status != b.status:
        return None, requests
    body_match = a.body_hash == b.body_hash
    length_close = (
        a.body_length == b.body_length
        or abs(a.body_length - b.body_length)
        <= max(1, int(0.01 * max(a.body_length, b.body_length)))
    )
    if not (body_match and length_close):
        return None, requests
    return a, requests


def _matches_spa_fallback(resp: httpx.Response, sig: _SpaSig | None) -> bool:
    if sig is None:
        return False
    if resp.status_code != sig.status:
        return False
    body = resp.text or ""
    if not body and sig.body_hash is None:
        return True
    if not body or sig.body_hash is None:
        return False
    return _spa_body_hash(body) == sig.body_hash


async def _safe_request(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    traffic_log: str | None,
    delay: float = 0.0,
) -> httpx.Response | None:
    if delay > 0:
        await asyncio.sleep(delay)
    try:
        resp = await client.request(method, url)
        _write_traffic(traffic_log, method, url, resp)
        return resp
    except httpx.HTTPError:
        return None


async def _method_checks(
    client: httpx.AsyncClient,
    base: str,
    traffic_log: str | None,
    delay: float = 0.0,
) -> tuple[list[WebFinding], int]:
    findings: list[WebFinding] = []
    requests_sent = 0
    options = await _safe_request(client, "OPTIONS", base, traffic_log, delay=delay)
    requests_sent += 1
    if options is not None:
        allow = options.headers.get("allow", "")
        public = options.headers.get("public", "")
        methods = _parse_methods(allow or public)
        dangerous = sorted(methods & DANGEROUS_METHODS)
        if dangerous:
            findings.append(WebFinding(
                url=base,
                check="http_methods",
                severity="medium",
                title=f"Potentially Dangerous HTTP Methods Advertised: {', '.join(dangerous)}",
                evidence=f"Allow/Public header: {allow or public}",
                status_code=options.status_code,
                remediation="Disable methods that are not required by the application.",
            ))

    trace = await _safe_request(client, "TRACE", base, traffic_log, delay=delay)
    requests_sent += 1
    if trace is not None and trace.status_code < 400 and "TRACE" in trace.text[:1000].upper():
        findings.append(WebFinding(
            url=base,
            check="trace",
            severity="medium",
            title="HTTP TRACE Method Enabled",
            evidence="TRACE request was accepted and appeared to reflect request content.",
            status_code=trace.status_code,
            remediation="Disable TRACE at the web server or reverse proxy.",
        ))
    return findings, requests_sent


def _header_findings(url: str, resp: httpx.Response) -> list[WebFinding]:
    # Missing-security-header checks and CSP weakness analysis are handled
    # by modules/web/headers.py:SecurityHeadersModule, which is invoked from
    # the same scan_infrastructure orchestrator. We only emit
    # version-disclosure header findings here to avoid duplicates.
    #
    # Managed-infrastructure signatures (CDN/PaaS/load-balancer) cannot
    # be stripped by the operator — reporting them is true-positive but
    # accepted-risk noise. Skip emission entirely for those values;
    # modules/recon/tech_fingerprint.py already records and pre-suppresses
    # them with full reasoning.
    UNAVOIDABLE_SIGNATURES = (
        "amazons3", "amazonec2", "cloudfront", "cloudflare",
        "akamai", "fastly", "google frontend", "gws",
        "vercel", "netlify", "nginx", "apache",
    )
    headers = {k.lower(): v for k, v in resp.headers.items()}
    findings: list[WebFinding] = []
    for header, evidence in INFORMATION_HEADERS.items():
        value = headers.get(header)
        if not value:
            continue
        # Skip placeholder / non-informative values that don't actually
        # disclose a technology — e.g. servers that send literal
        # ``Server: server`` or ``Server: -``. Reporting them as
        # technology disclosure is misleading.
        stripped = value.strip().strip("-").strip()
        if not stripped or stripped.lower() == header.lower():
            continue
        value_lower = value.lower()
        if any(sig in value_lower for sig in UNAVOIDABLE_SIGNATURES):
            continue
        findings.append(WebFinding(
            url=str(resp.url),
            check="fingerprint",
            severity="info",
            title=f"Informational Header Exposed: {header}",
            evidence=f"{header}: {value[:160]}",
            status_code=resp.status_code,
            remediation="Remove or minimize version-disclosing response headers where feasible.",
        ))
    return findings


def _body_findings(url: str, resp: httpx.Response) -> list[WebFinding]:
    findings: list[WebFinding] = []
    body = resp.text[:50000]
    generator = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', body, re.I)
    if generator:
        findings.append(WebFinding(
            url=url,
            check="fingerprint",
            severity="info",
            title="Generator Meta Tag Exposed",
            evidence=f"generator: {generator.group(1)[:160]}",
            status_code=resp.status_code,
            remediation="Remove generator meta tags if version disclosure is not needed.",
        ))
    for name, pattern, evidence in DISCLOSURE_PATTERNS:
        if pattern.search(body):
            findings.append(WebFinding(
                url=url,
                check=name,
                severity=_severity_for_pattern(name),
                title=_title_for_pattern(name),
                evidence=evidence,
                status_code=resp.status_code,
                remediation=_remediation_for_pattern(name),
            ))
    return findings


def _path_findings(path: str, resp: httpx.Response) -> list[WebFinding]:
    if resp.status_code in {404, 410}:
        return []
    # 401/403 means the path is properly access-controlled. That's the
    # *correct* server behaviour, not a vulnerability — emitting a
    # finding here just adds noise and confuses operators (the title
    # literally said "Protected" while still firing as a finding).
    # Same reasoning for redirects to a login page.
    if resp.status_code in {401, 403}:
        return []
    if resp.status_code >= 400:
        return []
    if resp.history and _interesting_path(path):
        final_path = (urlparse(str(resp.url)).path or "/").rstrip("/")
        requested_path = path.rstrip("/")
        if final_path != requested_path:
            # Auth-redirected to a different path — same story as a
            # 401/403: the path is gated, not exposed. Don't emit.
            return []

    findings = _body_findings(str(resp.url), resp)
    if _interesting_path(path):
        severity = "high" if path in {"/.env", "/.git/config", "/database.sql", "/dump.sql"} else "medium"
        findings.append(WebFinding(
            url=str(resp.url),
            check="interesting_path",
            severity=severity,
            title=f"Interesting Path Exposed: {path}",
            evidence=f"Returned HTTP {resp.status_code} with {len(resp.content)} bytes.",
            status_code=resp.status_code,
            remediation="Remove sensitive/default files or restrict access at the server/proxy layer.",
        ))
    return findings


def _check_db_findings(path: str, resp: httpx.Response, checks: list[WebCheck]) -> list[WebFinding]:
    findings: list[WebFinding] = []
    for check in checks:
        if check.path != path or not _match_expression(check.match, resp):
            continue
        findings.append(WebFinding(
            url=str(resp.url),
            check=check.check,
            severity=check.severity,
            title=check.title,
            evidence=f"Check {check.id} matched: {check.match}",
            status_code=resp.status_code,
            remediation=check.remediation,
            references=check.references or [],
            cves=check.cves or [],
            tags=check.tags or [],
        ))
    return findings


def _match_expression(expr: str, resp: httpx.Response) -> bool:
    parts = [part.strip() for part in expr.split("&&") if part.strip()]
    return all(_match_token(part, resp) for part in parts)


def _match_token(token: str, resp: httpx.Response) -> bool:
    negate = token.startswith("!")
    if negate:
        token = token[1:]
    result = _match_positive_token(token, resp)
    return not result if negate else result


def _match_positive_token(token: str, resp: httpx.Response) -> bool:
    if ":" not in token:
        raise ValueError(f"invalid matcher {token!r}; expected TYPE:value")
    kind, value = token.split(":", 1)
    kind = kind.upper()
    headers = {k.lower(): v for k, v in resp.headers.items()}
    body = resp.text[:100000]
    if kind == "CODE":
        allowed = {int(part.strip()) for part in value.split("|") if part.strip().isdigit()}
        return resp.status_code in allowed
    if kind == "BODY":
        return value.lower() in body.lower()
    if kind == "BODY_REGEX":
        return re.search(value, body, re.I) is not None
    if kind == "HEADER":
        name, expected = _split_name_value(value)
        actual = headers.get(name.lower())
        return actual is not None and (expected is None or expected.lower() in actual.lower())
    if kind == "COOKIE":
        cookies = resp.headers.get_list("set-cookie") if hasattr(resp.headers, "get_list") else []
        return any(value.lower() in raw.lower() for raw in cookies)
    if kind == "CONTENT_TYPE":
        return value.lower() in headers.get("content-type", "").lower()
    if kind == "SIZE_GT":
        return len(resp.content) > int(value)
    if kind == "SIZE_LT":
        return len(resp.content) < int(value)
    raise ValueError(f"unknown matcher kind {kind!r}")


def _split_name_value(value: str) -> tuple[str, str | None]:
    if "=" not in value:
        return value.strip(), None
    name, expected = value.split("=", 1)
    return name.strip(), expected.strip()


def _version_findings(url: str, resp: httpx.Response) -> list[WebFinding]:
    haystack = "\n".join([
        resp.headers.get("server", ""),
        resp.headers.get("x-powered-by", ""),
        resp.text[:20000],
    ])
    checks = [
        (r"Apache/2\.4\.(?:[0-9]|[1-2][0-9])\b", "Potentially Outdated Apache Version Exposed", "high", ["CVE-2017-15715", "CVE-2019-0211"], "Upgrade Apache HTTP Server and avoid exposing exact version banners."),
        (r"nginx/1\.(?:[0-9]|1[0-6])\b", "Potentially Outdated nginx Version Exposed", "medium", ["CVE-2017-7529"], "Upgrade nginx and minimize version disclosure."),
        (r"PHP/5\.|PHP/7\.[0-3]\b", "End-of-Life PHP Version Exposed", "high", [], "Upgrade PHP to a supported release and remove X-Powered-By exposure."),
        (r"WordPress\s+(?:[1-5]\.|6\.0|6\.1|6\.2)\b", "Potentially Outdated WordPress Version Exposed", "medium", [], "Update WordPress core, plugins, and themes."),
        (r"Apache-Coyote/1\.1|Tomcat/(?:5|6|7|8\.)", "Potentially Outdated Tomcat Version Exposed", "high", ["CVE-2017-12615"], "Upgrade Tomcat and restrict management interfaces."),
        (r"Jetty\((?:6|7|8|9\.)", "Potentially Outdated Jetty Version Exposed", "medium", [], "Upgrade Jetty and reduce version disclosure."),
    ]
    findings: list[WebFinding] = []
    for pattern, title, severity, cves, remediation in checks:
        match = re.search(pattern, haystack, re.I)
        if not match:
            continue
        findings.append(WebFinding(
            url=url,
            check="version_fingerprint",
            severity=severity,
            title=title,
            evidence=f"Matched exposed version string: {match.group(0)}",
            status_code=resp.status_code,
            remediation=remediation,
            references=["https://www.cve.org/"],
            cves=cves,
            tags=["fingerprint", "version"],
        ))
    return findings


def _parse_methods(value: str) -> set[str]:
    return {part.strip().upper() for part in value.split(",") if part.strip()}


def _paths_for_profile(profile: str, extra_paths: list[str] | None) -> list[str]:
    paths = list(INTERESTING_PATHS["quick"])
    if profile in {"standard", "deep"}:
        paths.extend(INTERESTING_PATHS["standard"])
    if profile == "deep":
        paths.extend(INTERESTING_PATHS["deep"])
    paths.extend(extra_paths or [])
    return list(dict.fromkeys(paths))


def _interesting_path(path: str) -> bool:
    return path in {p for values in INTERESTING_PATHS.values() for p in values}


def _severity_for_pattern(name: str) -> str:
    return {
        "git_config": "high",
        "env_file": "critical",
        "backup_artifact": "high",
        "phpinfo": "medium",
        "spring_actuator": "high",
        "stack_trace": "medium",
        "directory_listing": "medium",
    }.get(name, "low")


def _title_for_pattern(name: str) -> str:
    return {
        "git_config": "Git Configuration Exposed",
        "env_file": "Environment Secrets File Exposed",
        "backup_artifact": "Backup or Database Dump Exposed",
        "phpinfo": "Diagnostic phpinfo Page Exposed",
        "spring_actuator": "Spring Actuator Data Exposed",
        "stack_trace": "Application Stack Trace Disclosed",
        "directory_listing": "Directory Listing Enabled",
    }.get(name, "Information Disclosure")


def _remediation_for_pattern(name: str) -> str:
    return {
        "directory_listing": "Disable directory indexing.",
        "phpinfo": "Remove diagnostic pages from production.",
        "stack_trace": "Disable verbose errors in production.",
        "spring_actuator": "Restrict actuator endpoints and expose only required health data.",
        "git_config": "Block access to VCS metadata and remove deployed .git directories.",
        "env_file": "Remove environment files from web root and rotate exposed secrets.",
        "backup_artifact": "Remove backups/dumps from web root and rotate exposed credentials.",
    }.get(name, "Remove or restrict the exposed resource.")


def _normalize_target(target: str) -> str:
    parsed = urlparse(target)
    if not parsed.scheme:
        return f"https://{target.rstrip('/')}/"
    return target


def _encode_path(path: str, mode: str) -> str:
    if mode == "none":
        return path
    if mode == "url":
        return quote(path, safe="/")
    if mode == "double-url":
        return quote(quote(path, safe="/"), safe="/")
    raise ValueError("request encoding must be one of: none, url, double-url")


def _dedupe_findings(findings: list[WebFinding]) -> list[WebFinding]:
    seen: set[str] = set()
    out: list[WebFinding] = []
    for finding in findings:
        key = f"{finding.url}|{finding.check}|{finding.title}"
        if key in seen:
            continue
        seen.add(key)
        out.append(finding)
    return out


def _apply_suppressions(findings: list[WebFinding], rules: list[dict[str, str]]) -> list[WebFinding]:
    if not rules:
        return findings
    return [finding for finding in findings if not any(_suppression_matches(rule, finding) for rule in rules)]


def _suppression_matches(rule: dict[str, str], finding: WebFinding) -> bool:
    for key, value in rule.items():
        actual = getattr(finding, key, "")
        if value.lower() not in str(actual).lower():
            return False
    return True


def _write_traffic(path: str | None, method: str, url: str, resp: httpx.Response) -> None:
    if not path:
        return
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    record = {
        "ts": time.time(),
        "request": {"method": method, "url": url},
        "response": {
            "status": resp.status_code,
            "url": str(resp.url),
            "content_type": resp.headers.get("content-type"),
            "bytes": len(resp.content),
        },
    }
    with target.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, sort_keys=True) + "\n")


def parse_headers(values: Iterable[str] | None) -> dict[str, str]:
    headers: dict[str, str] = {}
    for item in values or []:
        if ":" not in item:
            raise ValueError(f"invalid header {item!r}; use 'Name: value'")
        key, value = item.split(":", 1)
        headers[key.strip()] = value.strip()
    return headers


def parse_paths_file(path: str | None) -> list[str]:
    if not path:
        return []
    return [
        line.strip()
        for line in Path(path).read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]


def load_checks(
    extra_dbs: list[str] | None,
    *,
    profile: str,
    tags: list[str] | None,
    tuning: list[str] | None,
) -> list[WebCheck]:
    paths = [DEFAULT_CHECK_DB]
    if USER_CHECK_DB.exists():
        paths.append(USER_CHECK_DB)
    paths.extend(Path(p) for p in extra_dbs or [])
    checks: list[WebCheck] = []
    for path in paths:
        if not path.exists():
            continue
        data = json.loads(path.read_text(encoding="utf-8"))
        for item in data.get("checks", []):
            check = WebCheck(
                id=str(item["id"]),
                path=str(item["path"]),
                match=str(item["match"]),
                title=str(item["title"]),
                severity=str(item.get("severity", "info")),
                check=str(item.get("check", "check_db")),
                remediation=str(item.get("remediation", "")),
                references=list(item.get("references", [])),
                cves=list(item.get("cves", [])),
                tags=list(item.get("tags", [])),
                profiles=list(item.get("profiles", ["quick", "standard", "deep"])),
            )
            if not _check_selected(check, profile, tags, tuning):
                continue
            checks.append(check)
    return checks


def _check_selected(check: WebCheck, profile: str, tags: list[str] | None, tuning: list[str] | None) -> bool:
    profile_order = {"quick": 1, "standard": 2, "deep": 3}
    allowed_profiles = check.profiles or ["quick", "standard", "deep"]
    if not any(profile_order.get(item, 0) <= profile_order.get(profile, 2) for item in allowed_profiles):
        return False
    check_tags = set(check.tags or [])
    if tags and not check_tags.intersection(tags):
        return False
    if tuning and not check_tags.intersection(tuning):
        return False
    return True


def load_auth_profile(path: str | None) -> tuple[dict[str, str], str | None]:
    if not path:
        return {}, None
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return dict(data.get("headers", {})), data.get("cookie")


def load_suppressions(paths: list[str] | None) -> list[dict[str, str]]:
    rules: list[dict[str, str]] = []
    for path in paths or []:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        raw_rules = data.get("suppressions", data if isinstance(data, list) else [])
        for rule in raw_rules:
            if isinstance(rule, dict):
                rules.append({str(k): str(v) for k, v in rule.items()})
    return rules


def parse_targets_file(path: str | None) -> list[str]:
    if not path:
        return []
    targets: list[str] = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        item = line.strip()
        if not item or item.startswith("#"):
            continue
        parts = item.split()
        if len(parts) >= 2 and parts[1].isdigit():
            host = parts[0].rstrip("/")
            scheme = "https" if parts[1] == "443" else "http"
            targets.append(f"{scheme}://{host}:{parts[1]}")
        else:
            targets.append(item)
    return targets


def update_check_db(source: str | None, destination: str | None) -> Path:
    dest = Path(destination).expanduser() if destination else USER_CHECK_DB
    dest.parent.mkdir(parents=True, exist_ok=True)
    if not source:
        shutil.copyfile(DEFAULT_CHECK_DB, dest)
        return dest
    if source.startswith(("http://", "https://")):
        data = httpx.get(source, timeout=15.0, follow_redirects=True).text
        parsed = json.loads(data)
        dest.write_text(json.dumps(parsed, indent=2), encoding="utf-8")
        return dest
    src = Path(source).expanduser()
    parsed = json.loads(src.read_text(encoding="utf-8"))
    dest.write_text(json.dumps(parsed, indent=2), encoding="utf-8")
    return dest


def render_results(results: list[WebScanResult], fmt: str) -> str:
    if len(results) == 1:
        return render_result(results[0], fmt)
    if fmt == "json":
        return json.dumps([_result_dict(result) for result in results], indent=2)
    if fmt == "csv":
        out = StringIO()
        writer = csv.DictWriter(out, fieldnames=_csv_fields(), extrasaction="ignore")
        writer.writeheader()
        for result in results:
            for finding in result.findings:
                writer.writerow(asdict(finding))
        return out.getvalue().rstrip()
    if fmt == "xml":
        return _render_xml(results)
    if fmt == "html":
        return _render_html(results)
    return "\n\n".join(render_result(result, fmt) for result in results)


def render_result(result: WebScanResult, fmt: str) -> str:
    if fmt == "json":
        return json.dumps(_result_dict(result), indent=2)
    if fmt == "csv":
        out = StringIO()
        writer = csv.DictWriter(out, fieldnames=_csv_fields(), extrasaction="ignore")
        writer.writeheader()
        for finding in result.findings:
            writer.writerow(asdict(finding))
        return out.getvalue().rstrip()
    if fmt == "xml":
        return _render_xml([result])
    if fmt == "html":
        return _render_html([result])
    if fmt != "table":
        raise ValueError("format must be one of: table, json, csv, xml, html")
    lines = [
        f"Scanned {result.target} with profile={result.profile}: {len(result.findings)} findings, {result.requests_sent} requests in {result.elapsed_sec:.2f}s",
    ]
    if result.evidence_path:
        lines.append(f"Evidence log: {result.evidence_path}")
    lines.append("")
    if not result.findings:
        lines.append("No web server exposure findings found.")
        return "\n".join(lines)
    headers = ("SEV", "CHECK", "TITLE", "URL")
    rows = [(f.severity, f.check, f.title, f.url) for f in result.findings]
    widths = [len(h) for h in headers]
    for row in rows:
        for idx, cell in enumerate(row):
            widths[idx] = min(max(widths[idx], len(str(cell))), 72)

    def fit(value: str, width: int) -> str:
        value = str(value)
        if len(value) > width:
            value = value[: max(0, width - 3)] + "..."
        return value.ljust(width)

    lines.append("  ".join(fit(h, widths[i]) for i, h in enumerate(headers)))
    lines.append("  ".join("-" * width for width in widths))
    for row in rows:
        lines.append("  ".join(fit(cell, widths[i]) for i, cell in enumerate(row)))
    return "\n".join(lines)


def _result_dict(result: WebScanResult) -> dict[str, Any]:
    return {
        "target": result.target,
        "profile": result.profile,
        "requests_sent": result.requests_sent,
        "elapsed_sec": round(result.elapsed_sec, 3),
        "evidence_path": result.evidence_path,
        "findings": [asdict(f) for f in result.findings],
    }


def _csv_fields() -> list[str]:
    return ["severity", "check", "title", "status_code", "url", "evidence", "remediation", "references", "cves", "tags"]


def _render_xml(results: list[WebScanResult]) -> str:
    lines = ['<?xml version="1.0" encoding="UTF-8"?>', "<webscan>"]
    for result in results:
        lines.append(f'  <target url="{html.escape(result.target)}" profile="{html.escape(result.profile)}" requests="{result.requests_sent}">')
        for finding in result.findings:
            lines.append(
                "    "
                f'<finding severity="{html.escape(finding.severity)}" check="{html.escape(finding.check)}" '
                f'status="{finding.status_code or ""}">'
            )
            lines.append(f"      <title>{html.escape(finding.title)}</title>")
            lines.append(f"      <url>{html.escape(finding.url)}</url>")
            lines.append(f"      <evidence>{html.escape(finding.evidence)}</evidence>")
            if finding.cves:
                lines.append(f"      <cves>{html.escape(','.join(finding.cves))}</cves>")
            lines.append("    </finding>")
        lines.append("  </target>")
    lines.append("</webscan>")
    return "\n".join(lines)


def _render_html(results: list[WebScanResult]) -> str:
    rows = []
    for result in results:
        for finding in result.findings:
            rows.append(
                "<tr>"
                f"<td>{html.escape(result.target)}</td>"
                f"<td>{html.escape(finding.severity)}</td>"
                f"<td>{html.escape(finding.check)}</td>"
                f"<td>{html.escape(finding.title)}</td>"
                f"<td>{html.escape(finding.url)}</td>"
                f"<td>{html.escape(finding.evidence)}</td>"
                "</tr>"
            )
    return (
        "<!doctype html><html><head><meta charset='utf-8'><title>Pencheff Webscan</title>"
        "<style>body{font-family:sans-serif}table{border-collapse:collapse;width:100%}"
        "td,th{border:1px solid #ccc;padding:6px;text-align:left}</style></head><body>"
        "<h1>Pencheff Webscan Report</h1><table><thead><tr>"
        "<th>Target</th><th>Severity</th><th>Check</th><th>Title</th><th>URL</th><th>Evidence</th>"
        "</tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table></body></html>"
    )


async def run_cli(args) -> int:
    try:
        if args.update_checks:
            path = update_check_db(args.update_source, args.update_destination)
            print(f"Updated webscan check database: {path}")
            return 0
        targets = list(args.target or []) + parse_targets_file(args.targets_file)
        if not targets:
            raise ValueError("at least one --target or --targets-file entry is required")
        results = []
        for target in targets:
            result = await scan(
                target,
                profile=args.profile,
                timeout=args.timeout,
                verify_ssl=args.verify_ssl,
                headers=parse_headers(args.header),
                cookie=args.cookie,
                proxy=args.proxy,
                concurrency=args.concurrency,
                extra_paths=(args.path or []) + parse_paths_file(args.paths_file),
                traffic_log=args.traffic_log,
                check_db=args.check_db,
                tags=args.tag,
                tuning=args.tuning,
                auth_profile=args.auth_profile,
                suppressions=args.suppressions,
                request_encoding=args.request_encoding,
                delay=args.delay,
            )
            results.append(result)
        print(render_results(results, args.format))
    except (ValueError, OSError, httpx.HTTPError) as exc:
        print(f"pencheff webscan: {exc}", file=sys.stderr)
        return 2
    return 0
