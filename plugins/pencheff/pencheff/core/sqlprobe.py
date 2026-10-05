"""First-party SQL injection assessor.

The probe is intentionally non-destructive: it detects likely SQL injection
with error signatures, boolean differentials, UNION-shape probes, stacked
query probes, and tightly capped timing checks. It does not dump data,
enumerate schemas, read/write files, create UDFs, or attempt shell access.
"""

from __future__ import annotations

import asyncio
import csv
import hashlib
import json
import random
import re
import sys
import time
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass, field
from difflib import SequenceMatcher
from html.parser import HTMLParser
from io import StringIO
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

import httpx


SQL_ERRORS = {
    "MySQL": [
        r"SQL syntax.*MySQL", r"Warning.*mysql_", r"MySQLSyntaxErrorException",
        r"valid MySQL result", r"check the manual that corresponds to your MySQL",
    ],
    "MariaDB": [r"MariaDB.*syntax", r"check the manual that corresponds to your MariaDB"],
    "PostgreSQL": [
        r"PostgreSQL.*ERROR", r"Warning.*\Wpg_", r"Npgsql\.", r"PG::SyntaxError",
        r"syntax error at or near",
    ],
    "MSSQL": [
        r"Driver.* SQL[\-_ ]*Server", r"OLE DB.* SQL Server",
        r"SQL Server.*Driver", r"Warning.*mssql_", r"Unclosed quotation mark",
        r"Msg \d+, Level \d+, State \d+",
    ],
    "Oracle": [
        r"\bORA-\d{5}", r"Oracle error", r"Oracle.*Driver",
        r"quoted string not properly terminated",
    ],
    "SQLite": [
        r"SQLite/JDBCDriver", r"SQLite\.Exception", r"System\.Data\.SQLite",
        r"Warning.*sqlite_", r"SQLITE_ERROR",
    ],
    "DB2": [r"DB2 SQL error", r"SQLCODE", r"SQLSTATE"],
    "Firebird": [r"Dynamic SQL Error", r"Firebird"],
    "Sybase": [r"Sybase message", r"Adaptive Server"],
    "Access": [r"Microsoft Access Driver", r"JET Database Engine"],
    "H2": [r"org\.h2\.jdbc", r"JdbcSQLSyntaxErrorException"],
    "Derby": [r"Apache Derby", r"Derby SQL error"],
}

DBMS_FAMILIES = {
    "generic": {
        "error": ["'", "\"", "')", "\")", "'))"],
        "boolean": [
            ("' AND '1'='1", "' AND '1'='2"),
            ("' AND 1=1--", "' AND 1=2--"),
            (" AND 1=1", " AND 1=2"),
        ],
        "union": [
            "' UNION ALL SELECT NULL--",
            "' UNION ALL SELECT NULL,NULL--",
            "' UNION ALL SELECT NULL,NULL,NULL--",
        ],
        "stacked": ["'; SELECT 1--"],
    },
    "mysql": {
        "time": ["' AND SLEEP({delay})--", "' OR SLEEP({delay})--"],
        "union": ["' UNION ALL SELECT NULL#", "' UNION ALL SELECT NULL,NULL#"],
        "stacked": ["'; SELECT SLEEP(0)--"],
    },
    "postgresql": {
        "time": ["'; SELECT pg_sleep({delay})--"],
        "stacked": ["'; SELECT pg_sleep(0)--"],
    },
    "mssql": {
        "time": ["'; WAITFOR DELAY '0:0:{delay}'--"],
        "stacked": ["'; SELECT 1--"],
    },
    "oracle": {
        "union": ["' UNION ALL SELECT NULL FROM dual--", "' UNION ALL SELECT NULL,NULL FROM dual--"],
    },
    "sqlite": {
        "stacked": ["'; SELECT 1--"],
    },
}

PROFILE_DEFAULTS = {
    "quick": {"level": 1, "risk": 1, "techniques": {"error", "boolean"}},
    "standard": {"level": 2, "risk": 1, "techniques": {"error", "boolean", "time", "union"}},
    "deep": {"level": 4, "risk": 2, "techniques": {"error", "boolean", "time", "union", "stacked"}},
}

TAMPERS: dict[str, Any] = {}


def _tamper(name: str):
    def wrap(fn):
        TAMPERS[name] = fn
        return fn
    return wrap


@_tamper("space2comment")
def _space2comment(payload: str) -> str:
    return payload.replace(" ", "/**/")


@_tamper("randomcase")
def _randomcase(payload: str) -> str:
    rng = random.Random(hashlib.sha256(payload.encode()).hexdigest())
    return "".join(ch.upper() if ch.isalpha() and rng.choice([True, False]) else ch for ch in payload)


@_tamper("equaltolike")
def _equaltolike(payload: str) -> str:
    return payload.replace("=", " LIKE ")


@dataclass(slots=True)
class HTTPRequestSpec:
    url: str
    method: str = "GET"
    data: str | None = None
    headers: dict[str, str] = field(default_factory=dict)


@dataclass(slots=True)
class ProbeFinding:
    url: str
    parameter: str
    technique: str
    confidence: str
    dbms: str | None
    payload: str
    evidence: str
    status_code: int | None = None


@dataclass(slots=True)
class ProbeResult:
    url: str
    method: str
    tested_parameters: list[str]
    findings: list[ProbeFinding]
    elapsed_sec: float
    requests_sent: int
    evidence_path: str | None = None
    cache_key: str | None = None


class RequestBuilder:
    def __init__(self, url: str, method: str, data: str | None):
        self.url = url
        self.method = method.upper()
        self.data = data or ""
        self.query_pairs = parse_qsl(urlparse(url).query, keep_blank_values=True)
        self.body_pairs = parse_qsl(self.data, keep_blank_values=True)

    def parameters(self) -> list[str]:
        pairs = self.body_pairs if self.method != "GET" and self.body_pairs else self.query_pairs
        seen: list[str] = []
        for key, _ in pairs:
            if key not in seen:
                seen.append(key)
        return seen

    def build(
        self,
        parameter: str,
        value: str,
        *,
        anti_cache: bool = False,
        csrf: dict[str, str] | None = None,
    ) -> tuple[str, str | None]:
        parsed = urlparse(self.url)
        nonce = str(int(time.time() * 1000))
        if self.method == "GET":
            pairs = [(k, value if k == parameter else v) for k, v in self.query_pairs]
            if csrf:
                pairs = [(k, csrf.get(k, v)) for k, v in pairs]
            if anti_cache:
                pairs.append(("_pcache", nonce))
            return urlunparse(parsed._replace(query=urlencode(pairs))), None
        pairs = [(k, value if k == parameter else v) for k, v in self.body_pairs]
        if csrf:
            pairs = [(k, csrf.get(k, v)) for k, v in pairs]
        query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
        if anti_cache:
            query_pairs.append(("_pcache", nonce))
        return urlunparse(parsed._replace(query=urlencode(query_pairs))), urlencode(pairs)

    def original_value(self, parameter: str) -> str:
        pairs = self.body_pairs if self.method != "GET" and self.body_pairs else self.query_pairs
        for key, value in pairs:
            if key == parameter:
                return value
        return "1"


class _DiscoveryParser(HTMLParser):
    def __init__(self, base_url: str):
        super().__init__()
        self.base_url = base_url
        self.links: set[str] = set()
        self.forms: list[HTTPRequestSpec] = []
        self._form: dict[str, Any] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]):
        data = {k.lower(): v or "" for k, v in attrs}
        if tag == "a" and data.get("href"):
            self.links.add(urljoin(self.base_url, data["href"]))
        if tag == "form":
            self._form = {
                "method": (data.get("method") or "GET").upper(),
                "action": urljoin(self.base_url, data.get("action") or self.base_url),
                "inputs": [],
            }
        if tag in {"input", "textarea", "select"} and self._form is not None and data.get("name"):
            self._form["inputs"].append((data["name"], data.get("value") or "1"))

    def handle_endtag(self, tag: str):
        if tag != "form" or self._form is None:
            return
        body = urlencode(self._form["inputs"])
        action = self._form["action"]
        method = self._form["method"]
        if method == "GET":
            sep = "&" if urlparse(action).query else "?"
            self.forms.append(HTTPRequestSpec(f"{action}{sep}{body}", "GET"))
        else:
            self.forms.append(HTTPRequestSpec(action, method, body))
        self._form = None


async def assess(
    url: str,
    *,
    method: str = "GET",
    data: str | None = None,
    headers: dict[str, str] | None = None,
    parameters: list[str] | None = None,
    techniques: set[str] | None = None,
    profile: str = "standard",
    level: int | None = None,
    risk: int | None = None,
    timeout: float = 8.0,
    delay: int = 2,
    verify_ssl: bool = False,
    proxy: str | None = None,
    cookie: str | None = None,
    tamper: list[str] | None = None,
    csrf_token: str | None = None,
    anti_cache: bool = False,
    traffic_log: str | None = None,
    verbosity: int = 1,
) -> ProbeResult:
    started = time.monotonic()
    profile_config = PROFILE_DEFAULTS.get(profile, PROFILE_DEFAULTS["standard"])
    level = profile_config["level"] if level is None else level
    risk = profile_config["risk"] if risk is None else risk
    techniques = set(techniques or profile_config["techniques"])
    builder = RequestBuilder(url, method, data)
    targets = parameters or builder.parameters()
    findings: list[ProbeFinding] = []
    requests_sent = 0

    if not targets:
        raise ValueError("No parameters found. Add query params, --data, --param, --request-file, --bulk-file, or --crawl.")

    request_headers = dict(headers or {})
    if cookie:
        request_headers["Cookie"] = cookie
    request_headers.setdefault("User-Agent", "Mozilla/5.0 (compatible; PencheffSqli/0.2)")
    request_headers.setdefault("Cache-Control", "no-cache")

    client_kwargs: dict[str, Any] = {
        "timeout": httpx.Timeout(timeout),
        "verify": verify_ssl,
        "follow_redirects": True,
        "headers": request_headers,
    }
    if proxy:
        client_kwargs["proxy"] = proxy

    async with httpx.AsyncClient(**client_kwargs) as client:
        csrf = await _refresh_csrf(client, builder, csrf_token) if csrf_token else None
        baseline = await _send(client, builder, None, None, anti_cache=anti_cache, csrf=csrf, traffic_log=traffic_log, verbosity=verbosity)
        requests_sent += 1

        for param in targets:
            original = builder.original_value(param)
            dbms_hint: str | None = None
            for technique in ("error", "boolean", "time", "union", "stacked"):
                if technique not in techniques:
                    continue
                sent, found = await _run_technique(
                    technique,
                    client,
                    builder,
                    baseline,
                    param,
                    original,
                    delay,
                    level,
                    risk,
                    tamper or [],
                    anti_cache,
                    csrf,
                    traffic_log,
                    verbosity,
                )
                requests_sent += sent
                if found and not dbms_hint:
                    dbms_hint = found[0].dbms
                findings.extend(found)
                if found and risk <= 1 and technique in {"error", "boolean"}:
                    break

    result = ProbeResult(
        url=url,
        method=method.upper(),
        tested_parameters=targets,
        findings=findings,
        elapsed_sec=time.monotonic() - started,
        requests_sent=requests_sent,
        evidence_path=traffic_log,
        cache_key=_cache_key(url, method, data, targets, sorted(techniques)),
    )
    return result


async def _run_technique(
    technique: str,
    client: httpx.AsyncClient,
    builder: RequestBuilder,
    baseline: httpx.Response,
    param: str,
    original: str,
    delay: int,
    level: int,
    risk: int,
    tampers: list[str],
    anti_cache: bool,
    csrf: dict[str, str] | None,
    traffic_log: str | None,
    verbosity: int,
) -> tuple[int, list[ProbeFinding]]:
    if technique == "error":
        return await _error_probe(client, builder, param, original, level, tampers, anti_cache, csrf, traffic_log, verbosity)
    if technique == "boolean":
        return await _boolean_probe(client, builder, baseline, param, original, level, tampers, anti_cache, csrf, traffic_log, verbosity)
    if technique == "time":
        return await _time_probe(client, builder, param, original, delay, level, tampers, anti_cache, csrf, traffic_log, verbosity)
    if technique == "union":
        return await _union_probe(client, builder, baseline, param, original, level, risk, tampers, anti_cache, csrf, traffic_log, verbosity)
    if technique == "stacked":
        return await _stacked_probe(client, builder, param, original, level, risk, tampers, anti_cache, csrf, traffic_log, verbosity)
    return 0, []


async def _send(
    client: httpx.AsyncClient,
    builder: RequestBuilder,
    parameter: str | None,
    value: str | None,
    *,
    anti_cache: bool = False,
    csrf: dict[str, str] | None = None,
    traffic_log: str | None = None,
    verbosity: int = 1,
) -> httpx.Response:
    if parameter is None:
        url, body = builder.build("", "", anti_cache=anti_cache, csrf=csrf)
        if builder.method == "GET":
            url = builder.url
            if anti_cache:
                parsed = urlparse(url)
                pairs = parse_qsl(parsed.query, keep_blank_values=True) + [("_pcache", str(int(time.time() * 1000)))]
                url = urlunparse(parsed._replace(query=urlencode(pairs)))
            resp = await client.get(url)
            _write_traffic(traffic_log, builder.method, url, None, resp, verbosity)
            return resp
        resp = await client.request(
            builder.method,
            urlunparse(urlparse(builder.url)._replace(query=urlparse(url).query)),
            content=builder.data if csrf is None else body,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        _write_traffic(traffic_log, builder.method, str(resp.request.url), builder.data, resp, verbosity)
        return resp
    url, body = builder.build(parameter, value or "", anti_cache=anti_cache, csrf=csrf)
    if builder.method == "GET":
        resp = await client.get(url)
        _write_traffic(traffic_log, "GET", url, None, resp, verbosity)
        return resp
    resp = await client.request(
        builder.method,
        url,
        content=body or "",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    _write_traffic(traffic_log, builder.method, url, body, resp, verbosity)
    return resp


async def _error_probe(
    client: httpx.AsyncClient,
    builder: RequestBuilder,
    param: str,
    original: str,
    level: int,
    tampers: list[str],
    anti_cache: bool,
    csrf: dict[str, str] | None,
    traffic_log: str | None,
    verbosity: int,
) -> tuple[int, list[ProbeFinding]]:
    findings: list[ProbeFinding] = []
    sent = 0
    payloads = _payloads("error", level)
    for suffix in payloads:
        payload = original + _apply_tampers(suffix, tampers)
        try:
            resp = await _send(client, builder, param, payload, anti_cache=anti_cache, csrf=csrf, traffic_log=traffic_log, verbosity=verbosity)
            sent += 1
        except httpx.HTTPError:
            continue
        for dbms, patterns in SQL_ERRORS.items():
            if any(re.search(pattern, resp.text, re.IGNORECASE) for pattern in patterns):
                findings.append(ProbeFinding(
                    url=str(resp.url),
                    parameter=param,
                    technique="error",
                    confidence="high",
                    dbms=dbms,
                    payload=payload,
                    status_code=resp.status_code,
                    evidence=f"SQL error signature matched for {dbms}.",
                ))
                return sent, findings
    return sent, findings


async def _boolean_probe(
    client: httpx.AsyncClient,
    builder: RequestBuilder,
    baseline: httpx.Response,
    param: str,
    original: str,
    level: int,
    tampers: list[str],
    anti_cache: bool,
    csrf: dict[str, str] | None,
    traffic_log: str | None,
    verbosity: int,
) -> tuple[int, list[ProbeFinding]]:
    findings: list[ProbeFinding] = []
    sent = 0
    for true_suffix, false_suffix in _payloads("boolean", level):
        try:
            true_payload = original + _apply_tampers(true_suffix, tampers)
            false_payload = original + _apply_tampers(false_suffix, tampers)
            true_resp = await _send(client, builder, param, true_payload, anti_cache=anti_cache, csrf=csrf, traffic_log=traffic_log, verbosity=verbosity)
            false_resp = await _send(client, builder, param, false_payload, anti_cache=anti_cache, csrf=csrf, traffic_log=traffic_log, verbosity=verbosity)
            sent += 2
        except httpx.HTTPError:
            continue

        score = _differential_score(baseline, true_resp, false_resp)
        if score["true_ratio"] > 0.90 and score["false_ratio"] < 0.82 and (score["len_diff"] > 200 or score["status_diff"]):
            confirm = await _confirm_boolean(client, builder, param, true_payload, false_payload, anti_cache, csrf, traffic_log, verbosity)
            sent += confirm[0]
            if not confirm[1]:
                continue
            findings.append(ProbeFinding(
                url=str(true_resp.url),
                parameter=param,
                technique="boolean",
                confidence="medium",
                dbms=None,
                payload=f"{true_payload} / {false_payload}",
                status_code=true_resp.status_code,
                evidence=(
                    f"True response close to baseline ({score['true_ratio']:.2f}); "
                    f"false response diverged ({score['false_ratio']:.2f}); "
                    f"length diff {score['len_diff']}."
                ),
            ))
            return sent, findings
    return sent, findings


async def _confirm_boolean(
    client: httpx.AsyncClient,
    builder: RequestBuilder,
    param: str,
    true_payload: str,
    false_payload: str,
    anti_cache: bool,
    csrf: dict[str, str] | None,
    traffic_log: str | None,
    verbosity: int,
) -> tuple[int, bool]:
    try:
        true_resp = await _send(client, builder, param, true_payload, anti_cache=anti_cache, csrf=csrf, traffic_log=traffic_log, verbosity=verbosity)
        false_resp = await _send(client, builder, param, false_payload, anti_cache=anti_cache, csrf=csrf, traffic_log=traffic_log, verbosity=verbosity)
    except httpx.HTTPError:
        return 0, False
    return 2, abs(len(true_resp.text) - len(false_resp.text)) > 200 or true_resp.status_code != false_resp.status_code


async def _time_probe(
    client: httpx.AsyncClient,
    builder: RequestBuilder,
    param: str,
    original: str,
    delay: int,
    level: int,
    tampers: list[str],
    anti_cache: bool,
    csrf: dict[str, str] | None,
    traffic_log: str | None,
    verbosity: int,
) -> tuple[int, list[ProbeFinding]]:
    findings: list[ProbeFinding] = []
    sent = 0
    try:
        start = time.monotonic()
        await _send(client, builder, param, original, anti_cache=anti_cache, csrf=csrf, traffic_log=traffic_log, verbosity=verbosity)
        baseline = time.monotonic() - start
        sent += 1
    except httpx.HTTPError:
        return sent, findings

    capped_delay = max(1, min(delay, 5))
    for dbms, suffix in _payloads("time", level):
        payload = original + _apply_tampers(suffix.format(delay=capped_delay), tampers)
        try:
            start = time.monotonic()
            await _send(client, builder, param, payload, anti_cache=anti_cache, csrf=csrf, traffic_log=traffic_log, verbosity=verbosity)
            elapsed = time.monotonic() - start
            sent += 1
        except httpx.HTTPError:
            continue
        if elapsed - baseline >= max(1.5, capped_delay * 0.7):
            findings.append(ProbeFinding(
                url=builder.url,
                parameter=param,
                technique="time",
                confidence="medium",
                dbms=dbms,
                payload=payload,
                evidence=f"Baseline {baseline:.2f}s, payload response {elapsed:.2f}s.",
            ))
            return sent, findings
    return sent, findings


async def _union_probe(
    client: httpx.AsyncClient,
    builder: RequestBuilder,
    baseline: httpx.Response,
    param: str,
    original: str,
    level: int,
    risk: int,
    tampers: list[str],
    anti_cache: bool,
    csrf: dict[str, str] | None,
    traffic_log: str | None,
    verbosity: int,
) -> tuple[int, list[ProbeFinding]]:
    if risk < 1:
        return 0, []
    findings: list[ProbeFinding] = []
    sent = 0
    for dbms, suffix in _payloads("union", level):
        payload = original + _apply_tampers(suffix, tampers)
        try:
            resp = await _send(client, builder, param, payload, anti_cache=anti_cache, csrf=csrf, traffic_log=traffic_log, verbosity=verbosity)
            sent += 1
        except httpx.HTTPError:
            continue
        if _looks_like_union_shape_change(baseline, resp) or _has_sql_error(resp.text):
            findings.append(ProbeFinding(
                url=str(resp.url),
                parameter=param,
                technique="union",
                confidence="low" if not _has_sql_error(resp.text) else "medium",
                dbms=dbms if dbms != "generic" else None,
                payload=payload,
                status_code=resp.status_code,
                evidence="UNION-shape probe changed response structure or triggered a SQL parser response.",
            ))
            return sent, findings
    return sent, findings


async def _stacked_probe(
    client: httpx.AsyncClient,
    builder: RequestBuilder,
    param: str,
    original: str,
    level: int,
    risk: int,
    tampers: list[str],
    anti_cache: bool,
    csrf: dict[str, str] | None,
    traffic_log: str | None,
    verbosity: int,
) -> tuple[int, list[ProbeFinding]]:
    if risk < 2:
        return 0, []
    findings: list[ProbeFinding] = []
    sent = 0
    for dbms, suffix in _payloads("stacked", level):
        payload = original + _apply_tampers(suffix, tampers)
        try:
            resp = await _send(client, builder, param, payload, anti_cache=anti_cache, csrf=csrf, traffic_log=traffic_log, verbosity=verbosity)
            sent += 1
        except httpx.HTTPError:
            continue
        if _has_sql_error(resp.text) or resp.status_code >= 500:
            findings.append(ProbeFinding(
                url=str(resp.url),
                parameter=param,
                technique="stacked",
                confidence="low",
                dbms=dbms if dbms != "generic" else None,
                payload=payload,
                status_code=resp.status_code,
                evidence="Safe stacked-query probe caused SQL parser/server behavior change. No destructive statements were sent.",
            ))
            return sent, findings
    return sent, findings


def _payloads(technique: str, level: int) -> list[Any]:
    values: list[Any] = []
    for dbms, family in DBMS_FAMILIES.items():
        entries = family.get(technique, [])
        if technique in {"time", "union", "stacked"}:
            values.extend((dbms, item) for item in entries)
        else:
            values.extend(entries)
    cap = {1: 3, 2: 6, 3: 10, 4: 18, 5: 40}.get(max(1, min(level, 5)), 6)
    return values[:cap]


def _apply_tampers(payload: str, names: list[str]) -> str:
    for name in names:
        fn = TAMPERS.get(name)
        if not fn:
            raise ValueError(f"unknown tamper {name!r}; available: {', '.join(sorted(TAMPERS))}")
        payload = fn(payload)
    return payload


def _differential_score(baseline: httpx.Response, true_resp: httpx.Response, false_resp: httpx.Response) -> dict[str, Any]:
    return {
        "true_ratio": _similarity(baseline.text, true_resp.text),
        "false_ratio": _similarity(baseline.text, false_resp.text),
        "len_diff": abs(len(true_resp.text) - len(false_resp.text)),
        "status_diff": true_resp.status_code != false_resp.status_code,
    }


def _looks_like_union_shape_change(baseline: httpx.Response, resp: httpx.Response) -> bool:
    if resp.status_code != baseline.status_code and resp.status_code >= 500:
        return True
    base_tags = len(re.findall(r"<(?:td|th|li|option)\b", baseline.text, re.IGNORECASE))
    resp_tags = len(re.findall(r"<(?:td|th|li|option)\b", resp.text, re.IGNORECASE))
    return abs(base_tags - resp_tags) >= 3 and _similarity(baseline.text, resp.text) < 0.85


def _has_sql_error(body: str) -> bool:
    return any(re.search(pattern, body, re.IGNORECASE) for patterns in SQL_ERRORS.values() for pattern in patterns)


def _similarity(a: str, b: str) -> float:
    return SequenceMatcher(None, _normalize_body(a), _normalize_body(b)).ratio()


def _normalize_body(body: str) -> str:
    body = re.sub(r"\d{4}-\d{2}-\d{2}[T ][0-9:.+-]+", "", body)
    body = re.sub(r"\b[0-9a-f]{16,}\b", "", body, flags=re.IGNORECASE)
    body = re.sub(r"\b\d{8,}\b", "", body)
    return body[:20000]


async def _refresh_csrf(client: httpx.AsyncClient, builder: RequestBuilder, token_name: str) -> dict[str, str]:
    resp = await client.get(builder.url)
    pattern = (
        r'<input[^>]+name=["\']' + re.escape(token_name) +
        r'["\'][^>]*value=["\']([^"\']+)["\']'
    )
    match = re.search(pattern, resp.text, re.IGNORECASE)
    return {token_name: match.group(1)} if match else {}


def _write_traffic(path: str | None, method: str, url: str, body: str | None, resp: httpx.Response, verbosity: int) -> None:
    if not path:
        return
    record: dict[str, Any] = {
        "ts": time.time(),
        "request": {"method": method, "url": url, "body": body},
        "response": {"status": resp.status_code, "url": str(resp.url), "elapsed_ms": round(resp.elapsed.total_seconds() * 1000, 2) if resp.elapsed else None},
    }
    if verbosity >= 2:
        record["response"]["headers"] = dict(resp.headers)
    if verbosity >= 3:
        record["response"]["body_sample"] = resp.text[:1000]
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
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


def parse_raw_request(path: str, base_url: str | None = None) -> HTTPRequestSpec:
    raw = Path(path).read_text(encoding="utf-8")
    head, _, body = raw.replace("\r\n", "\n").partition("\n\n")
    lines = [line for line in head.splitlines() if line.strip()]
    if not lines:
        raise ValueError("raw request file is empty")
    method, target, *_ = lines[0].split()
    headers = parse_headers(lines[1:])
    host = headers.get("Host") or headers.get("host")
    if target.startswith("http"):
        url = target
    else:
        if not host and not base_url:
            raise ValueError("raw request needs Host header or --base-url")
        scheme = urlparse(base_url).scheme if base_url else "https"
        netloc = urlparse(base_url).netloc if base_url else host
        url = f"{scheme}://{netloc}{target}"
    return HTTPRequestSpec(url=url, method=method, data=body or None, headers=headers)


def parse_bulk_file(path: str) -> list[HTTPRequestSpec]:
    specs: list[HTTPRequestSpec] = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        item = line.strip()
        if not item or item.startswith("#"):
            continue
        parts = item.split(maxsplit=2)
        if len(parts) == 1:
            specs.append(HTTPRequestSpec(parts[0], "GET"))
        elif len(parts) == 2:
            specs.append(HTTPRequestSpec(parts[1], parts[0]))
        else:
            specs.append(HTTPRequestSpec(parts[1], parts[0], parts[2]))
    return specs


def parse_burp_xml(path: str) -> list[HTTPRequestSpec]:
    specs: list[HTTPRequestSpec] = []
    root = ET.parse(path).getroot()
    for item in root.findall(".//item"):
        method = (item.findtext("method") or "GET").strip()
        url = (item.findtext("url") or "").strip()
        request = item.findtext("request")
        if request:
            try:
                specs.append(_spec_from_burp_request(request, url))
                continue
            except ValueError:
                pass
        if url:
            specs.append(HTTPRequestSpec(url=url, method=method))
    return specs


def _spec_from_burp_request(raw: str, fallback_url: str) -> HTTPRequestSpec:
    import base64

    try:
        decoded = base64.b64decode(raw, validate=True).decode("utf-8", errors="replace")
    except Exception:
        decoded = raw
    temp = Path("/tmp/pencheff_burp_request.txt")
    temp.write_text(decoded, encoding="utf-8")
    return parse_raw_request(str(temp), fallback_url)


async def crawl(seed_url: str, *, timeout: float = 8.0, verify_ssl: bool = False, limit: int = 25) -> list[HTTPRequestSpec]:
    parsed_seed = urlparse(seed_url)
    seen: set[str] = set()
    queue = [seed_url]
    specs: list[HTTPRequestSpec] = []
    async with httpx.AsyncClient(timeout=httpx.Timeout(timeout), verify=verify_ssl, follow_redirects=True) as client:
        while queue and len(seen) < limit:
            url = queue.pop(0)
            if url in seen:
                continue
            seen.add(url)
            try:
                resp = await client.get(url)
            except httpx.HTTPError:
                continue
            if urlparse(str(resp.url)).query:
                specs.append(HTTPRequestSpec(str(resp.url), "GET"))
            parser = _DiscoveryParser(str(resp.url))
            parser.feed(resp.text)
            specs.extend(parser.forms)
            for link in parser.links:
                parsed = urlparse(link)
                if parsed.netloc == parsed_seed.netloc and link not in seen and len(queue) < limit:
                    queue.append(link)
    return _dedupe_specs(specs)


def _dedupe_specs(specs: list[HTTPRequestSpec]) -> list[HTTPRequestSpec]:
    seen: set[str] = set()
    out: list[HTTPRequestSpec] = []
    for spec in specs:
        key = f"{spec.method} {spec.url} {spec.data or ''}"
        if key in seen:
            continue
        seen.add(key)
        out.append(spec)
    return out


def render_result(result: ProbeResult, fmt: str) -> str:
    fmt = fmt.lower()
    if fmt == "json":
        return json.dumps(_result_to_dict(result), indent=2)
    if fmt == "csv":
        return _render_csv(result)
    if fmt == "table":
        return _render_table(result)
    raise ValueError("format must be one of: table, json, csv")


def render_results(results: list[ProbeResult], fmt: str) -> str:
    if len(results) == 1:
        return render_result(results[0], fmt)
    if fmt == "json":
        return json.dumps([_result_to_dict(result) for result in results], indent=2)
    if fmt == "csv":
        rows = []
        for result in results:
            rows.extend(asdict(f) for f in result.findings)
        out = StringIO()
        writer = csv.DictWriter(out, fieldnames=["parameter", "technique", "confidence", "dbms", "status_code", "payload", "evidence", "url"])
        writer.writeheader()
        writer.writerows(rows)
        return out.getvalue().rstrip()
    return "\n\n".join(_render_table(result) for result in results)


def _result_to_dict(result: ProbeResult) -> dict[str, Any]:
    return {
        "url": result.url,
        "method": result.method,
        "tested_parameters": result.tested_parameters,
        "requests_sent": result.requests_sent,
        "elapsed_sec": round(result.elapsed_sec, 3),
        "evidence_path": result.evidence_path,
        "cache_key": result.cache_key,
        "findings": [asdict(f) for f in result.findings],
    }


def _render_csv(result: ProbeResult) -> str:
    out = StringIO()
    writer = csv.DictWriter(out, fieldnames=["parameter", "technique", "confidence", "dbms", "status_code", "payload", "evidence", "url"])
    writer.writeheader()
    for finding in result.findings:
        writer.writerow(asdict(finding))
    return out.getvalue().rstrip()


def _render_table(result: ProbeResult) -> str:
    lines = [
        f"{result.method} {result.url}",
        f"Tested {', '.join(result.tested_parameters)} with {result.requests_sent} requests in {result.elapsed_sec:.2f}s",
    ]
    if result.evidence_path:
        lines.append(f"Evidence log: {result.evidence_path}")
    lines.append("")
    if not result.findings:
        lines.append("No SQL injection evidence found.")
        return "\n".join(lines)
    headers = ("PARAM", "TECHNIQUE", "CONF", "DBMS", "EVIDENCE")
    rows = [(f.parameter, f.technique, f.confidence, f.dbms or "-", f.evidence) for f in result.findings]
    widths = [len(h) for h in headers]
    for row in rows:
        for idx, cell in enumerate(row):
            widths[idx] = min(max(widths[idx], len(cell)), 64)

    def fit(value: str, width: int) -> str:
        if len(value) > width:
            value = value[: max(0, width - 3)] + "..."
        return value.ljust(width)

    lines.append("  ".join(fit(h, widths[i]) for i, h in enumerate(headers)))
    lines.append("  ".join("-" * w for w in widths))
    for row in rows:
        lines.append("  ".join(fit(cell, widths[i]) for i, cell in enumerate(row)))
    return "\n".join(lines)


def _cache_key(url: str, method: str, data: str | None, parameters: list[str], techniques: list[str]) -> str:
    raw = json.dumps({"url": url, "method": method, "data": data, "parameters": parameters, "techniques": techniques}, sort_keys=True)
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _cache_path(cache_dir: str, key: str) -> Path:
    return Path(cache_dir).expanduser() / f"{key}.json"


def save_cache(result: ProbeResult, cache_dir: str) -> None:
    if not result.cache_key:
        return
    path = _cache_path(cache_dir, result.cache_key)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(_result_to_dict(result), indent=2), encoding="utf-8")


def load_cache(cache_dir: str, key: str) -> ProbeResult | None:
    path = _cache_path(cache_dir, key)
    if not path.exists():
        return None
    data = json.loads(path.read_text(encoding="utf-8"))
    return ProbeResult(
        url=data["url"],
        method=data["method"],
        tested_parameters=data["tested_parameters"],
        findings=[ProbeFinding(**item) for item in data["findings"]],
        elapsed_sec=data["elapsed_sec"],
        requests_sent=data["requests_sent"],
        evidence_path=data.get("evidence_path"),
        cache_key=data.get("cache_key"),
    )


async def run_cli(args) -> int:
    try:
        specs = await _specs_from_args(args)
        if not specs:
            raise ValueError("No targets to assess.")
        techniques = set(args.technique or [])
        if not techniques or "all" in techniques:
            techniques = set(PROFILE_DEFAULTS.get(args.profile, PROFILE_DEFAULTS["standard"])["techniques"])
        results: list[ProbeResult] = []
        for spec in specs:
            merged_headers = {**spec.headers, **parse_headers(args.header)}
            cache_params = args.param or RequestBuilder(spec.url, spec.method, spec.data).parameters()
            key = _cache_key(spec.url, spec.method, spec.data, cache_params, sorted(techniques))
            if args.resume:
                cached = load_cache(args.cache_dir, key)
                if cached:
                    results.append(cached)
                    continue
            result = await assess(
                spec.url,
                method=spec.method,
                data=spec.data,
                headers=merged_headers,
                parameters=args.param,
                techniques=techniques,
                profile=args.profile,
                level=args.level,
                risk=args.risk,
                timeout=args.timeout,
                delay=args.delay,
                verify_ssl=args.verify_ssl,
                proxy=args.proxy,
                cookie=args.cookie,
                tamper=args.tamper,
                csrf_token=args.csrf_token,
                anti_cache=args.anti_cache,
                traffic_log=args.traffic_log,
                verbosity=args.verbose,
            )
            save_cache(result, args.cache_dir)
            results.append(result)
        print(render_results(results, args.format))
    except (ValueError, httpx.HTTPError, OSError, ET.ParseError) as exc:
        print(f"pencheff sqli: {exc}", file=sys.stderr)
        return 2
    return 0


async def _specs_from_args(args) -> list[HTTPRequestSpec]:
    if args.wizard:
        return [_wizard_spec()]
    specs: list[HTTPRequestSpec] = []
    if args.request_file:
        specs.append(parse_raw_request(args.request_file, args.base_url))
    if args.bulk_file:
        specs.extend(parse_bulk_file(args.bulk_file))
    if args.burp_xml:
        specs.extend(parse_burp_xml(args.burp_xml))
    if args.crawl:
        specs.extend(await crawl(args.crawl, timeout=args.timeout, verify_ssl=args.verify_ssl, limit=args.crawl_limit))
    if args.url:
        specs.append(HTTPRequestSpec(args.url, args.method, args.data))
    return _dedupe_specs(specs)


def _wizard_spec() -> HTTPRequestSpec:
    url = input("Target URL: ").strip()
    method = (input("Method [GET]: ").strip() or "GET").upper()
    data = None
    if method != "GET":
        data = input("URL-encoded body [blank for none]: ").strip() or None
    return HTTPRequestSpec(url, method, data)
