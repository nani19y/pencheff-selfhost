"""First-party template-based detection scanner.

Pulse is a safe template engine for authorized targets. Templates are
JSON, or YAML when PyYAML is installed. The engine supports a safe HTTP subset
for detection templates, request chaining, variables, regex extractors,
lightweight fuzzing, passive DNS/TCP/TLS checks, basic headless DOM checks when
Playwright is available, trust/ignore metadata, cache/resume, and reports.
"""

from __future__ import annotations

import asyncio
import csv
import fnmatch
import hashlib
import html
import json
import re
import shutil
import socket
import ssl
import sys
import time
from dataclasses import asdict, dataclass, field
from io import StringIO
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

import httpx


BUILTIN_TEMPLATE_DIR = Path(__file__).with_name("pulse_templates")
USER_TEMPLATE_DIR = Path.home() / ".pencheff" / "pulse_templates"
USER_IGNORE = Path.home() / ".pencheff" / ".pulse-ignore"

# Phase 2.2 — community DAST rule library, populated by:
#   * ``tools/nuclei2pulse.py`` — imports ProjectDiscovery's Nuclei
#     templates (MIT) into Pulse JSON with attribution preserved.
#   * ``plugins/pencheff/pencheff/modules/dast/rule_synth.py`` —
#     AI-generates Pulse templates from CVE + permissive PoC pairs.
# Both write under this dir; the loader walks it alongside the
# built-in + user dirs so a vanilla install picks up community rules
# automatically. Templates here are signature-verified at scan time
# via the existing ``signed`` field on ``PulseTemplate``.
COMMUNITY_TEMPLATE_DIR = (
    Path(__file__).resolve().parents[3]
    / "bench" / "rules" / "community" / "pulse"
)

PROFILE_SEVERITIES = {
    "quick": {"critical", "high"},
    "standard": {"critical", "high", "medium"},
    "deep": {"critical", "high", "medium", "low", "info"},
    "cicd": {"critical", "high"},
}


@dataclass(slots=True)
class PulseTemplate:
    id: str
    name: str
    severity: str
    description: str
    remediation: str
    tags: list[str]
    references: list[str]
    cves: list[str]
    requests: list[dict[str, Any]]
    classification: dict[str, Any] = field(default_factory=dict)
    variables: dict[str, Any] = field(default_factory=dict)
    source_path: str = ""
    source_hash: str = ""
    signed: bool = False
    author: str = ""
    protocols: list[str] = field(default_factory=list)


@dataclass(slots=True)
class PulseFinding:
    template_id: str
    name: str
    severity: str
    url: str
    evidence: str
    matcher: str
    extracted: dict[str, list[str]] = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    cves: list[str] = field(default_factory=list)
    remediation: str = ""
    status_code: int | None = None
    classification: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class PulseResult:
    target: str
    templates_loaded: int
    requests_sent: int
    elapsed_sec: float
    findings: list[PulseFinding]
    stats: dict[str, Any] = field(default_factory=dict)


async def scan(
    targets: list[str],
    *,
    template_paths: list[str] | None = None,
    profile: str = "standard",
    severities: list[str] | None = None,
    tags: list[str] | None = None,
    template_ids: list[str] | None = None,
    exclude_ids: list[str] | None = None,
    workflow: str | None = None,
    headers: dict[str, str] | None = None,
    cookie: str | None = None,
    auth_profile: str | None = None,
    proxy: str | None = None,
    timeout: float = 8.0,
    concurrency: int = 20,
    rate_limit: float = 0.0,
    verify_ssl: bool = False,
    ignore_file: str | None = None,
    require_signed: bool = False,
    trusted_author: list[str] | None = None,
    cache_dir: str | None = None,
    resume: bool = False,
    retries: int = 0,
    max_host_errors: int = 20,
    stats_file: str | None = None,
    interactsh_url: str | None = None,
    headless: bool = False,
) -> list[PulseResult]:
    templates = load_templates(
        template_paths,
        profile=profile,
        severities=severities,
        tags=tags,
        template_ids=template_ids,
        exclude_ids=exclude_ids,
        workflow=workflow,
        ignore_file=ignore_file,
        require_signed=require_signed,
        trusted_author=trusted_author,
    )
    auth_headers, auth_cookie = load_auth_profile(auth_profile)
    request_headers = {**auth_headers, **dict(headers or {})}
    request_headers.setdefault("User-Agent", "Mozilla/5.0 (compatible; PencheffPulse/0.2)")
    if cookie or auth_cookie:
        request_headers["Cookie"] = cookie or auth_cookie
    client_kwargs: dict[str, Any] = {
        "timeout": httpx.Timeout(timeout),
        "verify": verify_ssl,
        "follow_redirects": True,
        "headers": request_headers,
    }
    if proxy:
        client_kwargs["proxy"] = proxy

    sem = asyncio.Semaphore(max(1, concurrency))
    async with httpx.AsyncClient(**client_kwargs) as client:
        results = await asyncio.gather(*(
            _scan_target(
                client, target, templates, sem,
                rate_limit=rate_limit,
                cache_dir=cache_dir,
                resume=resume,
                retries=retries,
                max_host_errors=max_host_errors,
                interactsh_url=interactsh_url,
                headless=headless,
            )
            for target in targets
        ))
    if stats_file:
        stats = {
            "targets": len(results),
            "templates": len(templates),
            "requests": sum(r.requests_sent for r in results),
            "findings": sum(len(r.findings) for r in results),
            "protocols": sorted({p for t in templates for p in t.protocols}),
        }
        Path(stats_file).write_text(json.dumps(stats, indent=2), encoding="utf-8")
    return results


async def _scan_target(
    client: httpx.AsyncClient,
    target: str,
    templates: list[PulseTemplate],
    sem: asyncio.Semaphore,
    *,
    rate_limit: float,
    cache_dir: str | None,
    resume: bool,
    retries: int,
    max_host_errors: int,
    interactsh_url: str | None,
    headless: bool,
) -> PulseResult:
    started = time.monotonic()
    normalized = normalize_target(target)
    cache_path = _cache_path(cache_dir, normalized)
    if resume and cache_path and cache_path.exists():
        data = json.loads(cache_path.read_text(encoding="utf-8"))
        return PulseResult(
            target=data["target"],
            templates_loaded=data["templates_loaded"],
            requests_sent=data["requests_sent"],
            elapsed_sec=data["elapsed_sec"],
            findings=[PulseFinding(**item) for item in data["findings"]],
            stats=data.get("stats", {}),
        )

    requests_sent = 0
    errors = 0
    findings: list[PulseFinding] = []

    async def run_template(template: PulseTemplate) -> tuple[int, int, list[PulseFinding]]:
        context = build_context(normalized, template.variables, interactsh_url)
        sent = 0
        local_errors = 0
        local_findings: list[PulseFinding] = []
        for req in template.requests:
            protocol = str(req.get("protocol", "http")).lower()
            try:
                if protocol == "http":
                    count, found, extracted = await run_http_request(client, sem, normalized, template, req, context, rate_limit, retries, interactsh_url)
                elif protocol == "headless":
                    count, found, extracted = await run_headless_request(normalized, template, req, context, headless)
                else:
                    count, found, extracted = await run_passive_protocol(normalized, template, req, context)
                sent += count
                local_findings.extend(found)
                for key, values in extracted.items():
                    if values:
                        context[key] = values[0]
                if req.get("stop-at-first-match") and found:
                    break
            except Exception:
                local_errors += 1
                if local_errors >= max_host_errors:
                    break
        return sent, local_errors, local_findings

    for sent, template_errors, found in await asyncio.gather(*(run_template(t) for t in templates)):
        requests_sent += sent
        errors += template_errors
        findings.extend(found)

    result = PulseResult(
        target=normalized,
        templates_loaded=len(templates),
        requests_sent=requests_sent,
        elapsed_sec=time.monotonic() - started,
        findings=dedupe_findings(findings),
        stats={
            "templates": len(templates),
            "requests": requests_sent,
            "errors": errors,
            "protocols": sorted({p for t in templates for p in t.protocols}),
        },
    )
    if cache_path:
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        cache_path.write_text(json.dumps(asdict(result), indent=2), encoding="utf-8")
    return result


async def run_http_request(
    client: httpx.AsyncClient,
    sem: asyncio.Semaphore,
    base_url: str,
    template: PulseTemplate,
    req: dict[str, Any],
    context: dict[str, str],
    rate_limit: float,
    retries: int,
    interactsh_url: str | None,
) -> tuple[int, list[PulseFinding], dict[str, list[str]]]:
    found: list[PulseFinding] = []
    extracted_context: dict[str, list[str]] = {}
    sent = 0
    for request_item in expand_fuzzing(req, base_url, context, interactsh_url):
        async with sem:
            if rate_limit > 0:
                await asyncio.sleep(rate_limit)
            method = str(request_item.get("method", req.get("method", "GET"))).upper()
            path = str(request_item.get("path", req.get("path", "/")))
            rendered_path = render_variables(path, base_url, context, interactsh_url)
            if urlparse(rendered_path).scheme:
                url = rendered_path
            else:
                url = urljoin(base_url.rstrip("/") + "/", rendered_path.lstrip("/"))
            body = render_variables(str(request_item.get("body", "")), base_url, context, interactsh_url) if request_item.get("body") is not None else None
            headers = {str(k): render_variables(str(v), base_url, context, interactsh_url) for k, v in dict(request_item.get("headers", {})).items()}
            resp = None
            for attempt in range(retries + 1):
                try:
                    resp = await client.request(method, url, content=body, headers=headers or None)
                    break
                except httpx.HTTPError:
                    if attempt >= retries:
                        return sent + 1, found, extracted_context
            sent += 1
            if resp is None:
                continue
            matched = evaluate_matchers(request_item.get("matchers", req.get("matchers", [])), resp)
            extracted = run_extractors(request_item.get("extractors", req.get("extractors", [])), resp)
            merge_extracted(extracted_context, extracted)
            if matched:
                found.append(to_finding(template, str(resp.url), f"Template {template.id} matched {matched}", matched, extracted, resp.status_code))
    return sent, found, extracted_context


async def run_passive_protocol(
    base_url: str,
    template: PulseTemplate,
    req: dict[str, Any],
    context: dict[str, str],
) -> tuple[int, list[PulseFinding], dict[str, list[str]]]:
    protocol = str(req.get("protocol", "")).lower()
    parsed = urlparse(base_url)
    host = render_variables(str(req.get("host", parsed.hostname or "")), base_url, context, None)
    evidence = ""
    ok = False
    if protocol == "dns":
        records = socket.getaddrinfo(host, None)
        evidence = ",".join(sorted({item[4][0] for item in records}))
        ok = bool(records)
    elif protocol == "tcp":
        port = int(req.get("port", parsed.port or (443 if parsed.scheme == "https" else 80)))
        with socket.create_connection((host, port), timeout=float(req.get("timeout", 3.0))):
            evidence = f"TCP {host}:{port} reachable"
            ok = True
    elif protocol == "tls":
        port = int(req.get("port", 443))
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=float(req.get("timeout", 4.0))) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                evidence = json.dumps(cert, default=str)[:1000]
                ok = True
    else:
        return 0, [], {}
    text_resp = SimpleResponse(200 if ok else 0, evidence, {})
    matched = evaluate_matchers(req.get("matchers", []), text_resp)
    return 1, [to_finding(template, base_url, evidence, matched or protocol, {}, text_resp.status_code)] if matched else [], {}


async def run_headless_request(
    base_url: str,
    template: PulseTemplate,
    req: dict[str, Any],
    context: dict[str, str],
    enabled: bool,
) -> tuple[int, list[PulseFinding], dict[str, list[str]]]:
    if not enabled:
        return 0, [], {}
    try:
        from playwright.async_api import async_playwright  # type: ignore
    except Exception:
        return 0, [], {}
    actions = req.get("steps", req.get("actions", []))
    final_url = base_url
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()
        values: dict[str, str] = {}
        for action in actions:
            name = action.get("name")
            kind = action.get("action")
            args = action.get("args", {})
            if kind == "navigate":
                final_url = render_variables(str(args.get("url", base_url)), base_url, context, None)
                await page.goto(final_url, wait_until="domcontentloaded")
            elif kind in {"waitload", "waitdom", "waitidle"}:
                await page.wait_for_load_state("networkidle" if kind == "waitidle" else "load")
            elif kind == "text":
                await page.fill(str(args.get("selector") or args.get("xpath")), str(args.get("value", "")))
            elif kind == "click":
                await page.click(str(args.get("selector") or args.get("xpath")))
            elif kind == "script":
                code = str(args.get("code", ""))
                if "=>" in code and not any(bad in code for bad in ("fetch(", "XMLHttpRequest", "import(")):
                    values[name or "script"] = str(await page.evaluate(code))
        body = await page.content()
        await browser.close()
    resp = SimpleResponse(200, body + "\n" + json.dumps(values), {})
    matched = evaluate_matchers(req.get("matchers", []), resp)
    extracted = run_extractors(req.get("extractors", []), resp)
    merge_extracted(extracted, {k: [v] for k, v in values.items()})
    return 1, [to_finding(template, final_url, f"Headless template {template.id} matched", matched or "headless", extracted, 200)] if matched else [], extracted


class SimpleResponse:
    def __init__(self, status_code: int, text: str, headers: dict[str, str]):
        self.status_code = status_code
        self.text = text
        self.headers = httpx.Headers(headers)
        self.content = text.encode()


def to_finding(template: PulseTemplate, url: str, evidence: str, matcher: str, extracted: dict[str, list[str]], status_code: int | None) -> PulseFinding:
    return PulseFinding(
        template_id=template.id,
        name=template.name,
        severity=template.severity,
        url=url,
        evidence=evidence,
        matcher=matcher,
        extracted=extracted,
        tags=template.tags,
        references=template.references,
        cves=template.cves,
        remediation=template.remediation,
        status_code=status_code,
        classification=template.classification,
    )


def merge_extracted(target: dict[str, list[str]], source: dict[str, list[str]]) -> None:
    for key, values in source.items():
        target.setdefault(key, [])
        target[key].extend(values)


def evaluate_matchers(matchers: list[dict[str, Any]], resp: Any) -> str | None:
    if not matchers:
        return None
    condition = "or"
    if matchers and isinstance(matchers[0], dict) and "condition" in matchers[0]:
        condition = str(matchers[0].get("condition", "or")).lower()
        matchers = matchers[1:]
    results = [(matcher, match_one(matcher, resp)) for matcher in matchers]
    ok = all(value for _, value in results) if condition == "and" else any(value for _, value in results)
    if not ok:
        return None
    return ",".join(str(m.get("type", "matcher")) for m, value in results if value)


def match_one(matcher: dict[str, Any], resp: Any) -> bool:
    mtype = str(matcher.get("type", "")).lower()
    part = str(matcher.get("part", "body")).lower()
    negative = bool(matcher.get("negative", False))
    haystack = response_part(resp, part)
    result = False
    if mtype == "status":
        result = resp.status_code in {int(x) for x in matcher.get("status", [])}
    elif mtype == "word":
        words = [str(x) for x in matcher.get("words", [])]
        condition = str(matcher.get("condition", "or")).lower()
        checks = [word.lower() in haystack.lower() for word in words]
        result = all(checks) if condition == "and" else any(checks)
    elif mtype == "regex":
        result = any(re.search(str(pattern), haystack, re.I) for pattern in matcher.get("regex", []))
    elif mtype == "header":
        name = str(matcher.get("name", "")).lower()
        value = str(matcher.get("value", ""))
        actual = resp.headers.get(name, "")
        result = bool(actual) and (not value or value.lower() in actual.lower())
    elif mtype == "size":
        size = len(resp.content)
        result = size >= int(matcher.get("min", 0)) and size <= int(matcher.get("max", 10**12))
    elif mtype == "dsl":
        result = all(eval_dsl(str(expr), resp) for expr in matcher.get("dsl", []))
    return not result if negative else result


def eval_dsl(expr: str, resp: Any) -> bool:
    body = resp.text[:100000]
    headers = {k.lower(): v for k, v in resp.headers.items()}
    allowed = {
        "status_code": resp.status_code,
        "body": body,
        "headers": headers,
        "content_length": len(resp.content),
        "contains": lambda a, b: str(b).lower() in str(a).lower(),
        "header": lambda name: headers.get(str(name).lower(), ""),
    }
    if not re.fullmatch(r"[A-Za-z0-9_ .,'\"()=!<>&|+-]+", expr):
        return False
    try:
        return bool(eval(expr, {"__builtins__": {}}, allowed))
    except Exception:
        return False


def response_part(resp: Any, part: str) -> str:
    if part == "header":
        return "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
    if part == "all":
        return response_part(resp, "header") + "\n\n" + resp.text[:100000]
    return resp.text[:100000]


def run_extractors(extractors: list[dict[str, Any]], resp: Any) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for extractor in extractors:
        name = str(extractor.get("name", extractor.get("type", "extractor")))
        part = str(extractor.get("part", "body")).lower()
        haystack = response_part(resp, part)
        if extractor.get("type") == "regex":
            values: list[str] = []
            for pattern in extractor.get("regex", []):
                values.extend(match.group(1) if match.groups() else match.group(0) for match in re.finditer(str(pattern), haystack, re.I))
            if values:
                out[name] = values[:10]
    return out


def expand_fuzzing(req: dict[str, Any], base_url: str, context: dict[str, str], interactsh_url: str | None) -> list[dict[str, Any]]:
    fuzzing = req.get("fuzzing") or []
    if not fuzzing:
        return [req]
    expanded: list[dict[str, Any]] = []
    for rule in fuzzing:
        payloads = [render_variables(str(p), base_url, context, interactsh_url) for p in rule.get("payloads", rule.get("fuzz", []))]
        if not payloads:
            continue
        part = str(rule.get("part", "query"))
        mode = str(rule.get("mode", "single"))
        ftype = str(rule.get("type", "replace"))
        for payload in payloads[:20]:
            item = dict(req)
            path = str(item.get("path", "/"))
            body = item.get("body")
            headers = dict(item.get("headers", {}))
            if part == "query":
                item["path"] = fuzz_query(path, payload, ftype, mode, rule)
            elif part == "body" and body is not None:
                item["body"] = fuzz_form(str(body), payload, ftype, mode, rule)
            elif part == "header":
                for key in rule.get("keys", []):
                    if key in headers:
                        headers[key] = apply_fuzz(str(headers[key]), payload, ftype)
                item["headers"] = headers
            expanded.append(item)
    return expanded or [req]


def fuzz_query(path: str, payload: str, ftype: str, mode: str, rule: dict[str, Any]) -> str:
    parsed = urlparse(path)
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    if not pairs:
        pairs = [(str(rule.get("key", "q")), "1")]
    keys = set(rule.get("keys", []))
    key_patterns = [re.compile(p) for p in rule.get("keys-regex", [])]
    out = []
    for key, value in pairs:
        selected = not keys and not key_patterns or key in keys or any(p.search(key) for p in key_patterns)
        out.append((key, apply_fuzz(value, payload, ftype) if selected or mode == "multiple" else value))
    return urlunparse(parsed._replace(query=urlencode(out)))


def fuzz_form(body: str, payload: str, ftype: str, mode: str, rule: dict[str, Any]) -> str:
    pairs = parse_qsl(body, keep_blank_values=True)
    keys = set(rule.get("keys", []))
    out = []
    for key, value in pairs:
        selected = not keys or key in keys
        out.append((key, apply_fuzz(value, payload, ftype) if selected or mode == "multiple" else value))
    return urlencode(out)


def apply_fuzz(value: str, payload: str, ftype: str) -> str:
    if ftype == "prefix":
        return payload + value
    if ftype == "postfix":
        return value + payload
    if ftype == "infix":
        midpoint = len(value) // 2
        return value[:midpoint] + payload + value[midpoint:]
    return payload


def load_templates(
    template_paths: list[str] | None,
    *,
    profile: str,
    severities: list[str] | None,
    tags: list[str] | None,
    template_ids: list[str] | None,
    exclude_ids: list[str] | None,
    workflow: str | None,
    ignore_file: str | None = None,
    require_signed: bool = False,
    trusted_author: list[str] | None = None,
) -> list[PulseTemplate]:
    paths = [BUILTIN_TEMPLATE_DIR]
    if COMMUNITY_TEMPLATE_DIR.exists():
        paths.append(COMMUNITY_TEMPLATE_DIR)
    if USER_TEMPLATE_DIR.exists():
        paths.append(USER_TEMPLATE_DIR)
    paths.extend(Path(p).expanduser() for p in template_paths or [])
    workflow_filters = load_workflow(workflow)
    wanted_severities = set(severities or PROFILE_SEVERITIES.get(profile, PROFILE_SEVERITIES["standard"]))
    wanted_tags = set(tags or workflow_filters.get("tags", []))
    wanted_ids = set(template_ids or workflow_filters.get("template_ids", []))
    excluded = set(exclude_ids or []) | load_ignore_patterns(ignore_file)
    trusted = set(trusted_author or [])
    templates: list[PulseTemplate] = []
    for root in paths:
        files = [root] if root.is_file() else sorted(root.rglob("*.json")) + sorted(root.rglob("*.yaml")) + sorted(root.rglob("*.yml"))
        for file in files:
            data = load_template_file(file)
            for raw in data if isinstance(data, list) else [data]:
                template = parse_template(raw, file)
                if any(fnmatch.fnmatch(template.id, pattern) for pattern in excluded):
                    continue
                if require_signed and not template.signed:
                    continue
                if trusted and template.author not in trusted:
                    continue
                if wanted_ids and template.id not in wanted_ids:
                    continue
                if template.severity not in wanted_severities:
                    continue
                if wanted_tags and not set(template.tags).intersection(wanted_tags):
                    continue
                templates.append(template)
    return list({template.id: template for template in templates}.values())


def load_template_file(path: Path) -> Any:
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() in {".yaml", ".yml"}:
        try:
            import yaml  # type: ignore
            return yaml.safe_load(text)
        except ImportError as exc:
            raise ValueError("YAML templates require PyYAML; use JSON templates or install PyYAML") from exc
    return json.loads(text)


def parse_template(raw: dict[str, Any], source: Path) -> PulseTemplate:
    info = raw.get("info", {})
    requests = normalize_requests(raw)
    source_text = source.read_text(encoding="utf-8")
    signature = info.get("signature") or raw.get("signature")
    return PulseTemplate(
        id=str(raw["id"]),
        name=str(info.get("name", raw["id"])),
        severity=str(info.get("severity", "info")).lower(),
        description=str(info.get("description", "")),
        remediation=str(info.get("remediation", "")),
        tags=normalize_list(info.get("tags", [])),
        references=normalize_list(info.get("references", info.get("reference", []))),
        cves=normalize_list(info.get("cves", (info.get("classification") or {}).get("cve-id", []))),
        classification=dict(info.get("classification", {})),
        variables=dict(raw.get("variables", {})),
        requests=requests,
        source_path=str(source),
        source_hash=hashlib.sha256(source_text.encode()).hexdigest(),
        signed=bool(signature),
        author=str(info.get("author", "")),
        protocols=sorted({str(req.get("protocol", "http")).lower() for req in requests}),
    )


def normalize_requests(raw: dict[str, Any]) -> list[dict[str, Any]]:
    if raw.get("requests"):
        requests: list[dict[str, Any]] = []
        for req in raw["requests"]:
            requests.extend(expand_raw_requests(dict(req, protocol=req.get("protocol", "http"))))
        return requests
    requests: list[dict[str, Any]] = []
    for item in raw.get("http", []):
        req = dict(item)
        req["protocol"] = "http"
        if req.get("raw"):
            requests.extend(expand_raw_requests(req))
        elif "path" in req and isinstance(req["path"], list):
            for path in req["path"]:
                copy = dict(req)
                copy["path"] = path.replace("{{BaseURL}}", "/")
                requests.append(copy)
        else:
            requests.append(req)
    for key in ("dns", "tcp", "tls", "headless"):
        for item in raw.get(key, []):
            requests.append(dict(item, protocol=key))
    return requests


def expand_raw_requests(req: dict[str, Any]) -> list[dict[str, Any]]:
    raw_items = req.get("raw")
    if not raw_items:
        return [req]
    out: list[dict[str, Any]] = []
    for raw in raw_items if isinstance(raw_items, list) else [raw_items]:
        parsed = parse_raw_http(str(raw))
        item = dict(req)
        item.pop("raw", None)
        item.update(parsed)
        out.append(item)
    return out


def parse_raw_http(raw: str) -> dict[str, Any]:
    normalized = raw.replace("\r\n", "\n")
    head, _, body = normalized.partition("\n\n")
    lines = [line for line in head.split("\n") if line.strip()]
    if not lines:
        raise ValueError("raw HTTP template request is empty")
    first = lines[0].split()
    if len(first) < 2:
        raise ValueError("raw HTTP template request must start with METHOD path HTTP/version")
    method, path = first[0].upper(), first[1]
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" in line:
            key, value = line.split(":", 1)
            if key.strip().lower() != "host":
                headers[key.strip()] = value.strip()
    return {"protocol": "http", "method": method, "path": path, "headers": headers, "body": body or None}


def normalize_list(value: Any) -> list[str]:
    if not value:
        return []
    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    return [str(item) for item in value]


def load_ignore_patterns(path: str | None) -> set[str]:
    candidates = [Path(".pulse-ignore"), USER_IGNORE]
    if path:
        candidates.append(Path(path))
    patterns: set[str] = set()
    for candidate in candidates:
        if candidate.exists():
            patterns.update(line.strip() for line in candidate.read_text(encoding="utf-8").splitlines() if line.strip() and not line.strip().startswith("#"))
    return patterns


def load_workflow(path: str | None) -> dict[str, list[str]]:
    if not path:
        return {}
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return {"tags": normalize_list(data.get("tags", [])), "template_ids": normalize_list(data.get("template_ids", []))}


def load_auth_profile(path: str | None) -> tuple[dict[str, str], str | None]:
    if not path:
        return {}, None
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return dict(data.get("headers", {})), data.get("cookie")


def normalize_target(target: str) -> str:
    return target if urlparse(target).scheme else f"https://{target.rstrip('/')}/"


def build_context(base_url: str, variables: dict[str, Any], interactsh_url: str | None) -> dict[str, str]:
    parsed = urlparse(base_url)
    context = {
        "BaseURL": base_url.rstrip("/"),
        "Hostname": parsed.hostname or "",
        "Host": parsed.netloc,
        "Scheme": parsed.scheme,
        "interactsh-url": interactsh_url or "oast.invalid",
    }
    for key, value in variables.items():
        context[str(key)] = render_helper(str(value), context)
    return context


def render_variables(value: str, base_url: str, context: dict[str, str] | None = None, interactsh_url: str | None = None) -> str:
    ctx = context or build_context(base_url, {}, interactsh_url)
    for key, val in ctx.items():
        value = value.replace("{{" + key + "}}", val)
    return render_helper(value, ctx)


def render_helper(value: str, context: dict[str, str]) -> str:
    def repl(match: re.Match[str]) -> str:
        expr = match.group(1).strip()
        if expr.startswith("base64("):
            import base64
            inner = expr[7:-1].strip("'\"")
            return base64.b64encode(inner.encode()).decode()
        if expr.startswith("lower("):
            return expr[6:-1].strip("'\"").lower()
        if expr.startswith("upper("):
            return expr[6:-1].strip("'\"").upper()
        if expr == "rand_int()":
            return str(int(time.time() * 1000) % 100000)
        return context.get(expr, match.group(0))
    return re.sub(r"{{\s*([^{}]+)\s*}}", repl, value)


def parse_headers(values: Iterable[str] | None) -> dict[str, str]:
    headers: dict[str, str] = {}
    for item in values or []:
        if ":" not in item:
            raise ValueError(f"invalid header {item!r}; use 'Name: value'")
        key, value = item.split(":", 1)
        headers[key.strip()] = value.strip()
    return headers


def parse_targets_file(path: str | None) -> list[str]:
    if not path:
        return []
    return [line.strip() for line in Path(path).read_text(encoding="utf-8").splitlines() if line.strip() and not line.strip().startswith("#")]


def dedupe_findings(findings: list[PulseFinding]) -> list[PulseFinding]:
    seen: set[str] = set()
    out: list[PulseFinding] = []
    for finding in findings:
        key = f"{finding.template_id}|{finding.url}"
        if key in seen:
            continue
        seen.add(key)
        out.append(finding)
    return out


def _cache_path(cache_dir: str | None, target: str) -> Path | None:
    if not cache_dir:
        return None
    digest = hashlib.sha256(target.encode()).hexdigest()[:16]
    return Path(cache_dir).expanduser() / f"{digest}.json"


def update_templates(source: str | None, destination: str | None) -> Path:
    dest = Path(destination).expanduser() if destination else USER_TEMPLATE_DIR
    dest.mkdir(parents=True, exist_ok=True)
    if not source:
        shutil.copytree(BUILTIN_TEMPLATE_DIR, dest, dirs_exist_ok=True)
        return dest
    if source.startswith(("http://", "https://")):
        data = httpx.get(source, timeout=15.0, follow_redirects=True).text
        parsed = json.loads(data)
        (dest / "remote.json").write_text(json.dumps(parsed, indent=2), encoding="utf-8")
        return dest
    src = Path(source).expanduser()
    if src.is_dir():
        shutil.copytree(src, dest, dirs_exist_ok=True)
    else:
        shutil.copyfile(src, dest / src.name)
    return dest


def render_results(results: list[PulseResult], fmt: str) -> str:
    if fmt == "json":
        return json.dumps([asdict(result) for result in results], indent=2)
    if fmt == "jsonl":
        return "\n".join(json.dumps(asdict(finding), sort_keys=True) for result in results for finding in result.findings)
    if fmt == "csv":
        out = StringIO()
        writer = csv.DictWriter(out, fieldnames=["template_id", "name", "severity", "url", "matcher", "evidence", "status_code", "tags", "references", "cves"], extrasaction="ignore")
        writer.writeheader()
        for result in results:
            for finding in result.findings:
                writer.writerow(asdict(finding))
        return out.getvalue().rstrip()
    if fmt == "html":
        rows = []
        for result in results:
            for finding in result.findings:
                rows.append("<tr>" + "".join(f"<td>{html.escape(str(value))}</td>" for value in [result.target, finding.severity, finding.template_id, finding.name, finding.url, finding.evidence]) + "</tr>")
        return "<!doctype html><html><body><h1>Pencheff Pulse</h1><table><tr><th>Target</th><th>Severity</th><th>ID</th><th>Name</th><th>URL</th><th>Evidence</th></tr>" + "".join(rows) + "</table></body></html>"
    if fmt == "xml":
        lines = ['<?xml version="1.0" encoding="UTF-8"?>', "<pulse>"]
        for result in results:
            lines.append(f'  <target url="{html.escape(result.target)}">')
            for finding in result.findings:
                lines.append(f'    <finding id="{html.escape(finding.template_id)}" severity="{html.escape(finding.severity)}"><name>{html.escape(finding.name)}</name><url>{html.escape(finding.url)}</url><evidence>{html.escape(finding.evidence)}</evidence></finding>')
            lines.append("  </target>")
        lines.append("</pulse>")
        return "\n".join(lines)
    lines = []
    for result in results:
        lines.append(f"Scanned {result.target}: {len(result.findings)} findings, {result.requests_sent} requests, {result.templates_loaded} templates")
        for finding in result.findings:
            lines.append(f"{finding.severity.upper():8} {finding.template_id:28} {finding.name}  {finding.url}")
    return "\n".join(lines)


async def run_cli(args) -> int:
    try:
        if args.update_templates:
            path = update_templates(args.update_source, args.update_destination)
            print(f"Updated pulse templates: {path}")
            return 0
        targets = list(args.target or []) + parse_targets_file(args.targets_file)
        if not targets:
            raise ValueError("at least one --target or --targets-file entry is required")
        results = await scan(
            targets,
            template_paths=args.templates,
            profile=args.profile,
            severities=args.severity,
            tags=args.tag,
            template_ids=args.template_id,
            exclude_ids=args.exclude_id,
            workflow=args.workflow,
            headers=parse_headers(args.header),
            cookie=args.cookie,
            auth_profile=args.auth_profile,
            proxy=args.proxy,
            timeout=args.timeout,
            concurrency=args.concurrency,
            rate_limit=args.rate_limit,
            verify_ssl=args.verify_ssl,
            ignore_file=args.ignore_file,
            require_signed=args.require_signed,
            trusted_author=args.trusted_author,
            cache_dir=args.cache_dir,
            resume=args.resume,
            retries=args.retries,
            max_host_errors=args.max_host_errors,
            stats_file=args.stats_file,
            interactsh_url=args.interactsh_url,
            headless=args.headless,
        )
        print(render_results(results, args.format))
    except (ValueError, OSError, httpx.HTTPError) as exc:
        print(f"pencheff pulse: {exc}", file=sys.stderr)
        return 2
    return 0
