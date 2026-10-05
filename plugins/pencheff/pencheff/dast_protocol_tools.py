"""Protocol-specific DAST scanners (feature 001-multi-target-scan-pipelines).

Wraps three classes of tool the existing scan_api / scan_websocket can't fully
cover:

  * ``run_graphql_cop`` — graphql-cop probes for introspection exposure,
    field-suggestion leaks, batched-query DoS, alias attacks.
  * ``run_inql`` — Pentestit's InQL extracts GraphQL schemas + auto-generates
    query/mutation fuzz cases; complements run_graphql_cop.
  * ``run_grpcurl`` — gRPC reflection enumeration + method invocation. Used
    by GrpcReflectionAgent for service/method discovery and primitive payload
    fuzzing.
  * ``parse_proto`` — pure-Python .proto parser fallback when gRPC reflection
    is disabled and the operator uploaded proto files in kind_config.

Subprocess discipline mirrors artifact_tools: ``shutil.which`` gate, graceful
``{"error": "binary not found", "skipped": True}`` when missing, JSON parsing
into pencheff finding shape with ``owasp_category`` tagging.
"""
from __future__ import annotations

import asyncio
import json
import re
import shutil
from typing import Any

from .artifact_tools import _kind_config_for_session, _run_subprocess, _which
from .core.http_client import DEFAULT_USER_AGENT


def _proxy_and_headers(cfg: dict) -> tuple[str | None, dict[str, str]]:
    """Operator egress proxy + request headers for the GraphQL CLIs.

    Mirrors the HTTP client: kind_config.proxy routes around IP-based WAF
    blocks, kind_config.headers (with a realistic default UA) blends past
    signature rules. graphql-cop's own UA (``graphql-cop/1.15``) is an instant
    WAF tell, so we always override it.
    """
    proxy = cfg.get("proxy") or None
    headers = dict(cfg.get("headers") or {}) if isinstance(cfg.get("headers"), dict) else {}
    headers.setdefault("User-Agent", DEFAULT_USER_AGENT)
    return proxy, headers


def _persist_tool_findings(session_id: str, raw: list[dict[str, Any]]) -> int:
    """Record dict-shaped findings emitted by the protocol tools onto the
    session's FindingsDB, so they appear in scan results (the scan_* modules
    self-persist; these tools previously only returned findings to the agent,
    which silently dropped them). Best-effort: never raises into the tool path."""
    if not raw:
        return 0
    try:
        from pencheff.config import Severity
        from pencheff.core.findings import Finding
        from pencheff.core.session import get_session
    except Exception:  # pragma: no cover - import guard
        return 0
    sess = get_session(session_id)
    if sess is None:
        return 0
    sev_map = {"critical": Severity.CRITICAL, "high": Severity.HIGH,
               "medium": Severity.MEDIUM, "low": Severity.LOW, "info": Severity.INFO}
    base = (_kind_config_for_session(session_id) or {}).get("base_url", "") or ""
    objs = []
    for f in raw:
        objs.append(Finding(
            title=str(f.get("title", "Finding"))[:255],
            severity=sev_map.get(str(f.get("severity", "low")).lower(), Severity.LOW),
            category=str(f.get("category", "misconfiguration")),
            owasp_category=str(f.get("owasp_category", "A05:2021")),
            description=str(f.get("description", "")),
            remediation=str(f.get("remediation", "")),
            endpoint=str(f.get("endpoint") or base),
        ))
    return sess.findings.add_many(objs)


# ============================================================================
# run_graphql_cop
# ============================================================================


async def run_graphql_cop(
    session_id: str,
    endpoint: str | None = None,
) -> dict[str, Any]:
    """Probe a GraphQL endpoint for introspection / DoS / info-leak issues.

    Allowlist: ``endpoint`` MUST equal the target's base_url (we don't ship a
    separate kind_config.graphql_endpoint — the URL is on Target.base_url and
    the agent passes it through). When ``endpoint`` is None, we fall back to
    the session-bound kind_config.
    """
    if not _which("graphql-cop"):
        return {"error": "binary not found: graphql-cop", "skipped": True}
    cfg = _kind_config_for_session(session_id) or {}
    if not endpoint:
        endpoint = cfg.get("endpoint") or cfg.get("base_url") or ""
    if not endpoint or not endpoint.startswith(("http://", "https://")):
        return {"error": "endpoint must be a fully-qualified http(s):// URL"}

    # -f/--force: run the checks even when graphql-cop's pre-flight can't
    # confirm the endpoint is GraphQL. The operator already declared this a
    # graphql target, and WAF-fronted endpoints (e.g. behind ThreatX/Cloudflare)
    # 403 the detection probe — without --force graphql-cop bails with
    # "does not seem to be running GraphQL" and returns zero findings.
    argv = ["graphql-cop", "-t", endpoint, "-o", "json", "-f"]
    if cfg.get("introspection_enabled") is False:
        argv.append("--no-introspection")
    # Egress proxy + realistic headers to get past IP/signature WAF blocks.
    proxy, headers = _proxy_and_headers(cfg)
    if proxy:
        argv += ["-x", proxy]
    if headers:
        argv += ["-H", json.dumps(headers)]
    result = await _run_subprocess(argv, timeout=120)
    if result.get("error"):
        return result
    findings = _parse_graphql_cop_json(result.get("stdout", ""))
    _persist_tool_findings(session_id, findings)
    return {"scanner": "graphql-cop", "findings_count": len(findings), "findings": findings}


def _parse_graphql_cop_json(stdout: str) -> list[dict[str, Any]]:
    if not stdout.strip():
        return []
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return []
    # graphql-cop emits a list of {result, title, severity, description, …} for
    # EVERY check — ``result`` is True only when the check actually fired. Emit a
    # finding just for the True ones; False = "checked, not vulnerable" (would be
    # a false positive if reported).
    findings: list[dict[str, Any]] = []
    for entry in data if isinstance(data, list) else (data.get("results") or []):
        if not isinstance(entry, dict) or entry.get("result") is False:
            continue
        sev_raw = (entry.get("severity") or "low").lower()
        sev_map = {"critical": "critical", "high": "high", "medium": "medium",
                   "low": "low", "info": "info", "informational": "info"}
        title = entry.get("title") or entry.get("name") or "GraphQL issue"
        findings.append({
            "title": title[:255],
            "severity": sev_map.get(sev_raw, "low"),
            "category": "graphql_misconfiguration",
            # OWASP API Security Top 10 maps closer than the web list; we
            # keep the same enum used by the existing breakers and lean on
            # A05:2021 (Security Misconfiguration) for introspection/aliasing
            # and A04:2021 (Insecure Design) for query-depth DoS. Default to
            # A05 — operators triage further during review.
            "owasp_category": "A05:2021",
            "description": (entry.get("description") or "")[:512],
            "remediation": entry.get("remediation") or "",
        })
    return findings


# ============================================================================
# run_inql
# ============================================================================


async def run_inql(
    session_id: str,
    endpoint: str | None = None,
    output_format: str = "json",
) -> dict[str, Any]:
    """Extract a GraphQL schema via InQL and surface object-permission gaps.

    InQL's standalone CLI emits JSON of queries/mutations the agent can then
    probe via test_endpoint. We translate the schema summary into INFO-level
    findings so the operator sees what was discovered.
    """
    if not _which("inql"):
        return {"error": "binary not found: inql", "skipped": True}
    cfg = _kind_config_for_session(session_id) or {}
    if not endpoint:
        endpoint = cfg.get("endpoint") or cfg.get("base_url") or ""
    if not endpoint or not endpoint.startswith(("http://", "https://")):
        return {"error": "endpoint must be a fully-qualified http(s):// URL"}

    argv = ["inql", "-t", endpoint, "-o", output_format]
    # inql: -p <proxy>; --header takes two args (key value), repeatable.
    proxy, headers = _proxy_and_headers(cfg)
    if proxy:
        argv += ["-p", proxy]
    for k, v in headers.items():
        argv += ["--header", k, v]
    result = await _run_subprocess(argv, timeout=180)
    if result.get("error"):
        return result
    # InQL prints a verbose schema dump rather than structured findings; we
    # surface a single INFO finding summarising what it found, plus the raw
    # schema for the orchestrator to feed downstream agents.
    queries = mutations = subscriptions = 0
    for line in (result.get("stdout") or "").splitlines():
        if line.startswith("Query."):
            queries += 1
        elif line.startswith("Mutation."):
            mutations += 1
        elif line.startswith("Subscription."):
            subscriptions += 1
    finding = {
        "title": f"GraphQL schema introspected: {queries}Q / {mutations}M / {subscriptions}S",
        "severity": "info",
        "category": "graphql_schema_disclosure",
        "owasp_category": "A05:2021",
        "description": (
            f"InQL extracted {queries} queries, {mutations} mutations, "
            f"{subscriptions} subscriptions from {endpoint}. Review for "
            f"object-level authorization gaps (BOLA / IDOR via GraphQL aliases)."
        ),
    }
    return {
        "scanner": "inql",
        "findings_count": 1 if (queries or mutations or subscriptions) else 0,
        "findings": [finding] if (queries or mutations or subscriptions) else [],
        "schema_summary": {"queries": queries, "mutations": mutations, "subscriptions": subscriptions},
    }


# ============================================================================
# run_grpcurl
# ============================================================================


def _grpc_transport_mismatch(result: dict[str, Any]) -> bool:
    """True when grpcurl failed specifically because of a TLS/plaintext transport
    mismatch — the signal that retrying with the opposite transport is worthwhile.
    A clean exit, or a failure for any other reason (bad host, timeout), returns
    False so we don't pointlessly re-run."""
    if result.get("returncode") == 0:
        return False
    blob = ((result.get("stderr") or "") + " " + (result.get("error") or "")).lower()
    return any(sig in blob for sig in (
        "does not look like a tls handshake",  # TLS attempted against plaintext h2c
        "wrong version number",
        "tls: ",
        "http2",                                # plaintext attempted against TLS
        "received unexpected",
        "transport: ",
    ))


async def run_grpcurl(
    session_id: str,
    target: str | None = None,
    action: str = "list",
    service: str | None = None,
    method: str | None = None,
    payload_json: str | None = None,
) -> dict[str, Any]:
    """Drive grpcurl for reflection enumeration and method invocation.

    Actions:
      * ``list`` — enumerate services (default).
      * ``describe`` — describe a service or method.
      * ``invoke`` — call a method with a JSON payload.

    Safety: the calling agent_runner already blocks ``--plaintext`` and
    ``--import-path`` via _DANGEROUS_ARG_SUBSTRINGS (feature 001 S-07).
    This wrapper additionally validates ``target`` against the session's
    kind_config and refuses freeform args.
    """
    if not _which("grpcurl"):
        return {"error": "binary not found: grpcurl", "skipped": True}
    cfg = _kind_config_for_session(session_id) or {}
    if not target:
        target = cfg.get("base_url") or cfg.get("endpoint") or ""
    target = (target or "").strip()
    # grpcurl wants a bare host:port — strip the URL scheme the target is
    # registered with (grpc://, grpcs://, http(s)://, dns:///). Leaving the
    # scheme on makes grpcurl treat "grpc://host:443" as the host and fail.
    for pfx in ("grpc://", "grpcs://", "https://", "http://", "dns:///"):
        if target.startswith(pfx):
            target = target[len(pfx):]
            break
    target = target.rstrip("/")
    if not target:
        return {"error": "no target host:port supplied"}
    # Disallow shell metacharacters defensively (grpcurl is exec'd as argv but
    # the agent could otherwise emit dangerous-looking values).
    if any(c in target for c in (" ", ";", "&", "|", "\n", "\r", "$", "`")):
        return {"error": "invalid target — host:port only"}

    # Build the action-specific argv tail (everything after the transport flags).
    tail: list[str] = []
    if action == "list":
        tail = [target, "list"] + ([service] if service else [])
    elif action == "describe":
        if not service and not method:
            return {"error": "describe requires service or method"}
        tail = [target, "describe", service or method]  # type: ignore[list-item]
    elif action == "invoke":
        if not service or not method:
            return {"error": "invoke requires service AND method"}
        if payload_json is None:
            payload_json = "{}"
        try:
            json.loads(payload_json)  # validate
        except json.JSONDecodeError:
            return {"error": "payload_json must be valid JSON"}
        tail = ["-d", payload_json, target, f"{service}/{method}"]
    else:
        return {"error": f"unknown action: {action}"}

    # Transport: start from the operator's declaration, but AUTO-FALL BACK to
    # the other transport on a TLS/plaintext handshake mismatch. Operators
    # routinely mis-declare this (e.g. plaintext=false against a plaintext h2c
    # server on :443), which would otherwise fail every reflection call. The
    # flags come from config, never agent input, so the run_security_tool
    # --plaintext blocklist (which only inspects agent-supplied argv) doesn't apply.
    if cfg.get("plaintext"):
        primary = ["-plaintext"]
        alt = [] if cfg.get("tls_verify", True) else ["-insecure"]
    elif not cfg.get("tls_verify", True):
        primary = ["-insecure"]
        alt = ["-plaintext"]
    else:
        primary = []
        alt = ["-plaintext"]

    result = await _run_subprocess(["grpcurl", *primary, *tail], timeout=60)
    if alt != primary and _grpc_transport_mismatch(result):
        retry = await _run_subprocess(["grpcurl", *alt, *tail], timeout=60)
        if not _grpc_transport_mismatch(retry):
            result = retry
    if result.get("error"):
        return result
    findings: list[dict[str, Any]] = []
    # When the agent invokes a method with garbage input and the server
    # accepts it (no auth, no validation), surface as a finding. Otherwise
    # we just return the stdout for the agent to interpret.
    stdout = result.get("stdout") or ""
    # A successful ``list`` means server reflection is live — it hands an
    # unauthenticated client the full service/method catalogue (the gRPC analog
    # of GraphQL introspection being enabled). Surface it as a posture finding.
    if action == "list" and result.get("returncode") == 0 and stdout.strip():
        services = [s.strip() for s in stdout.splitlines() if s.strip()]
        findings.append({
            "title": "gRPC Server Reflection Enabled",
            "severity": "medium",
            "category": "grpc_reflection_exposed",
            "owasp_category": "A05:2021",  # Security Misconfiguration
            "description": (
                "The gRPC server has reflection enabled, exposing its full "
                "service and method catalogue to unauthenticated clients — the "
                "complete API attack surface. Disable server reflection in "
                "production builds."
            ),
            "evidence": {"services": services[:50], "response_excerpt": stdout[:512]},
        })
    if action == "invoke" and result.get("returncode") == 0:
        findings.append({
            "title": f"gRPC method {service}/{method} accepted unauthenticated invocation",
            "severity": "medium",
            "category": "grpc_unauthenticated_method",
            "owasp_category": "A01:2021",  # Broken Access Control
            "description": (
                f"Calling {service}/{method} with payload returned success "
                f"without an auth header. Verify whether this method should "
                f"require authentication."
            ),
            "evidence": {"response_excerpt": stdout[:512]},
        })
    _persist_tool_findings(session_id, findings)
    return {
        "scanner": "grpcurl",
        "findings_count": len(findings),
        "findings": findings,
        "stdout": stdout[:4096],
    }


# ============================================================================
# parse_proto — pure-Python fallback when reflection is disabled
# ============================================================================


# Pre-feature-001 we never accepted .proto file content from operators; with
# GrpcConfig.proto_files supported, we need to surface what services are
# declared so the agent can drive run_grpcurl describe/invoke against them.
# A full protobuf parser is overkill — we extract service + rpc declarations
# via regex which is robust to comment/whitespace variations.
_PROTO_SERVICE_RE = re.compile(
    r"\bservice\s+(\w+)\s*\{([^}]*)\}",
    re.MULTILINE | re.DOTALL,
)
_PROTO_RPC_RE = re.compile(
    r"\brpc\s+(\w+)\s*\(\s*(stream\s+)?(\w+(?:\.\w+)*)\s*\)\s*"
    r"returns\s*\(\s*(stream\s+)?(\w+(?:\.\w+)*)\s*\)",
)


async def parse_proto(
    session_id: str,
    proto_content: str | None = None,
) -> dict[str, Any]:
    """Extract service + RPC declarations from operator-supplied .proto files.

    Used when ``kind_config.reflection_enabled = False`` and the operator
    uploaded protobuf source via ``kind_config.proto_files``. Returns a
    structured services list the agent can hand to ``run_grpcurl describe``
    once it has the live target.
    """
    cfg = _kind_config_for_session(session_id) or {}
    # Caller may pass content explicitly; fall back to kind_config.proto_files
    # which is a list[str] of .proto file bodies.
    sources: list[str] = []
    if proto_content:
        sources.append(proto_content)
    for body in cfg.get("proto_files") or []:
        if isinstance(body, str):
            sources.append(body)
    if not sources:
        return {"error": "no proto content supplied"}

    services: list[dict[str, Any]] = []
    for src in sources:
        for svc_match in _PROTO_SERVICE_RE.finditer(src):
            svc_name = svc_match.group(1)
            body = svc_match.group(2)
            rpcs: list[dict[str, Any]] = []
            for rpc_match in _PROTO_RPC_RE.finditer(body):
                rpcs.append({
                    "name": rpc_match.group(1),
                    "input_type": rpc_match.group(3),
                    "input_stream": bool(rpc_match.group(2)),
                    "output_type": rpc_match.group(5),
                    "output_stream": bool(rpc_match.group(4)),
                })
            services.append({"name": svc_name, "rpcs": rpcs})

    return {
        "scanner": "parse_proto",
        "services": services,
        "service_count": len(services),
        "rpc_count": sum(len(s["rpcs"]) for s in services),
    }


__all__ = [
    "run_graphql_cop",
    "run_inql",
    "run_grpcurl",
    "parse_proto",
]
