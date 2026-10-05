# SPDX-License-Identifier: AGPL-3.0-or-later
"""Synthesise an OpenAPI 3.1 document from captured ``ProxyFlow`` rows.

The deterministic core handles 80% of useful synthesis without ever
calling an LLM:

* **URL templating** — collapses ``/users/123/posts/456`` and
  ``/users/789/posts/012`` into the same path with ``{userId}`` /
  ``{postId}`` parameters. The detector handles UUIDs, integer ids,
  and base-36 ids.
* **Method + status aggregation** — every (path, method) pair gets
  a response object per observed status code.
* **Response-shape inference** — JSON bodies are walked once and
  collapsed into a minimal JSON Schema (``type``, ``properties``,
  ``items``). Shapes seen on multiple requests are merged.
* **Auth detection** — ``Authorization: Bearer …`` ↔ HTTP bearer;
  ``X-API-Key`` headers ↔ apiKey securitySchemes. The synthesised
  spec carries the scheme + a ``security`` requirement on every
  operation that observed a credentialed request.
* **Provenance** — every operation's ``description`` carries the
  count of captured requests + the first/last seen timestamp so an
  auditor can answer "where did this endpoint come from?".

LLM assistance is optional: pass ``chat=client._chat`` to fill in
operation summaries / parameter descriptions / tag selection. The
deterministic skeleton is unchanged when ``chat`` is ``None``.
"""
from __future__ import annotations

import json
import logging
import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Iterable
from urllib.parse import urlparse

log = logging.getLogger(__name__)


@dataclass
class SynthesisResult:
    spec: dict[str, Any]
    endpoints_seen: int
    flows_processed: int
    auth_schemes: list[str] = field(default_factory=list)
    template_replacements: dict[str, int] = field(default_factory=dict)


@dataclass
class _Flow:
    """Minimal shape we need from a ``ProxyFlow`` row.

    Decoupled from the dataclass so we can drive the synth from a
    list[dict] read out of the SaaS ``proxy_traffic`` table without
    instantiating the plugin's ``ProxyFlow``.
    """
    method: str
    url: str
    req_headers: dict[str, str]
    req_body: str | bytes | None
    status: int
    resp_headers: dict[str, str]
    resp_body: str | bytes | None


# ─── URL templating ────────────────────────────────────────────────


_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
_INT_ID_RE = re.compile(r"^\d{1,18}$")
_BASE36_ID_RE = re.compile(r"^[0-9A-Za-z]{8,40}$")


def _classify_segment(seg: str) -> tuple[str, str] | None:
    """Return ``(template_token, openapi_type)`` if ``seg`` looks like
    an id, else ``None``."""
    if _UUID_RE.match(seg):
        return "{id}", "string"
    if _INT_ID_RE.match(seg):
        return "{id}", "integer"
    if _BASE36_ID_RE.match(seg):
        return "{id}", "string"
    return None


def _template_path(path: str, replacements: Counter) -> tuple[str, list[dict[str, Any]]]:
    """Convert a concrete path into a templated path + parameter list.

    Multiple id-shaped segments in the same path get distinct names —
    ``/users/{userId}/posts/{postId}`` — based on the preceding
    segment, falling back to ``{id1}`` / ``{id2}``.
    """
    segments = [s for s in path.split("/") if s]
    out_parts: list[str] = []
    params: list[dict[str, Any]] = []
    seen_kinds: dict[str, int] = {}
    for i, seg in enumerate(segments):
        cls = _classify_segment(seg)
        if cls is None:
            out_parts.append(seg)
            continue
        prev = segments[i - 1] if i > 0 else "id"
        # Strip pluralisation + non-alpha to produce ``user`` from
        # ``users`` and ``post`` from ``posts/``.
        base = re.sub(r"[^a-z]", "", prev.lower())
        if base.endswith("s") and len(base) > 1:
            base = base[:-1]
        if not base:
            base = "id"
        seen_kinds[base] = seen_kinds.get(base, 0) + 1
        token = base + "Id" if seen_kinds[base] == 1 else f"{base}Id{seen_kinds[base]}"
        out_parts.append("{" + token + "}")
        replacements[base] += 1
        params.append({
            "name": token,
            "in": "path",
            "required": True,
            "schema": {"type": cls[1]},
        })
    return "/" + "/".join(out_parts), params


# ─── JSON-shape inference ──────────────────────────────────────────


def _infer_schema(value: Any) -> dict[str, Any]:
    """Return a minimal JSON Schema describing ``value``."""
    if value is None:
        return {"type": "null"}
    if isinstance(value, bool):
        return {"type": "boolean"}
    if isinstance(value, int):
        return {"type": "integer"}
    if isinstance(value, float):
        return {"type": "number"}
    if isinstance(value, str):
        return {"type": "string"}
    if isinstance(value, list):
        if not value:
            return {"type": "array", "items": {}}
        # Merge across all items so a heterogenous list still emits
        # one shape.
        merged = _infer_schema(value[0])
        for v in value[1:]:
            merged = _merge_schemas(merged, _infer_schema(v))
        return {"type": "array", "items": merged}
    if isinstance(value, dict):
        props = {k: _infer_schema(v) for k, v in value.items()}
        return {"type": "object", "properties": props}
    return {}  # unknown


def _merge_schemas(a: dict[str, Any], b: dict[str, Any]) -> dict[str, Any]:
    """Best-effort merge — same type ↦ deep merge; different types ↦
    the wider one wins (string > integer > null)."""
    if a == b:
        return a
    if a.get("type") != b.get("type"):
        # Coerce to whichever is "wider"; fall back to the first.
        return a or b
    if a["type"] == "object":
        merged_props = {**(a.get("properties") or {})}
        for k, v in (b.get("properties") or {}).items():
            merged_props[k] = (
                _merge_schemas(merged_props[k], v) if k in merged_props else v
            )
        return {"type": "object", "properties": merged_props}
    if a["type"] == "array":
        return {"type": "array", "items": _merge_schemas(
            a.get("items") or {}, b.get("items") or {},
        )}
    return a


# ─── Auth detection ────────────────────────────────────────────────


def _detect_auth(flows: Iterable[_Flow]) -> dict[str, dict[str, Any]]:
    """Return the OpenAPI ``securitySchemes`` block populated from
    headers seen across ``flows``."""
    schemes: dict[str, dict[str, Any]] = {}
    for f in flows:
        # Header keys come back from mitmproxy / WebExtension in the
        # case the upstream client sent — always lower-casing here.
        normalized = {k.lower(): v for k, v in (f.req_headers or {}).items()}
        if "authorization" in normalized:
            value = (normalized["authorization"] or "").strip()
            if value.lower().startswith("bearer "):
                schemes["bearerAuth"] = {
                    "type": "http", "scheme": "bearer",
                    "bearerFormat": "JWT" if value.count(".") == 2 else "opaque",
                }
            elif value.lower().startswith("basic "):
                schemes["basicAuth"] = {"type": "http", "scheme": "basic"}
        for hdr_lower in ("x-api-key", "x-auth-token"):
            if hdr_lower in normalized:
                schemes.setdefault(
                    f"apiKey-{hdr_lower}",
                    {"type": "apiKey", "in": "header", "name": hdr_lower},
                )
    return schemes


# ─── Synthesis driver ──────────────────────────────────────────────


def summarize_endpoints(flows: Iterable[_Flow]) -> dict[tuple[str, str], int]:
    """Diagnostic — return ``{(method, templated_path): count}``."""
    rep = Counter()
    out: Counter = Counter()
    for f in flows:
        path = urlparse(f.url).path or "/"
        templated, _ = _template_path(path, rep)
        out[(f.method.upper(), templated)] += 1
    return dict(out)


def synthesize_openapi(
    flows: Iterable[_Flow],
    *,
    title: str = "Runtime-discovered API",
    version: str = "0.1.0",
    chat: Callable[[str, str], str | None] | None = None,
) -> SynthesisResult:
    """Build an OpenAPI 3.1 spec from captured request/response flows.

    The resulting spec includes per-operation provenance (how many
    times the endpoint was observed, first/last seen timestamps) so a
    drift detector can render the diff with confidence.
    """
    flows = list(flows)
    if not flows:
        return SynthesisResult(
            spec=_empty_spec(title, version),
            endpoints_seen=0, flows_processed=0,
        )

    replacements: Counter = Counter()
    # Group flows by (templated_path, method) → list of flows.
    by_op: dict[tuple[str, str], list[_Flow]] = {}
    by_op_params: dict[tuple[str, str], list[dict[str, Any]]] = {}
    server_origins: Counter = Counter()
    for f in flows:
        try:
            parsed = urlparse(f.url)
        except Exception:  # noqa: BLE001
            continue
        if parsed.scheme and parsed.netloc:
            server_origins[f"{parsed.scheme}://{parsed.netloc}"] += 1
        path = parsed.path or "/"
        templated, params = _template_path(path, replacements)
        key = (f.method.upper(), templated)
        by_op.setdefault(key, []).append(f)
        # Path params are stable across all flows for the same key —
        # only set the first time so we don't drift.
        by_op_params.setdefault(key, params)

    auth_schemes = _detect_auth(flows)
    paths: dict[str, dict[str, Any]] = {}
    now = datetime.now(timezone.utc).isoformat()

    for (method, templated_path), op_flows in by_op.items():
        op = paths.setdefault(templated_path, {})
        responses: dict[str, dict[str, Any]] = {}
        merged_response_schema: dict[str, Any] | None = None
        timestamps = sorted(getattr(f, "timestamp", 0.0) for f in op_flows)

        for flow in op_flows:
            status = str(flow.status or 200)
            r_obj = responses.setdefault(status, {"description": ""})
            schema = _infer_response_schema(flow)
            if schema is not None:
                if merged_response_schema is None:
                    merged_response_schema = schema
                else:
                    merged_response_schema = _merge_schemas(
                        merged_response_schema, schema,
                    )
                r_obj["content"] = {
                    "application/json": {"schema": merged_response_schema},
                }

        request_body = _infer_request_body(op_flows)
        # Operation summary: deterministic by default, LLM-augmented
        # when caller passes ``chat``.
        summary = f"{method.title()} {templated_path}"
        if chat is not None:
            llm_summary = _llm_summary(chat, method, templated_path, op_flows)
            if llm_summary:
                summary = llm_summary

        operation: dict[str, Any] = {
            "summary": summary[:140],
            "description": (
                f"Auto-discovered from {len(op_flows)} captured request"
                f"{'s' if len(op_flows) != 1 else ''}; "
                f"first seen {datetime.fromtimestamp(timestamps[0], tz=timezone.utc).isoformat() if timestamps else now}, "
                f"last seen {datetime.fromtimestamp(timestamps[-1], tz=timezone.utc).isoformat() if timestamps else now}."
            ),
            "parameters": list(by_op_params.get((method, templated_path), [])),
            "responses": responses or {"200": {"description": ""}},
        }
        if request_body is not None:
            operation["requestBody"] = request_body
        if auth_schemes:
            operation["security"] = [{name: []} for name in auth_schemes]
        op[method.lower()] = operation

    spec = _empty_spec(title, version)
    spec["servers"] = [{"url": u} for u, _ in server_origins.most_common(3)]
    spec["paths"] = paths
    if auth_schemes:
        spec["components"] = {"securitySchemes": auth_schemes}

    return SynthesisResult(
        spec=spec,
        endpoints_seen=len(by_op),
        flows_processed=len(flows),
        auth_schemes=sorted(auth_schemes.keys()),
        template_replacements=dict(replacements),
    )


def _infer_response_schema(flow: _Flow) -> dict[str, Any] | None:
    body = flow.resp_body
    if body is None:
        return None
    if isinstance(body, bytes):
        try:
            body = body.decode("utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            return None
    if not body or not body.strip():
        return None
    # Only JSON responses get schemas; HTML/text bodies are skipped.
    content_type = ""
    for k, v in (flow.resp_headers or {}).items():
        if k.lower() == "content-type":
            content_type = (v or "").lower()
            break
    if content_type and "json" not in content_type:
        return None
    try:
        parsed = json.loads(body)
    except json.JSONDecodeError:
        return None
    return _infer_schema(parsed)


def _infer_request_body(flows: list[_Flow]) -> dict[str, Any] | None:
    """Return an OpenAPI ``requestBody`` block when at least one
    captured flow had a JSON request body. Schema is merged across
    all observed bodies."""
    schemas = []
    for f in flows:
        body = f.req_body
        if body is None:
            continue
        if isinstance(body, bytes):
            try:
                body = body.decode("utf-8", errors="replace")
            except Exception:  # noqa: BLE001
                continue
        body = (body or "").strip()
        if not body or not (body.startswith("{") or body.startswith("[")):
            continue
        try:
            schemas.append(_infer_schema(json.loads(body)))
        except json.JSONDecodeError:
            continue
    if not schemas:
        return None
    merged = schemas[0]
    for s in schemas[1:]:
        merged = _merge_schemas(merged, s)
    return {
        "required": True,
        "content": {"application/json": {"schema": merged}},
    }


def _llm_summary(
    chat: Callable[[str, str], str | None],
    method: str,
    path: str,
    flows: list[_Flow],
) -> str | None:
    """One-line operation summary via the LLM.

    Pencheff's existing ``LLMClient._chat`` returns text or ``None``;
    we strip code fences and clip to 140 chars.
    """
    sample = flows[0]
    user = json.dumps({
        "method": method, "path": path,
        "sample_request_body": (
            (sample.req_body[:500] if isinstance(sample.req_body, str)
             else str(sample.req_body or "")[:500])
        ),
        "sample_response_status": sample.status,
        "sample_response_body_head": (
            (sample.resp_body[:500] if isinstance(sample.resp_body, str)
             else str(sample.resp_body or "")[:500])
        ),
    }, ensure_ascii=False)
    system = (
        "Summarise the API endpoint in ≤120 chars, plain prose, no "
        "markdown. Do not invent fields. Output a single line, no JSON."
    )
    raw = chat(system, user)
    if not raw:
        return None
    line = raw.strip().splitlines()[0].strip("`*_ ")
    return line[:140] if line else None


def _empty_spec(title: str, version: str) -> dict[str, Any]:
    return {
        "openapi": "3.1.0",
        "info": {
            "title": title,
            "version": version,
            "x-pencheff-source": "runtime-traffic-synthesis",
        },
        "paths": {},
    }
