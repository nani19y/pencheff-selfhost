"""OpenAPI 3.x / Swagger 2.0 / Postman v2.1 spec importer.

Parses API specs and seeds session.discovered.endpoints so scan modules
have complete coverage without relying on crawl-based discovery.
"""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import urljoin, urlparse, urlsplit, urlunsplit


def _rebase_onto_target(url: str, base_url: str) -> str:
    """Force an imported endpoint's origin to the actual target's scheme+host.

    API specs almost always declare a dev/placeholder ``servers`` entry (e.g.
    ``http://localhost:8888``) that is NOT the host being scanned. Left as-is,
    those endpoints get dropped as cross-origin by the route filter, so the
    seeded surface is discarded. We keep the endpoint's PATH (incl. any server
    path prefix) and query, but swap the origin to the target being scanned.
    """
    tgt = urlsplit(base_url)
    if not tgt.netloc:
        return url
    src = urlsplit(url if "://" in url else urljoin(base_url, url))
    return urlunsplit((tgt.scheme or src.scheme or "http", tgt.netloc,
                       src.path, src.query, ""))


def _resolve_ref(spec: dict, ref: str) -> dict:
    """Resolve a $ref pointer within the spec (local only)."""
    parts = ref.lstrip("#/").split("/")
    node = spec
    for p in parts:
        node = node.get(p.replace("~1", "/").replace("~0", "~"), {})
    return node if isinstance(node, dict) else {}


def _schema_example(schema: dict, spec: dict, _depth: int = 0) -> Any:
    """Generate a simple example value from a JSON Schema fragment."""
    if "$ref" in schema:
        schema = _resolve_ref(spec, schema["$ref"])
    if _depth > 3:
        return None
    t = schema.get("type", "string")
    fmt = schema.get("format", "")
    if t == "integer":
        return schema.get("example", 1)
    if t == "number":
        return schema.get("example", 1.0)
    if t == "boolean":
        return schema.get("example", True)
    if t == "array":
        items = schema.get("items", {})
        return [_schema_example(items, spec, _depth + 1)]
    if t == "object":
        props = schema.get("properties", {})
        return {k: _schema_example(v, spec, _depth + 1) for k, v in list(props.items())[:5]}
    # string
    if fmt == "email":
        return schema.get("example", "user@example.com")
    if fmt == "date-time":
        return schema.get("example", "2024-01-01T00:00:00Z")
    if fmt == "uuid":
        return schema.get("example", "00000000-0000-0000-0000-000000000000")
    if schema.get("enum"):
        return schema["enum"][0]
    return schema.get("example", "test")


def _extract_params(parameter_list: list[dict], spec: dict) -> list[dict]:
    out = []
    for p in parameter_list:
        if "$ref" in p:
            p = _resolve_ref(spec, p["$ref"])
        out.append({
            "name": p.get("name", ""),
            "in": p.get("in", "query"),
            "required": p.get("required", False),
            "schema": p.get("schema", p.get("type", "string")),
            # Carry the raw entry so callers can pull `example` / `examples` /
            # default values when substituting path placeholders.
            "_raw": p,
        })
    return out


def _path_param_example(p: dict, spec: dict) -> str | None:
    """Best-effort example value for a path parameter.

    Order of preference:
      1. ``example`` on the parameter itself
      2. ``examples[<first>].value`` on the parameter
      3. ``default`` on the parameter's schema
      4. ``example`` on the parameter's schema
      5. Synthetic value derived from the schema type/format
    """
    raw = p.get("_raw") or {}
    if "example" in raw:
        return str(raw["example"])
    examples = raw.get("examples") or {}
    if isinstance(examples, dict) and examples:
        first = next(iter(examples.values()))
        if isinstance(first, dict) and "value" in first:
            return str(first["value"])
    schema = raw.get("schema") or {}
    if isinstance(schema, dict):
        if "$ref" in schema:
            schema = _resolve_ref(spec, schema["$ref"])
        if "default" in schema:
            return str(schema["default"])
        if "example" in schema:
            return str(schema["example"])
        synthetic = _schema_example(schema, spec)
        if synthetic is not None and not isinstance(synthetic, (dict, list)):
            return str(synthetic)
    return None


def _substitute_path(path: str, params: list[dict], spec: dict) -> str | None:
    """Replace ``{name}`` placeholders with example values.

    Returns the substituted path, or None if any ``{...}`` placeholder is
    left over (i.e. the importer has no usable example for it). Endpoints
    with unresolved placeholders should be dropped — registering them
    causes the scanner / agent to probe paths like ``/orgs/{org_id}``
    literally, which always 404s and burns budget.
    """
    by_name = {p["name"]: p for p in params if p.get("in") == "path"}
    out = path
    for name, p in by_name.items():
        marker = "{" + name + "}"
        if marker not in out:
            continue
        example = _path_param_example(p, spec)
        if example is None or "{" in example or "}" in example:
            return None
        out = out.replace(marker, example)
    if "{" in out and "}" in out:
        # Stray placeholder we don't have a parameter definition for.
        return None
    return out


def import_openapi3(spec: dict, base_url: str) -> list[dict[str, Any]]:
    """Parse OpenAPI 3.x spec and return a list of endpoint dicts."""
    endpoints: list[dict[str, Any]] = []
    servers = spec.get("servers", [])
    server_url = servers[0].get("url", base_url) if servers else base_url

    # Resolve relative server URL against provided base_url
    if not server_url.startswith("http"):
        server_url = urljoin(base_url, server_url)

    for path, path_item in spec.get("paths", {}).items():
        if not isinstance(path_item, dict):
            continue
        common_params = path_item.get("parameters", [])

        for method in ("get", "post", "put", "patch", "delete", "options", "head"):
            op = path_item.get(method)
            if not op:
                continue

            all_params = list(common_params) + op.get("parameters", [])
            params = _extract_params(all_params, spec)
            param_names = [p["name"] for p in params]

            # Build a body example if present
            body_example: dict | None = None
            req_body = op.get("requestBody", {})
            if req_body:
                if "$ref" in req_body:
                    req_body = _resolve_ref(spec, req_body["$ref"])
                content = req_body.get("content", {})
                for mime in ("application/json", "application/x-www-form-urlencoded", "multipart/form-data"):
                    if mime in content:
                        schema = content[mime].get("schema", {})
                        body_example = _schema_example(schema, spec)
                        break

            substituted_path = _substitute_path(path, params, spec)
            if substituted_path is None:
                # Path has unresolved {...} placeholders we can't substitute
                # — skip rather than register a literal-templated URL.
                continue
            url = server_url.rstrip("/") + substituted_path
            endpoints.append({
                "url": url,
                "method": method.upper(),
                "source": "openapi3",
                "params": param_names,
                "parameters": params,
                "body_example": body_example,
                "operation_id": op.get("operationId", ""),
                "tags": op.get("tags", []),
                "summary": op.get("summary", ""),
                "path_template": path,
            })

    return endpoints


def import_swagger2(spec: dict, base_url: str) -> list[dict[str, Any]]:
    """Parse Swagger 2.0 spec and return a list of endpoint dicts."""
    endpoints: list[dict[str, Any]] = []
    scheme = "https" if "https" in spec.get("schemes", ["https"]) else "http"
    host = spec.get("host", urlparse(base_url).netloc)
    base_path = spec.get("basePath", "/")
    server_url = f"{scheme}://{host}{base_path}"

    for path, path_item in spec.get("paths", {}).items():
        if not isinstance(path_item, dict):
            continue
        common_params = path_item.get("parameters", [])

        for method in ("get", "post", "put", "patch", "delete", "options", "head"):
            op = path_item.get(method)
            if not op:
                continue

            all_params = list(common_params) + op.get("parameters", [])
            params = _extract_params(all_params, spec)
            param_names = [p["name"] for p in params]

            # Body from 'body' parameter
            body_example: dict | None = None
            body_params = [p for p in all_params if p.get("in") == "body"]
            if body_params:
                bp = body_params[0]
                if "$ref" in bp:
                    bp = _resolve_ref(spec, bp["$ref"])
                schema = bp.get("schema", {})
                body_example = _schema_example(schema, spec)

            substituted_path = _substitute_path(path, params, spec)
            if substituted_path is None:
                continue
            url = server_url.rstrip("/") + substituted_path
            endpoints.append({
                "url": url,
                "method": method.upper(),
                "source": "swagger2",
                "params": param_names,
                "parameters": params,
                "body_example": body_example,
                "operation_id": op.get("operationId", ""),
                "tags": op.get("tags", []),
                "summary": op.get("summary", ""),
                "path_template": path,
            })

    return endpoints


def import_postman_v2(collection: dict, base_url: str) -> list[dict[str, Any]]:
    """Parse Postman Collection v2.1 and return endpoint dicts."""
    endpoints: list[dict[str, Any]] = []

    def _process_items(items: list) -> None:
        for item in items:
            # Folder — recurse
            if "item" in item:
                _process_items(item["item"])
                continue
            req = item.get("request", {})
            if not req:
                continue
            method = req.get("method", "GET").upper()
            url_obj = req.get("url", {})
            if isinstance(url_obj, str):
                url = url_obj
                params = []
            else:
                raw = url_obj.get("raw", "")
                url = raw
                params = [q.get("key", "") for q in url_obj.get("query", []) if q.get("key")]

            body_example = None
            body = req.get("body", {})
            if body:
                mode = body.get("mode", "")
                if mode == "raw":
                    raw_body = body.get("raw", "")
                    try:
                        body_example = json.loads(raw_body)
                    except Exception:
                        body_example = raw_body
                elif mode == "urlencoded":
                    body_example = {e.get("key", ""): e.get("value", "") for e in body.get("urlencoded", [])}
                elif mode == "formdata":
                    body_example = {e.get("key", ""): e.get("value", "") for e in body.get("formdata", [])}

            endpoints.append({
                "url": url,
                "method": method,
                "source": "postman",
                "params": params,
                "parameters": [{"name": p, "in": "query"} for p in params],
                "body_example": body_example,
                "operation_id": item.get("name", ""),
                "tags": [],
                "summary": item.get("name", ""),
            })

    _process_items(collection.get("item", []))
    return endpoints


def parse_api_spec(
    content: str,
    base_url: str,
    hint: str = "auto",
) -> dict[str, Any]:
    """Parse an API spec (JSON or YAML string) and return endpoints + metadata.

    hint: 'openapi3', 'swagger2', 'postman', or 'auto' (detect from content).
    """
    import yaml  # pyyaml is a hard dep

    try:
        spec = json.loads(content)
    except json.JSONDecodeError:
        try:
            spec = yaml.safe_load(content)
        except Exception as e:
            return {"error": f"Failed to parse spec: {e}", "endpoints": []}

    if not isinstance(spec, dict):
        return {"error": "Spec is not a JSON/YAML object", "endpoints": []}

    # Auto-detect format
    if hint == "auto":
        if spec.get("openapi", "").startswith("3"):
            hint = "openapi3"
        elif spec.get("swagger", "").startswith("2"):
            hint = "swagger2"
        elif "info" in spec and "item" in spec:
            hint = "postman"
        else:
            return {"error": "Cannot detect spec format. Provide hint=openapi3/swagger2/postman", "endpoints": []}

    if hint == "openapi3":
        endpoints = import_openapi3(spec, base_url)
        spec_type = "OpenAPI 3.x"
    elif hint == "swagger2":
        endpoints = import_swagger2(spec, base_url)
        spec_type = "Swagger 2.0"
    elif hint == "postman":
        endpoints = import_postman_v2(spec, base_url)
        spec_type = "Postman v2.1"
    else:
        return {"error": f"Unknown hint '{hint}'", "endpoints": []}

    # Rebase every endpoint onto the target being scanned. Specs declare a
    # placeholder/dev server (localhost, example.com) that is rarely the host
    # under test; without this the seeded endpoints are dropped as cross-origin.
    for ep in endpoints:
        ep["url"] = _rebase_onto_target(ep["url"], base_url)

    return {
        "spec_type": spec_type,
        "title": (spec.get("info", {}) or {}).get("title", "Unknown API"),
        "version": (spec.get("info", {}) or {}).get("version", ""),
        "endpoint_count": len(endpoints),
        "endpoints": endpoints,
    }
