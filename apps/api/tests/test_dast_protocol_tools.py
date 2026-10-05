"""Tests for plugins/pencheff/pencheff/dast_protocol_tools.py.

Subprocess-dependent paths are stubbed; we verify the security contracts
(target sanitization, action gating, kind_config fallback, --plaintext
defensive handling) and the JSON parser correctness.
"""
from __future__ import annotations

import json

import pytest

import pencheff.dast_protocol_tools as pt
import pencheff.artifact_tools as at


@pytest.fixture(autouse=True)
def _clear_kind_configs():
    at._SESSION_KIND_CONFIGS.clear()
    yield
    at._SESSION_KIND_CONFIGS.clear()


# ----------------------------------------------------------------------------
# run_graphql_cop
# ----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_graphql_cop_missing_binary_returns_skipped(monkeypatch) -> None:
    monkeypatch.setattr(pt, "_which", lambda b: False)
    result = await pt.run_graphql_cop("sid", endpoint="https://api.example.com/graphql")
    assert "binary not found: graphql-cop" in result["error"]
    assert result["skipped"] is True


@pytest.mark.asyncio
async def test_graphql_cop_rejects_non_http_endpoint(monkeypatch) -> None:
    monkeypatch.setattr(pt, "_which", lambda b: True)
    result = await pt.run_graphql_cop("sid", endpoint="ftp://example.com/")
    assert "endpoint must be" in result["error"]


@pytest.mark.asyncio
async def test_graphql_cop_falls_back_to_kind_config_endpoint(monkeypatch) -> None:
    monkeypatch.setattr(pt, "_which", lambda b: True)

    captured: dict = {}

    async def fake_run(argv, **kw):
        captured["argv"] = argv
        return {"returncode": 0, "stdout": "[]", "stderr": "", "timed_out": False}

    monkeypatch.setattr(pt, "_run_subprocess", fake_run)
    at.set_kind_config_for_session("sid", {"kind": "graphql", "endpoint": "https://gql.example.com/v1"})
    result = await pt.run_graphql_cop("sid", endpoint=None)
    assert result["scanner"] == "graphql-cop"
    assert "https://gql.example.com/v1" in captured["argv"]


@pytest.mark.asyncio
async def test_graphql_cop_forces_scan_for_waf_fronted_endpoints(monkeypatch) -> None:
    """-f/--force must be passed so WAF-fronted endpoints (that 403 the GraphQL
    detection probe) still get scanned instead of bailing with zero findings."""
    monkeypatch.setattr(pt, "_which", lambda b: True)
    captured: dict = {}

    async def fake_run(argv, **kw):
        captured["argv"] = argv
        return {"returncode": 0, "stdout": "[]", "stderr": "", "timed_out": False}

    monkeypatch.setattr(pt, "_run_subprocess", fake_run)
    await pt.run_graphql_cop("sid", endpoint="https://api.example.com/graphql")
    assert "-f" in captured["argv"]


@pytest.mark.asyncio
async def test_graphql_cop_passes_proxy_and_headers(monkeypatch) -> None:
    """Egress proxy (-x) + headers (-H JSON) route past IP/signature WAF blocks."""
    monkeypatch.setattr(pt, "_which", lambda b: True)
    captured: dict = {}

    async def fake_run(argv, **kw):
        captured["argv"] = argv
        return {"returncode": 0, "stdout": "[]", "stderr": "", "timed_out": False}

    monkeypatch.setattr(pt, "_run_subprocess", fake_run)
    at.set_kind_config_for_session("sid", {
        "kind": "graphql", "endpoint": "https://x/graphql",
        "proxy": "http://1.2.3.4:8080", "headers": {"User-Agent": "UA-X"},
    })
    await pt.run_graphql_cop("sid")
    argv = captured["argv"]
    assert "-x" in argv and "http://1.2.3.4:8080" in argv
    hdrs = json.loads(argv[argv.index("-H") + 1])
    assert hdrs["User-Agent"] == "UA-X"


@pytest.mark.asyncio
async def test_graphql_cop_defaults_realistic_ua_without_operator_headers(monkeypatch) -> None:
    monkeypatch.setattr(pt, "_which", lambda b: True)
    captured: dict = {}

    async def fake_run(argv, **kw):
        captured["argv"] = argv
        return {"returncode": 0, "stdout": "[]", "stderr": "", "timed_out": False}

    monkeypatch.setattr(pt, "_run_subprocess", fake_run)
    await pt.run_graphql_cop("sid", endpoint="https://x/graphql")
    hdrs = json.loads(captured["argv"][captured["argv"].index("-H") + 1])
    assert "PencheffScanner" not in hdrs["User-Agent"]  # not a WAF tell
    assert hdrs["User-Agent"].startswith("Mozilla/")


def test_parse_graphql_cop_drops_not_vulnerable_entries() -> None:
    raw = json.dumps([
        {"result": True, "title": "Introspection", "severity": "Medium", "description": "x"},
        {"result": False, "title": "Alias Overloading", "severity": "High", "description": "not vuln"},
    ])
    findings = pt._parse_graphql_cop_json(raw)
    assert [f["title"] for f in findings] == ["Introspection"]


@pytest.mark.asyncio
async def test_inql_passes_proxy_and_headers(monkeypatch) -> None:
    monkeypatch.setattr(pt, "_which", lambda b: True)
    captured: dict = {}

    async def fake_run(argv, **kw):
        captured["argv"] = argv
        return {"returncode": 0, "stdout": "Query.me", "stderr": "", "timed_out": False}

    monkeypatch.setattr(pt, "_run_subprocess", fake_run)
    at.set_kind_config_for_session("sid", {
        "kind": "graphql", "endpoint": "https://x/graphql",
        "proxy": "http://p:9", "headers": {"User-Agent": "UA-Y"},
    })
    await pt.run_inql("sid")
    argv = captured["argv"]
    assert "-p" in argv and "http://p:9" in argv
    idxs = [i for i, a in enumerate(argv) if a == "--header"]
    pairs = {argv[i + 1]: argv[i + 2] for i in idxs}
    assert pairs.get("User-Agent") == "UA-Y"


def test_parse_graphql_cop_json_list_shape() -> None:
    raw = json.dumps([
        {"title": "Introspection exposed", "severity": "Medium",
         "description": "GraphQL introspection is enabled in production."},
        {"title": "Field suggestions enabled", "severity": "Low",
         "description": "Server returns 'Did you mean...?' hints."},
    ])
    findings = pt._parse_graphql_cop_json(raw)
    assert len(findings) == 2
    assert findings[0]["severity"] == "medium"
    assert findings[1]["severity"] == "low"
    assert all(f["owasp_category"] == "A05:2021" for f in findings)


def test_parse_graphql_cop_handles_empty() -> None:
    assert pt._parse_graphql_cop_json("") == []
    assert pt._parse_graphql_cop_json("not json") == []


# ----------------------------------------------------------------------------
# run_inql
# ----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_inql_missing_binary_returns_skipped(monkeypatch) -> None:
    monkeypatch.setattr(pt, "_which", lambda b: False)
    result = await pt.run_inql("sid", endpoint="https://api.example.com/graphql")
    assert "binary not found: inql" in result["error"]


@pytest.mark.asyncio
async def test_inql_summarises_schema(monkeypatch) -> None:
    monkeypatch.setattr(pt, "_which", lambda b: True)

    async def fake_run(argv, **kw):
        # Simulate inql dumping a schema list.
        out = "\n".join([
            "Query.users", "Query.user", "Query.me",
            "Mutation.createUser", "Mutation.deleteUser",
            "Subscription.userUpdated",
        ])
        return {"returncode": 0, "stdout": out, "stderr": "", "timed_out": False}

    monkeypatch.setattr(pt, "_run_subprocess", fake_run)
    result = await pt.run_inql("sid", endpoint="https://api.example.com/graphql")
    assert result["schema_summary"] == {"queries": 3, "mutations": 2, "subscriptions": 1}
    assert result["findings"][0]["severity"] == "info"


# ----------------------------------------------------------------------------
# run_grpcurl
# ----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_grpcurl_rejects_shell_metachars_in_target(monkeypatch) -> None:
    monkeypatch.setattr(pt, "_which", lambda b: True)
    result = await pt.run_grpcurl("sid", target="evil.com:50051; rm -rf /")
    assert result["error"] == "invalid target — host:port only"


@pytest.mark.asyncio
async def test_grpcurl_unknown_action(monkeypatch) -> None:
    monkeypatch.setattr(pt, "_which", lambda b: True)
    at.set_kind_config_for_session("sid", {"kind": "grpc", "base_url": "grpc.example.com:50051"})
    result = await pt.run_grpcurl("sid", action="exploit")
    assert "unknown action" in result["error"]


@pytest.mark.asyncio
async def test_grpcurl_invoke_requires_service_and_method(monkeypatch) -> None:
    monkeypatch.setattr(pt, "_which", lambda b: True)
    at.set_kind_config_for_session("sid", {"kind": "grpc", "base_url": "grpc.example.com:50051"})
    result = await pt.run_grpcurl("sid", action="invoke", service="foo.Service")
    assert "invoke requires service AND method" in result["error"]


@pytest.mark.asyncio
async def test_grpcurl_invoke_rejects_invalid_json_payload(monkeypatch) -> None:
    monkeypatch.setattr(pt, "_which", lambda b: True)
    at.set_kind_config_for_session("sid", {"kind": "grpc", "base_url": "grpc.example.com:50051"})
    result = await pt.run_grpcurl(
        "sid",
        action="invoke",
        service="foo.Service",
        method="DoThing",
        payload_json="{not valid",
    )
    assert "payload_json must be valid JSON" in result["error"]


@pytest.mark.asyncio
async def test_grpcurl_passes_insecure_when_tls_verify_false(monkeypatch) -> None:
    monkeypatch.setattr(pt, "_which", lambda b: True)
    captured: dict = {}

    async def fake_run(argv, **kw):
        captured["argv"] = argv
        return {"returncode": 0, "stdout": "foo.Service\nbar.Other", "stderr": "", "timed_out": False}

    monkeypatch.setattr(pt, "_run_subprocess", fake_run)
    at.set_kind_config_for_session("sid", {
        "kind": "grpc", "base_url": "grpc.example.com:50051", "tls_verify": False,
    })
    result = await pt.run_grpcurl("sid", action="list")
    assert "grpcurl" in captured["argv"]
    assert "-insecure" in captured["argv"]
    # --plaintext must NEVER appear — that's a S-07 dangerous flag.
    assert "--plaintext" not in captured["argv"]
    assert result["scanner"] == "grpcurl"


@pytest.mark.asyncio
async def test_grpcurl_invoke_success_emits_finding(monkeypatch) -> None:
    monkeypatch.setattr(pt, "_which", lambda b: True)

    async def fake_run(argv, **kw):
        return {"returncode": 0, "stdout": '{"result":"ok"}', "stderr": "", "timed_out": False}

    monkeypatch.setattr(pt, "_run_subprocess", fake_run)
    at.set_kind_config_for_session("sid", {"kind": "grpc", "base_url": "grpc.example.com:50051"})
    result = await pt.run_grpcurl(
        "sid", action="invoke", service="foo.Service", method="GetSecret", payload_json="{}",
    )
    assert result["findings_count"] == 1
    assert result["findings"][0]["owasp_category"] == "A01:2021"  # broken access control
    assert "unauthenticated invocation" in result["findings"][0]["title"]


# ----------------------------------------------------------------------------
# parse_proto
# ----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_parse_proto_extracts_service_and_rpcs() -> None:
    proto = """
    syntax = "proto3";
    package myapp;

    service UserService {
        rpc GetUser (GetUserRequest) returns (User);
        rpc ListUsers (ListUsersRequest) returns (stream User);
        rpc UpdateUser (stream UpdateRequest) returns (User);
    }

    service AdminService {
        rpc Reset (Empty) returns (Empty);
    }
    """
    result = await pt.parse_proto("sid", proto_content=proto)
    assert result["service_count"] == 2
    assert result["rpc_count"] == 4
    svc_names = {s["name"] for s in result["services"]}
    assert svc_names == {"UserService", "AdminService"}
    user_service = next(s for s in result["services"] if s["name"] == "UserService")
    rpc_names = {r["name"] for r in user_service["rpcs"]}
    assert rpc_names == {"GetUser", "ListUsers", "UpdateUser"}
    # ListUsers is server-streaming
    list_users = next(r for r in user_service["rpcs"] if r["name"] == "ListUsers")
    assert list_users["output_stream"] is True
    assert list_users["input_stream"] is False
    # UpdateUser is client-streaming
    update_user = next(r for r in user_service["rpcs"] if r["name"] == "UpdateUser")
    assert update_user["input_stream"] is True


@pytest.mark.asyncio
async def test_parse_proto_falls_back_to_kind_config(monkeypatch) -> None:
    at.set_kind_config_for_session("sid", {
        "kind": "grpc",
        "proto_files": ["service Foo { rpc Bar (Req) returns (Resp); }"],
    })
    result = await pt.parse_proto("sid", proto_content=None)
    assert result["service_count"] == 1
    assert result["rpc_count"] == 1


@pytest.mark.asyncio
async def test_parse_proto_no_content_returns_error() -> None:
    result = await pt.parse_proto("sid-unbound", proto_content=None)
    assert "no proto content" in result["error"]
