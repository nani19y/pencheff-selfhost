"""GraphQL-specific vulnerability testing."""

from __future__ import annotations

from typing import Any

from pencheff.config import Severity
from pencheff.core.findings import Evidence, Finding
from pencheff.core.http_client import PencheffHTTPClient
from pencheff.core.session import PentestSession
from pencheff.core.waf_evasion import (
    SQLI_BYPASS_TAUTOLOGIES,
    looks_like_waf_block,
    sqli_evasion_variants,
    strip_operation_name,
)
from pencheff.modules.base import BaseTestModule

# Anonymous (no operation name) so it slips past operation-name allowlists like
# DVGA's "Operation Name X is not allowed". Field ``args`` are captured so the
# injection test can target String/ID arguments.
INTROSPECTION_QUERY = """{
  __schema {
    types {
      name
      fields {
        name
        args { name type { name kind ofType { name } } }
        type { name kind ofType { name } }
      }
    }
    queryType { name }
    mutationType { name }
  }
}"""

# A boolean-false counterpart to the true tautologies, for differential SQLi.
_SQLI_FALSE = "1 AND 1 LIKE 2"

DEPTH_QUERY_TEMPLATE = "{ __typename " + "".join(["{ __typename " for _ in range(20)]) + "}" * 20


class GraphQLModule(BaseTestModule):
    name = "graphql"
    category = "api"
    owasp_categories = ["A01", "A05"]
    description = "GraphQL vulnerability testing"

    def get_techniques(self) -> list[str]:
        return ["introspection", "depth_limit", "batch_attack", "field_suggestion"]

    async def run(
        self,
        session: PentestSession,
        http: PencheffHTTPClient,
        targets: list[str] | None = None,
        config: dict[str, Any] | None = None,
    ) -> list[Finding]:
        findings = []

        # Find GraphQL endpoints
        gql_endpoints = []
        for spec in session.discovered.api_specs:
            if spec.get("type") == "graphql":
                gql_endpoints.append(spec["url"])

        if not gql_endpoints:
            base_url = session.target.base_url
            for path in ["/graphql", "/graphiql", "/api/graphql", "/gql"]:
                try:
                    resp = await http.post(
                        f"{base_url}{path}",
                        json_data={"query": "{ __typename }"},
                        module="graphql",
                    )
                    if resp.status_code == 200 and "__typename" in resp.text:
                        gql_endpoints.append(f"{base_url}{path}")
                except Exception:
                    continue

        for url in gql_endpoints[:3]:
            injectable: list[tuple[str, str]] = []  # (field, string/ID arg) for Test 4
            # Test 1: Introspection (anonymous — evades operation-name allowlists)
            try:
                resp = await http.post(url, json_data={"query": INTROSPECTION_QUERY}, module="graphql")
                if resp.status_code == 200 and "__schema" in resp.text:
                    data = resp.json()
                    schema = data.get("data", {}).get("__schema", {}) or {}
                    types = schema.get("types", [])
                    type_names = [t["name"] for t in types if not t["name"].startswith("__")]
                    injectable = _string_arg_fields(schema)

                    findings.append(Finding(
                        title="GraphQL Introspection Enabled",
                        severity=Severity.MEDIUM,
                        category="misconfiguration",
                        owasp_category="A05",
                        description=f"GraphQL introspection is enabled, exposing the complete schema "
                                    f"({len(type_names)} types: {', '.join(type_names[:10])}...).",
                        remediation="Disable introspection in production. Only enable for development.",
                        endpoint=url,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                        cvss_score=5.3,
                        cwe_id="CWE-200",
                        evidence=[Evidence(
                            request_method="POST",
                            request_url=url,
                            response_status=resp.status_code,
                            description=f"Introspection returned {len(types)} types",
                        )],
                    ))
            except Exception:
                pass

            # Test 2: Query depth / complexity limit
            try:
                deep_query = "{ __typename " + "".join(["{ __typename " for _ in range(15)]) + "}" * 15
                resp = await http.post(url, json_data={"query": deep_query}, module="graphql")
                if resp.status_code == 200:
                    findings.append(Finding(
                        title="GraphQL No Query Depth Limit",
                        severity=Severity.MEDIUM,
                        category="misconfiguration",
                        owasp_category="A05",
                        description="No query depth limit detected. Deep/recursive queries can cause DoS.",
                        remediation="Implement query depth limiting (max 10-15 levels). "
                                    "Add query complexity analysis and cost limits.",
                        endpoint=url,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
                        cvss_score=5.3,
                        cwe_id="CWE-400",
                    ))
            except Exception:
                pass

            # Test 3: Batch query attack
            try:
                batch = [{"query": "{ __typename }"} for _ in range(20)]
                resp = await http.post(url, json_data=batch, module="graphql")
                if resp.status_code == 200:
                    try:
                        result = resp.json()
                        if isinstance(result, list) and len(result) >= 20:
                            findings.append(Finding(
                                title="GraphQL Batch Query Not Limited",
                                severity=Severity.MEDIUM,
                                category="misconfiguration",
                                owasp_category="A05",
                                description="Server accepts batched GraphQL queries without limit. "
                                            "Can be used for brute force or DoS attacks.",
                                remediation="Limit the number of operations in a single batch request.",
                                endpoint=url,
                                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
                                cvss_score=5.3,
                                cwe_id="CWE-770",
                            ))
                    except Exception:
                        pass
            except Exception:
                pass

            # Test 4: SQLi on string/ID args, with WAF evasion.
            # Classic tautology first; if the WAF blocks it, retry with
            # obfuscated variants. Boolean-differential (TRUE vs FALSE) confirms
            # injection; a variant that reaches the app after a block is logged
            # as a demonstrated WAF bypass.
            for field, arg in injectable[:4]:
                try:
                    tr = await self._sqli_probe(http, url, field, arg, "1 OR 1=1")   # TRUE
                    fa = await self._sqli_probe(http, url, field, arg, "1 AND 1=2")  # FALSE
                    if tr is None or fa is None:
                        continue  # couldn't reach the backend even with evasion
                    true_resp, ev_t = tr
                    false_resp, ev_f = fa
                    evaded_with = ev_t or ev_f  # None → no WAF interference on this field
                    differential = (
                        true_resp.status_code == 200 and false_resp.status_code == 200
                        and abs(len(true_resp.text) - len(false_resp.text)) > 32
                    )
                    if differential:
                        evnote = (
                            f" The WAF blocked the classic payload; obfuscated variant "
                            f"'{evaded_with}' bypassed it." if evaded_with else ""
                        )
                        findings.append(Finding(
                            title=(f"GraphQL SQL Injection (WAF-evaded): {field}.{arg}"
                                   if evaded_with else f"GraphQL SQL Injection: {field}.{arg}"),
                            severity=Severity.HIGH,
                            category="injection",
                            owasp_category="A03",
                            description=(
                                f"Boolean-based SQL injection in argument '{arg}' of field '{field}': "
                                f"a true vs false condition produced a response differential."
                                + evnote
                            ),
                            remediation="Parameterize backend queries; don't build SQL from GraphQL args. "
                                        "WAF signature filtering is not a substitute for fixing the sink.",
                            endpoint=url,
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                            cvss_score=7.5,
                            cwe_id="CWE-89",
                            evidence=[Evidence(
                                request_method="POST", request_url=url, response_status=200,
                                description=f"true/false response length {len(true_resp.text)}/{len(false_resp.text)}"
                                            + (f"; bypassed WAF with '{evaded_with}'" if evaded_with else ""),
                            )],
                        ))
                    elif evaded_with:
                        findings.append(Finding(
                            title=f"WAF Signature Bypass via Payload Obfuscation: {field}.{arg}",
                            severity=Severity.LOW,
                            category="waf_bypass",
                            owasp_category="A05",
                            description=(
                                f"The WAF blocked a classic injection payload on '{field}.{arg}' but an "
                                f"obfuscated variant ('{evaded_with}') passed inspection and reached the "
                                f"backend. Signature filtering is evadable here; verify the sink is not injectable."
                            ),
                            remediation="Do not rely on WAF signatures alone; fix injectable sinks and add "
                                        "positive-security/schema validation at the GraphQL layer.",
                            endpoint=url,
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                            cvss_score=3.7,
                            cwe_id="CWE-693",
                        ))
                    # else: reached app, no differential, no WAF interference → nothing to report
                except Exception:
                    pass

        return findings

    async def _sqli_probe(
        self, http: PencheffHTTPClient, url: str, field: str, arg: str, payload: str,
    ):
        """Send ``{ field(arg: "payload") { __typename } }``. If the WAF blocks
        it, retry with obfuscated variants. Returns ``(response, evaded_with)``
        where ``evaded_with`` is the variant that bypassed a block (None if the
        original wasn't blocked), or ``None`` if nothing reached the app."""
        q = '{ %s(%s: "%s") { __typename } }' % (field, arg, payload.replace('"', '\\"'))
        resp = await http.post(url, json_data={"query": q}, module="graphql")
        if not looks_like_waf_block(resp.status_code, resp.text):
            return resp, None
        for variant in sqli_evasion_variants(payload):
            q = '{ %s(%s: "%s") { __typename } }' % (field, arg, variant.replace('"', '\\"'))
            r2 = await http.post(url, json_data={"query": q}, module="graphql")
            if not looks_like_waf_block(r2.status_code, r2.text):
                return r2, variant
        return None


def _unwrap_type_name(t: dict) -> str:
    """Resolve a possibly-wrapped introspection type ref to its base name."""
    seen = 0
    while isinstance(t, dict) and t.get("name") is None and t.get("ofType") and seen < 10:
        t = t["ofType"]; seen += 1
    return (t or {}).get("name") or ""


def _string_arg_fields(schema: dict) -> list[tuple[str, str]]:
    """Query-type fields that take a String/ID argument — SQLi candidates."""
    query_type = (schema.get("queryType") or {}).get("name")
    if not query_type:
        return []
    out: list[tuple[str, str]] = []
    for t in schema.get("types", []):
        if t.get("name") != query_type:
            continue
        for fld in t.get("fields") or []:
            for a in fld.get("args") or []:
                if _unwrap_type_name(a.get("type") or {}) in ("String", "ID"):
                    out.append((fld["name"], a["name"]))
    return out
