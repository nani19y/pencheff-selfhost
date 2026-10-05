"""Consent-gated dynamic tool-invocation fuzzing for MCP scan.

All pure helpers (is_destructive, injection_payloads, response_indicates_injection,
select_tools) are synchronous and fully unit-testable without a live server.

fuzz_tools() is async and requires an active MCP session.
"""
from __future__ import annotations

import re
from typing import Any

from pencheff.config import Severity
from pencheff.core.findings import Finding
from pencheff.modules.mcp_scan.manifest import McpTool
from pencheff.modules.mcp_scan.static_analyzers import _DANGEROUS

# -- Pure core helpers --

def is_destructive(tool: McpTool) -> bool:
    """Return True if the tool name or description matches any dangerous pattern."""
    text = f"{tool.name} {tool.description}"
    return any(re.search(pattern, text) for pattern in _DANGEROUS)


def injection_payloads(oast_url: str) -> list[str]:
    """Return a list of injection probe payloads covering command, traversal, and SSRF."""
    return [
        "; id",
        "| id",
        "`id`",
        oast_url,
        f"http://{oast_url.split('://', 1)[-1]}",
        "../../../../etc/passwd",
        "../../../etc/shadow",
        "canary_safe_string",
    ]


_INJECTION_PATTERNS = re.compile(
    r"root:x:0:0|uid=\d+|/etc/passwd|/etc/shadow|\buid=",
    re.IGNORECASE,
)


def response_indicates_injection(text: str, oast_hit: bool) -> bool:
    """Return True if the response text or an OAST hit indicates successful injection."""
    if oast_hit:
        return True
    return bool(_INJECTION_PATTERNS.search(text))


def select_tools(
    tools: list[McpTool],
    allow: list[str],
    deny: list[str],
    dynamic: bool,
    destructive: bool,
) -> list[McpTool]:
    """Filter tools according to consent gates.

    - dynamic=False  → return [] (no dynamic invocation permitted)
    - allow non-empty → only tools in allow list pass
    - deny non-empty  → tools in deny list are excluded
    - destructive=False → tools matching _DANGEROUS patterns are excluded
    """
    if not dynamic:
        return []
    result = list(tools)
    if allow:
        result = [t for t in result if t.name in allow]
    if deny:
        result = [t for t in result if t.name not in deny]
    if not destructive:
        result = [t for t in result if not is_destructive(t)]
    return result


def _extract_text(result) -> str:
    """Robustly extract a text string from a call_tool result."""
    if isinstance(result, str):
        return result
    if hasattr(result, "content") and isinstance(result.content, list):
        parts = []
        for item in result.content:
            if hasattr(item, "text"):
                parts.append(item.text)
            else:
                parts.append(str(item))
        return " ".join(parts)
    if hasattr(result, "text"):
        return result.text
    return str(result)


# -- Live fuzzing (async, requires session) --

async def fuzz_tools(
    session: Any,
    tools: list[McpTool],
    *,
    oast: Any = None,
    allow: list[str],
    deny: list[str],
    dynamic: bool,
    destructive: bool,
    endpoint: str,
    max_calls: int = 50,
) -> list[Finding]:
    """Fuzz selected MCP tools with injection payloads via a live session.

    Args:
        session: An active MCP client session exposing call_tool(name, args).
        tools: Full tool list from the manifest.
        oast: Optional OAST helper with .url and async .poll() -> list.
        allow: Allowlist of tool names (empty = all pass).
        deny: Denylist of tool names.
        dynamic: Master gate — False means skip fuzzing entirely.
        destructive: If False, exclude destructive tools.
        endpoint: MCP endpoint string for Finding metadata.
        max_calls: Hard cap on total tool invocations.

    Returns:
        List of Findings for confirmed injections.
    """
    selected = select_tools(tools, allow=allow, deny=deny, dynamic=dynamic, destructive=destructive)
    findings: list[Finding] = []
    call_count = 0

    oast_url = ""
    if oast is not None:
        try:
            oast_url = oast.url if hasattr(oast, "url") else str(oast)
        except Exception:
            oast_url = ""

    payloads = injection_payloads(oast_url=oast_url or "http://oast.invalid/probe")

    for tool in selected:
        if call_count >= max_calls:
            break

        # Identify string parameter names from input_schema
        param_names: list[str] = []
        if tool.input_schema and isinstance(tool.input_schema, dict):
            props = tool.input_schema.get("properties", {})
            for pname, pschema in props.items():
                if isinstance(pschema, dict) and pschema.get("type") == "string":
                    param_names.append(pname)
        if not param_names:
            param_names = ["input"]

        for payload in payloads:
            if call_count >= max_calls:
                break
            args = {pname: payload for pname in param_names}
            resp_text = ""
            try:
                result = await session.call_tool(tool.name, args)
                resp_text = _extract_text(result) if result is not None else ""
            except Exception:
                pass
            call_count += 1

            oast_hit = False
            if oast is not None:
                try:
                    hits = await oast.poll() if hasattr(oast, "poll") else []
                    oast_hit = bool(hits)
                except Exception:
                    pass

            if response_indicates_injection(resp_text, oast_hit=oast_hit):
                if ".." in payload:
                    technique = "mcp:param-injection:traversal"
                    cwe_id = "CWE-22"
                    severity = Severity.HIGH
                elif oast_url and oast_url in payload:
                    technique = "mcp:param-injection:ssrf"
                    cwe_id = "CWE-918"
                    severity = Severity.HIGH
                else:
                    technique = "mcp:param-injection:command"
                    cwe_id = "CWE-78"
                    severity = Severity.CRITICAL

                findings.append(Finding(
                    title=f"Injection via MCP tool param: {tool.name}",
                    severity=severity,
                    category="mcp_param_injection",
                    owasp_category="LLM05",
                    description=(
                        f"Tool {tool.name!r} reflected an injected payload. "
                        f"Payload: {payload!r}. Response snippet: {resp_text[:200]!r}"
                    ),
                    remediation=(
                        "Validate and sanitize all tool input parameters. "
                        "Apply allowlists, length limits, and encoding before "
                        "passing values to system calls or file operations."
                    ),
                    endpoint=endpoint,
                    parameter=str(list(param_names)),
                    cwe_id=cwe_id,
                    metadata={"technique": technique, "tool": tool.name, "payload": payload},
                ))

        # --- mcp:result-injection: marker reflected in tool result → indirect prompt injection ---
        if call_count < max_calls:
            _RI_MARKER = "PENCHEFF_RESULT_INJECT_7Z"
            ri_args = {pname: f"<<{_RI_MARKER}>>" for pname in param_names}
            try:
                ri_resp = await session.call_tool(tool.name, ri_args)
                ri_text = _extract_text(ri_resp)
                if _RI_MARKER in (ri_text or ""):
                    findings.append(Finding(
                        title=f"MCP tool '{tool.name}' reflects attacker input into its result",
                        severity=Severity.HIGH,
                        category="mcp_result_injection",
                        owasp_category="LLM01",
                        description=(
                            "The tool echoed an injected marker into its result unsanitized — "
                            "a tool result can carry attacker instructions into the calling "
                            "model's context (indirect prompt injection via tool output)."
                        ),
                        remediation="Sanitize/escape tool output; never pass raw external content back as model context.",
                        endpoint=endpoint,
                        parameter=tool.name,
                        cwe_id="CWE-74",
                        metadata={"technique": "mcp:result-injection", "tool": tool.name},
                    ))
            except Exception:  # noqa: BLE001 — one probe failing mustn't abort the fuzz
                pass
            call_count += 1

        # --- mcp:destructive-no-consent: only when destructive opt-in ---
        if destructive and is_destructive(tool) and call_count < max_calls:
            try:
                await session.call_tool(tool.name, {pname: "PENCHEFF_BENIGN_PROBE" for pname in param_names})
                findings.append(Finding(
                    title=f"Destructive MCP tool '{tool.name}' callable without consent gate",
                    severity=Severity.HIGH,
                    category="mcp_destructive_no_consent",
                    owasp_category="LLM06",
                    description=(
                        "A destructive-classified tool executed on a benign probe with no "
                        "elicitation/consent step — a compromised model could trigger it freely."
                    ),
                    remediation="Gate destructive tools behind MCP elicitation/human consent before execution.",
                    endpoint=endpoint,
                    parameter=tool.name,
                    cwe_id="CWE-862",
                    metadata={"technique": "mcp:destructive-no-consent", "tool": tool.name},
                ))
            except Exception:  # noqa: BLE001
                pass
            call_count += 1

        # ponytail: mcp:tool-authz-bypass deferred — session.call_tool() is the only
        # available method; headers/auth are baked in at session-creation time in client.py
        # and are not overridable per-call. Implement when the session abstraction gains
        # an unauthenticated call path (e.g. call_tool_unauthenticated or header override).

    return findings
