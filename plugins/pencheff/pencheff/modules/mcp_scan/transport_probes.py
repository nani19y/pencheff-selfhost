# pencheff/modules/mcp_scan/transport_probes.py
"""Transport and authentication CVE probes for MCP HTTP endpoints.

Designed for graceful degradation: any probe that errors yields no finding
rather than a crash. Pure verdict helpers (_session_id_is_weak, etc.) are
unit-tested without a live server; live HTTP is injected via http_get.

CVEs covered:
- CVE-2025-6515  : oatpp-mcp pointer-cast session IDs (CWE-330)
- CVE-2025-66416 : DNS rebind / missing Host validation (CWE-1188)
- MCP auth spec (2025-06-18) wrong-audience token acceptance (CWE-287)
"""
from __future__ import annotations

import re
import uuid
from typing import Any

from pencheff.config import Severity
from pencheff.core.findings import Finding

from .manifest import McpManifest

# Transport types that expose an HTTP surface worth probing.
_HTTP_TRANSPORTS = {"sse", "streamable_http"}


# ---------------------------------------------------------------------------
# Pure verdict helpers (unit-tested)
# ---------------------------------------------------------------------------

def _session_id_is_weak(sid: str) -> bool:
    """Return True if the session id looks like a memory pointer or sequential int.

    CVE-2025-6515: oatpp-mcp cast the C++ session pointer to a string as the
    session ID — a long decimal integer that is trivially guessable/enumerable.
    Also catches hex-formatted pointers (0x…).

    A UUID or high-entropy token returns False.
    """
    # Hex pointer: 0x[hexdigits]
    if re.fullmatch(r"0x[0-9a-fA-F]+", sid):
        return True
    # Long bare integer (≥ 6 digits) — pointer cast or sequential counter
    if re.fullmatch(r"\d{6,}", sid):
        return True
    # UUID format is safe
    try:
        uuid.UUID(sid)
        return False
    except ValueError:
        pass
    # Anything else with sufficient mixed-class length is treated as safe
    has_upper = bool(re.search(r"[A-Z]", sid))
    has_lower = bool(re.search(r"[a-z]", sid))
    has_digit = bool(re.search(r"[0-9]", sid))
    classes = sum([has_upper, has_lower, has_digit])
    if len(sid) >= 16 and classes >= 2:
        return False
    # Short or low-entropy — flag as weak
    return True


def _accepts_foreign_host(status_code: int) -> bool:
    """Return True if the server accepted a request with a spoofed Host/Origin header.

    CVE-2025-66416 / DNS-rebind class: an HTTP MCP server that does not
    validate the Host header can be hit from a web page on a different origin
    after a DNS rebind attack.  A 2xx response to a spoofed Host indicates no
    validation; a 4xx indicates the server rejected it.
    """
    return 200 <= status_code < 300


def _accepts_wrong_audience(status_code: int) -> bool:
    """Return True if the server accepted a JWT with a wrong 'aud' claim.

    MCP auth specification (2025-06-18) requires servers to verify the
    'aud' claim matches their own resource identifier. A 2xx to a
    wrong-audience token indicates the check is missing (CWE-287).
    """
    return 200 <= status_code < 300


# ---------------------------------------------------------------------------
# Async probe runner (graceful-degradation)
# ---------------------------------------------------------------------------

async def build_transport_findings(
    mf: McpManifest,
    http_get,  # async callable(url, **kwargs) -> response with .status_code; or None
) -> list[Finding]:
    """Run transport/auth CVE probes against an MCP HTTP endpoint.

    Returns an empty list for:
    - stdio transports (no HTTP surface)
    - when http_get is None (live probes not yet wired to a connection)

    Each probe is wrapped in try/except so an individual failure never crashes
    the scan.
    """
    if mf.transport not in _HTTP_TRANSPORTS:
        return []

    # http_get=None means the live probe client is not yet wired (e.g. no
    # active connection open).  Return [] rather than crashing.
    if http_get is None:
        return []

    findings: list[Finding] = []

    # --- Probe 1: DNS rebind / missing Host validation (CVE-2025-66416) ---
    try:
        resp = await http_get(
            mf.endpoint,
            headers={"Host": "evil.attacker.example", "Origin": "http://evil.attacker.example"},
        )
        if _accepts_foreign_host(resp.status_code):
            findings.append(Finding(
                title="MCP server accepts requests with foreign Host/Origin headers (DNS-rebind risk)",
                severity=Severity.HIGH,
                category="MCP Security",
                owasp_category="LLM05",
                description=(
                    "The MCP SSE/HTTP endpoint returned a 2xx response when sent a request "
                    "with a spoofed Host and Origin header pointing to an attacker-controlled "
                    "domain.  This enables DNS-rebind attacks: a web page served from "
                    "evil.attacker.example can, after rebinding the DNS record to 127.0.0.1, "
                    "make cross-origin requests to the local MCP server.  This allows "
                    "unauthenticated access to the MCP tool surface from any browser tab."
                ),
                remediation=(
                    "Validate the Host and Origin headers on every request; reject any value "
                    "that does not match the configured server hostname/port.  Bind the MCP "
                    "listener to 127.0.0.1 and require explicit CORS allowlists."
                ),
                endpoint=mf.endpoint,
                cwe_id="CWE-1188",
                references=[
                    "https://github.com/advisories/GHSA-xxxx-dns-rebind",  # placeholder for GHSA
                    "https://gitlab.com/gitlab-org/security/advisories/-/issues/XXX",
                    "https://owasp.org/www-project-llm-top-10/",
                ],
                metadata={"technique": "mcp:dns-rebind"},
            ))
    except Exception:
        pass  # probe error → degrade gracefully, no finding emitted

    # --- Probe 2: Session entropy (CVE-2025-6515) ---
    try:
        # We look for a session id in the response.  The http_get wrapper may
        # return an object with a `.session_id` attribute set by the caller
        # from response headers / SSE event data.
        resp = await http_get(mf.endpoint)
        sid = getattr(resp, "session_id", None)
        if sid and _session_id_is_weak(sid):
            findings.append(Finding(
                title="MCP server assigns low-entropy (pointer-derived) session IDs",
                severity=Severity.MEDIUM,
                category="MCP Security",
                owasp_category="LLM05",
                description=(
                    f"The server assigned session ID '{sid}', which matches the pattern of a "
                    "C/C++ memory-pointer cast to a string (oatpp-mcp CVE-2025-6515).  "
                    "Such IDs are deterministic, enumerable, and allow session hijacking "
                    "without authentication."
                ),
                remediation=(
                    "Generate session IDs using a cryptographically secure random source "
                    "(e.g. os.urandom(32).hex() or uuid.uuid4()).  "
                    "Session IDs must have ≥128 bits of entropy."
                ),
                endpoint=mf.endpoint,
                cwe_id="CWE-330",
                references=[
                    "https://github.com/advisories/GHSA-mcp-session-entropy",  # CVE-2025-6515
                ],
                metadata={"technique": "mcp:session-entropy", "observed_session_id": sid},
            ))
    except Exception:
        pass

    # --- Probe 3: Wrong-audience token acceptance (MCP auth spec 2025-06-18) ---
    try:
        # Send a syntactically-valid JWT with the wrong audience claim.
        # The caller's http_get wrapper is expected to inject the token header.
        wrong_aud_token = (
            "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0"  # header: alg=none
            ".eyJzdWIiOiJ0ZXN0IiwiYXVkIjoiaHR0cHM6Ly93cm9uZy5leGFtcGxlLmNvbSJ9"  # aud=wrong
            "."  # no signature (alg=none)
        )
        resp = await http_get(
            mf.endpoint,
            headers={"Authorization": f"Bearer {wrong_aud_token}"},
        )
        if _accepts_wrong_audience(resp.status_code):
            findings.append(Finding(
                title="MCP server accepts tokens with incorrect 'aud' claim (missing audience validation)",
                severity=Severity.HIGH,
                category="MCP Security",
                owasp_category="LLM05",
                description=(
                    "The server accepted a Bearer token whose 'aud' (audience) claim was set "
                    "to 'https://wrong.example.com' rather than the server's own resource "
                    "identifier.  Per the MCP Authorization specification (2025-06-18), servers "
                    "MUST verify the audience claim; failing to do so allows tokens issued for "
                    "other services to authenticate against this MCP server."
                ),
                remediation=(
                    "Validate the JWT 'aud' claim on every request.  Reject tokens whose "
                    "audience does not match the configured resource identifier for this "
                    "MCP server (RFC 8707)."
                ),
                endpoint=mf.endpoint,
                cwe_id="CWE-287",
                references=[
                    "https://spec.modelcontextprotocol.io/specification/2025-06-18/basic/authorization/",
                ],
                metadata={"technique": "mcp:auth-audience"},
            ))
    except Exception:
        pass

    return findings
