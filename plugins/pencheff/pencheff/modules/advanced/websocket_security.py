"""WebSocket security testing module."""

from __future__ import annotations

import asyncio
from typing import Any
from urllib.parse import urlparse

from pencheff.config import Severity
from pencheff.core.findings import Evidence, Finding
from pencheff.core.http_client import PencheffHTTPClient
from pencheff.core.payload_loader import load_payloads
from pencheff.core.session import PentestSession
from pencheff.modules.base import BaseTestModule

# Injection payloads for WebSocket messages
WS_INJECTION_PAYLOADS = [
    '<script>alert(1)</script>',
    "' OR 1=1--",
    '{"__proto__":{"admin":true}}',
    '; ls -la',
    '{{7*7}}',
]


class WebSocketSecurityModule(BaseTestModule):
    """Test WebSocket security: CSWSH, auth bypass, message injection, transport security."""

    name = "websocket_security"
    category = "websocket"
    owasp_categories = ["A07", "A03"]
    description = "WebSocket hijacking, auth bypass, message injection, insecure transport"

    def get_techniques(self) -> list[str]:
        return [
            "cswsh_detection",
            "auth_bypass",
            "message_injection",
            "insecure_transport",
            "websocket_discovery",
        ]

    async def run(
        self,
        session: PentestSession,
        http: PencheffHTTPClient,
        targets: list[str] | None = None,
        config: dict[str, Any] | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []

        # Discover WebSocket endpoints
        ws_urls = targets or [ep["url"] for ep in session.discovered.websocket_endpoints]
        # websocket-KIND targets: base_url IS the ws://|wss:// endpoint. The
        # deterministic populator seeds it into discovered.endpoints/api_specs
        # (not websocket_endpoints), and the breaker session carries it as
        # session.target.base_url — either way the probes below need it, and
        # _discover_websockets can't recover it (it HTTP-GETs paths, which fails
        # on a ws:// scheme). Seed it directly so CSWSH/auth/injection actually run.
        if not ws_urls:
            base = (session.target.base_url or "").strip()
            if base.startswith(("ws://", "wss://")):
                ws_urls = [base]
        if not ws_urls:
            ws_urls = await self._discover_websockets(http, session)

        for url in ws_urls[:10]:
            # Insecure transport is a URL-property check — no connection needed,
            # so it runs even when the endpoint refuses the handshake below.
            if url.startswith("ws://"):
                findings.append(Finding(
                    title=f"Insecure WebSocket Transport: {url}",
                    severity=Severity.MEDIUM,
                    category="websocket",
                    owasp_category="A02",
                    description=(
                        f"WebSocket endpoint uses unencrypted ws:// protocol instead of wss://. "
                        f"Data transmitted over this connection can be intercepted by MITM attackers."
                    ),
                    remediation="Use wss:// (WebSocket Secure) for all WebSocket connections.",
                    endpoint=url,
                    cwe_id="CWE-319",
                    cvss_score=5.9,
                    cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
                ))

            # CSWSH doubles as the reachability probe: it connects with an
            # attacker Origin. On a rejected handshake it emits an INFO finding
            # explaining why — and the remaining probes can't run either, so we
            # skip them (no point hammering a rate-limited endpoint).
            cswsh = await self._test_cswsh(http, url, session)
            findings.extend(cswsh)
            if any("Handshake Rejected" in f.title for f in cswsh):
                continue

            # Test auth bypass
            findings.extend(await self._test_auth_bypass(http, url, session))
            # Test message injection
            findings.extend(await self._test_message_injection(http, url, session))
            # Test message replay (no nonce / anti-replay control)
            findings.extend(await self._test_message_replay(http, url, session))

        return findings

    async def _discover_websockets(
        self, http: PencheffHTTPClient, session: PentestSession,
    ) -> list[str]:
        """Discover WebSocket endpoints by checking Upgrade responses and scanning JS."""
        ws_urls: list[str] = []
        base_url = session.target.base_url
        parsed = urlparse(base_url)

        # Check common WebSocket paths
        ws_paths = ["/ws", "/websocket", "/socket", "/ws/", "/socket.io/", "/hub", "/signalr"]
        for path in ws_paths:
            url = f"{base_url}{path}"
            try:
                resp = await http.get(
                    url,
                    headers={"Upgrade": "websocket", "Connection": "Upgrade",
                             "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
                             "Sec-WebSocket-Version": "13"},
                    module="websocket_security",
                )
                # RFC 6455 §4.2.2: a real upgrade reply is HTTP/1.1 101 with
                # Connection: Upgrade, Upgrade: websocket, and a Sec-WebSocket-
                # Accept header. The previous check accepted *either* 101
                # *or* "upgrade" appearing anywhere in the Connection header,
                # which a CDN echoing "keep-alive, upgrade" could spoof.
                conn_hdr = resp.headers.get("connection", "").lower()
                upgrade_hdr = resp.headers.get("upgrade", "").lower()
                accept_hdr = resp.headers.get("sec-websocket-accept", "")
                is_real_upgrade = (
                    resp.status_code == 101
                    and "upgrade" in conn_hdr
                    and "websocket" in upgrade_hdr
                    and bool(accept_hdr)
                )
                if is_real_upgrade:
                    ws_scheme = "wss" if parsed.scheme == "https" else "ws"
                    ws_url = f"{ws_scheme}://{parsed.netloc}{path}"
                    ws_urls.append(ws_url)
                    session.discovered.websocket_endpoints.append({
                        "url": ws_url, "path": path, "discovered_via": "upgrade_probe",
                    })
            except Exception:
                continue

        # Scan JavaScript files for ws:// / wss:// URLs
        for ep in session.discovered.endpoints[:20]:
            url = ep.get("url", "")
            if url.endswith(".js"):
                try:
                    resp = await http.get(url, module="websocket_security")
                    import re
                    ws_matches = re.findall(r'wss?://[^\s\'"<>]+', resp.text)
                    for match in ws_matches:
                        if match not in ws_urls:
                            ws_urls.append(match)
                            session.discovered.websocket_endpoints.append({
                                "url": match, "discovered_via": "javascript_scan",
                            })
                except Exception:
                    continue

        return ws_urls

    async def _test_cswsh(
        self, http: PencheffHTTPClient, url: str, session: PentestSession,
    ) -> list[Finding]:
        """Test for Cross-Site WebSocket Hijacking — connect with attacker Origin."""
        findings: list[Finding] = []

        attacker_origin = "https://evil.com"
        try:
            ws = await http.websocket_connect(
                url,
                headers={"Origin": attacker_origin},
                module="websocket_security",
            )
            # If connection succeeds with attacker origin, CSWSH is possible
            await ws.close()
            findings.append(Finding(
                title=f"Cross-Site WebSocket Hijacking (CSWSH): {url}",
                severity=Severity.HIGH,
                category="websocket",
                owasp_category="A07",
                description=(
                    f"The WebSocket endpoint accepts connections from arbitrary Origins "
                    f"(tested: '{attacker_origin}'). An attacker can hijack "
                    f"the WebSocket connection via a malicious webpage, stealing data "
                    f"or performing actions as the victim."
                ),
                remediation=(
                    "Validate the Origin header on WebSocket upgrade requests. "
                    "Only accept connections from trusted origins. "
                    "Implement CSRF tokens for WebSocket authentication."
                ),
                endpoint=url,
                evidence=[Evidence(
                    request_method="WS_CONNECT",
                    request_url=url,
                    request_headers={"Origin": attacker_origin},
                    description="WebSocket connection accepted from attacker origin",
                )],
                cwe_id="CWE-346",
                cvss_score=8.1,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
            ))
        except Exception as exc:
            # Handshake rejected → the origin probe (and every other probe on
            # this URL) can't run. Surface WHY rather than silently returning
            # nothing — a rejected handshake (HTTP 429 rate-limit, origin/auth
            # block, TLS error, timeout) reads as "no issues" otherwise, which
            # is exactly how a throttled endpoint gets mistaken for a clean one.
            findings.append(Finding(
                title=f"WebSocket Handshake Rejected — Probes Could Not Run: {url}",
                severity=Severity.INFO,
                category="websocket",
                owasp_category="A07",
                description=(
                    f"The server rejected the WebSocket handshake "
                    f"({type(exc).__name__}: {str(exc)[:140]}). CSWSH, message-injection, "
                    f"auth-bypass and replay tests could NOT execute against this endpoint. "
                    f"Common causes: rate-limiting (HTTP 429), an Origin/auth block, or an "
                    f"upstream proxy/WAF. This is not evidence the endpoint is secure."
                ),
                remediation=(
                    "Re-run from an allowlisted source IP or lower the scan rate. If the "
                    "handshake is blocked by design (Origin/auth enforcement), that is a "
                    "positive security control."
                ),
                endpoint=url,
                evidence=[Evidence(
                    request_method="WS_CONNECT",
                    request_url=url,
                    request_headers={"Origin": attacker_origin},
                    description=f"Handshake rejected: {type(exc).__name__}: {str(exc)[:200]}",
                )],
                cwe_id="CWE-346",
            ))

        return findings

    async def _test_auth_bypass(
        self, http: PencheffHTTPClient, url: str, session: PentestSession,
    ) -> list[Finding]:
        """Test if WebSocket accepts connections without authentication."""
        findings: list[Finding] = []

        try:
            # Connect without any credentials
            ws = await http.websocket_connect(
                url, headers={}, module="websocket_security",
            )
            # Try sending a message
            await ws.send('{"type":"ping"}')
            try:
                response = await asyncio.wait_for(ws.recv(), timeout=5)
                findings.append(Finding(
                    title=f"WebSocket Auth Bypass: {url}",
                    severity=Severity.HIGH,
                    category="websocket",
                    owasp_category="A07",
                    description=(
                        f"The WebSocket endpoint accepts unauthenticated connections and "
                        f"processes messages. An attacker can interact with the WebSocket "
                        f"without valid credentials."
                    ),
                    remediation="Require authentication tokens for WebSocket connections. Validate credentials on each message.",
                    endpoint=url,
                    evidence=[Evidence(
                        request_method="WS_CONNECT",
                        request_url=url,
                        response_body_snippet=str(response)[:300],
                        description="WebSocket accepted unauthenticated connection and responded to message",
                    )],
                    cwe_id="CWE-306",
                    cvss_score=7.5,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                ))
            except asyncio.TimeoutError:
                pass
            await ws.close()
        except Exception:
            pass

        return findings

    async def _test_message_injection(
        self, http: PencheffHTTPClient, url: str, session: PentestSession,
    ) -> list[Finding]:
        """Test for injection vulnerabilities through WebSocket messages."""
        findings: list[Finding] = []
        payloads = load_payloads("websocket.txt") or WS_INJECTION_PAYLOADS

        try:
            ws = await http.websocket_connect(url, module="websocket_security")
        except Exception:
            return findings

        # Genuine server-side error signatures. Deliberately NOT generic words
        # like "error"/"command" — those match reflected payloads (e.g. the
        # "onerror=" in an echoed <img> XSS string, or "; ls -la"), producing
        # false positives on echo/broadcast endpoints. Every signature here is
        # specific enough that it cannot appear inside our own payloads.
        error_signatures = [
            "sql syntax", "sqlstate", "syntaxerror", "traceback (most recent",
            "unhandled exception", "stack trace", "unexpected token",
            "cannot read propert", "segmentation fault", "internal server error",
        ]

        # Drain an unsolicited greeting frame (e.g. echo.websocket.org sends
        # one on connect) so send↔recv stay aligned — otherwise recv() returns
        # the echo of the *previous* payload and evidence is misattributed.
        try:
            await asyncio.wait_for(ws.recv(), timeout=1.5)
        except Exception:
            pass

        reflected: str | None = None
        try:
            for payload in payloads[:10]:
                try:
                    await ws.send(payload)
                    response = await asyncio.wait_for(ws.recv(), timeout=3)
                except asyncio.TimeoutError:
                    continue
                resp_str = str(response)
                resp_lower = resp_str.lower()

                # A real server-side error provoked by the payload → injection.
                if any(sig in resp_lower for sig in error_signatures):
                    findings.append(Finding(
                        title=f"WebSocket Message Injection: {url}",
                        severity=Severity.MEDIUM,
                        category="websocket",
                        owasp_category="A03",
                        description=(
                            f"Injection payload via WebSocket message provoked a server-side "
                            f"error, indicating input reaches an interpreter without sanitisation. "
                            f"Payload: '{payload[:50]}'"
                        ),
                        remediation="Validate and sanitize all WebSocket message content. Apply the same input validation as HTTP endpoints.",
                        endpoint=url,
                        evidence=[Evidence(
                            request_method="WS_SEND",
                            request_url=url,
                            request_body=payload,
                            response_body_snippet=resp_str[:300],
                            description="Injection payload provoked a server-side error",
                        )],
                        cwe_id="CWE-74",
                        cvss_score=6.5,
                    ))
                    break

                # Verbatim reflection of a markup/template payload — a potential
                # XSS/SSTI sink if the value is later rendered to another client.
                # Reflection alone is not a confirmed server-side injection, so
                # this is LOW (not the error-based finding above).
                if reflected is None and payload in resp_str and any(
                    c in payload for c in "<>{}"
                ):
                    reflected = payload

            if reflected and not findings:
                findings.append(Finding(
                    title=f"WebSocket Reflects Unsanitized Input: {url}",
                    severity=Severity.LOW,
                    category="websocket",
                    owasp_category="A03",
                    description=(
                        f"The WebSocket endpoint reflects client-supplied markup back verbatim "
                        f"(payload: '{reflected[:50]}'). If a consuming client renders this without "
                        f"encoding, it is a cross-site scripting / template-injection sink."
                    ),
                    remediation="Context-encode all WebSocket message content before rendering it in any client. Never treat inbound frames as trusted markup.",
                    endpoint=url,
                    evidence=[Evidence(
                        request_method="WS_SEND",
                        request_url=url,
                        request_body=reflected,
                        response_body_snippet=reflected[:300],
                        description="Payload reflected back verbatim (not encoded)",
                    )],
                    cwe_id="CWE-79",
                    cvss_score=3.7,
                ))
        finally:
            await ws.close()

        return findings

    async def _test_message_replay(
        self, http: PencheffHTTPClient, url: str, session: PentestSession,
    ) -> list[Finding]:
        """Resend an identical frame and check the server processes it again —
        i.e. it has no nonce / sequence / anti-replay control."""
        findings: list[Finding] = []

        try:
            ws = await http.websocket_connect(url, module="websocket_security")
        except Exception:
            return findings

        try:
            # Drain any greeting so the two probe responses are comparable.
            try:
                await asyncio.wait_for(ws.recv(), timeout=1.5)
            except Exception:
                pass

            # Neutral probe — must NOT contain any rejection keyword below, or
            # an echo endpoint reflects it back and we'd read our own probe as
            # a rejection.
            probe = '{"pencheff":"seqcheck","n":1}'
            try:
                await ws.send(probe)
                r1 = await asyncio.wait_for(ws.recv(), timeout=3)
            except asyncio.TimeoutError:
                return findings  # no baseline response — can't assess replay

            try:
                await ws.send(probe)  # identical frame, replayed
                r2 = await asyncio.wait_for(ws.recv(), timeout=3)
            except asyncio.TimeoutError:
                return findings  # replay dropped → looks like anti-replay exists

            # A verbatim echo of the replayed frame = it was accepted a second
            # time. Otherwise, look for an explicit duplicate/nonce rejection.
            r2_str = str(r2)
            echoed = probe in r2_str
            r2_lower = r2_str.lower()
            rejected = (not echoed) and any(
                w in r2_lower
                for w in ["duplicate", "replay", "nonce", "already", "expired", "stale"]
            )
            if not rejected:
                findings.append(Finding(
                    title=f"No WebSocket Message Replay Protection: {url}",
                    severity=Severity.LOW,
                    category="websocket",
                    owasp_category="A04",
                    description=(
                        "An identical WebSocket frame was accepted and processed twice with no "
                        "nonce, sequence number, or duplicate rejection. For a state-changing or "
                        "authenticated channel this allows replay attacks (e.g. re-submitting a "
                        "captured privileged message)."
                    ),
                    remediation="Add a per-message nonce or monotonic sequence number and reject duplicates/out-of-order frames on state-changing operations.",
                    endpoint=url,
                    evidence=[Evidence(
                        request_method="WS_SEND",
                        request_url=url,
                        request_body=probe,
                        response_body_snippet=str(r2)[:300],
                        description="Replayed frame accepted and processed a second time",
                    )],
                    cwe_id="CWE-294",
                    cvss_score=3.7,
                ))
        finally:
            await ws.close()

        return findings
