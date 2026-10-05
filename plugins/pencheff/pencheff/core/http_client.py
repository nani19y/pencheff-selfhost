"""Shared async HTTP client with credential injection, rate limiting, and logging."""

from __future__ import annotations

import asyncio
import time
from typing import Any

import httpx

from pencheff.config import DEFAULT_REQUEST_TIMEOUT, MAX_REQUESTS_PER_SECOND, MAX_RESPONSE_SIZE
from pencheff.core.credentials import CredentialSet
from pencheff.core.session import PentestSession

# A current, realistic browser User-Agent. WAFs (ThreatX/Cloudflare/…) block on
# scanner-identifying UAs, so we blend in by default; operators can override via
# kind_config.headers. (Was "PencheffScanner/0.1" — an instant WAF red flag.)
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
)


def _session_net_config(session: PentestSession) -> tuple[str | None, dict[str, str]]:
    """(proxy, extra_headers) from the session's operator kind_config.

    Lets a scan route around IP-based WAF blocks: kind_config.proxy is a clean
    egress (http(s)://…) and kind_config.headers are merged into every request
    (realistic UA / Origin / auth). Read lazily to avoid an import cycle and to
    pick up config set after the client was constructed.
    """
    try:
        from pencheff.artifact_tools import _kind_config_for_session
    except Exception:  # noqa: BLE001
        return None, {}
    cfg = _kind_config_for_session(getattr(session, "id", "")) or {}
    proxy = cfg.get("proxy") or None
    headers = cfg.get("headers") if isinstance(cfg.get("headers"), dict) else {}
    return proxy, dict(headers or {})


class PencheffHTTPClient:
    """Async HTTP client wrapper for pentest operations."""

    def __init__(
        self,
        session: PentestSession,
        credential_set: str = "default",
        verify_ssl: bool = False,
        timeout: float = DEFAULT_REQUEST_TIMEOUT,
        max_rps: float = MAX_REQUESTS_PER_SECOND,
        http2: bool = False,
    ):
        self.session = session
        self._cred_name = credential_set
        self._verify_ssl = verify_ssl
        self._timeout = timeout
        self._max_rps = max_rps
        self._http2 = http2
        self._min_interval = 1.0 / max_rps if max_rps > 0 else 0
        self._last_request_time = 0.0
        self._client: httpx.AsyncClient | None = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            proxy, _ = _session_net_config(self.session)
            kwargs: dict[str, Any] = dict(
                verify=self._verify_ssl,
                timeout=httpx.Timeout(self._timeout),
                follow_redirects=True,
                max_redirects=5,
                limits=httpx.Limits(max_connections=20, max_keepalive_connections=10),
                http2=self._http2,
            )
            if proxy:
                kwargs["proxy"] = proxy  # httpx>=0.26 uses `proxy=`; CONNECT-tunnels https
            self._client = httpx.AsyncClient(**kwargs)
        return self._client

    def _get_creds(self) -> CredentialSet | None:
        return self.session.credentials.get(self._cred_name)

    async def _rate_limit(self):
        if self._min_interval > 0:
            elapsed = time.monotonic() - self._last_request_time
            if elapsed < self._min_interval:
                await asyncio.sleep(self._min_interval - elapsed)
            self._last_request_time = time.monotonic()

    async def request(
        self,
        method: str,
        url: str,
        headers: dict[str, str] | None = None,
        body: str | None = None,
        json_data: Any = None,
        params: dict[str, str] | None = None,
        follow_redirects: bool = True,
        inject_creds: bool = True,
        module: str = "unknown",
    ) -> httpx.Response:
        await self._rate_limit()
        client = await self._get_client()

        req_headers = dict(headers or {})
        # Operator-supplied headers (realistic UA / Origin / …) blend scanner
        # traffic past signature-based WAF rules. Explicit per-call headers win.
        _, cfg_headers = _session_net_config(self.session)
        for k, v in cfg_headers.items():
            req_headers.setdefault(k, v)
        req_headers.setdefault("User-Agent", DEFAULT_USER_AGENT)

        if inject_creds:
            creds = self._get_creds()
            if creds:
                req_headers = creds.inject_into_headers(req_headers)

        start = time.monotonic()
        kwargs: dict[str, Any] = {
            "method": method,
            "url": url,
            "headers": req_headers,
            "follow_redirects": follow_redirects,
        }
        if body is not None:
            kwargs["content"] = body
        if json_data is not None:
            kwargs["json"] = json_data
        if params:
            kwargs["params"] = params

        # OTel client span. Attributes are *redacted* before being set
        # because httpx headers may contain auth (we just injected
        # creds at line 81 — `req_headers` carries them) and the URL
        # query may carry tokens. Without redaction the span lives in
        # otel_spans for `retention_days` days with the secret intact.
        # The span is a no-op when OTel is disabled or absent.
        span_cm = None
        span = None
        try:
            from opentelemetry import trace
            from pencheff.observability.redact import redact_headers, redact_url
            tracer = trace.get_tracer("pencheff.http_client")
            span_cm = tracer.start_as_current_span(
                f"http.{method.lower()}",
                attributes={
                    "http.method": method,
                    "http.url": redact_url(url),
                    "http.request.headers.count": len(req_headers),
                    "pencheff.module": module,
                },
            )
            span = span_cm.__enter__()
        except Exception:
            span_cm = None

        try:
            try:
                response = await client.request(**kwargs)
                duration_ms = (time.monotonic() - start) * 1000
                self.session.log_request(method, url, response.status_code, module, duration_ms)
                if span is not None:
                    try:
                        span.set_attribute("http.status_code", response.status_code)
                        span.set_attribute("http.duration_ms", duration_ms)
                        cl = response.headers.get("content-length")
                        if cl and cl.isdigit():
                            span.set_attribute("http.response.size", int(cl))
                    except Exception:
                        pass
                return response
            except httpx.HTTPError as e:
                duration_ms = (time.monotonic() - start) * 1000
                self.session.log_request(method, url, None, module, duration_ms)
                if span is not None:
                    try:
                        span.set_attribute("http.error", type(e).__name__)
                        span.set_attribute("http.duration_ms", duration_ms)
                    except Exception:
                        pass
                raise
        finally:
            if span_cm is not None:
                try:
                    span_cm.__exit__(None, None, None)
                except Exception:
                    pass

    async def get(self, url: str, module: str = "unknown", **kwargs) -> httpx.Response:
        return await self.request("GET", url, module=module, **kwargs)

    async def post(self, url: str, module: str = "unknown", **kwargs) -> httpx.Response:
        return await self.request("POST", url, module=module, **kwargs)

    async def put(self, url: str, module: str = "unknown", **kwargs) -> httpx.Response:
        return await self.request("PUT", url, module=module, **kwargs)

    async def delete(self, url: str, module: str = "unknown", **kwargs) -> httpx.Response:
        return await self.request("DELETE", url, module=module, **kwargs)

    async def options(self, url: str, module: str = "unknown", **kwargs) -> httpx.Response:
        return await self.request("OPTIONS", url, module=module, **kwargs)

    async def raw_request(
        self,
        host: str,
        port: int,
        raw_bytes: bytes,
        module: str = "unknown",
        timeout: float = 10.0,
        use_tls: bool = False,
    ) -> bytes:
        """Send raw bytes over a TCP connection. Essential for HTTP smuggling
        where malformed HTTP that httpx would refuse to construct is required."""
        start = time.monotonic()
        try:
            if use_tls:
                import ssl as _ssl
                ctx = _ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = _ssl.CERT_NONE
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port, ssl=ctx),
                    timeout=timeout,
                )
            else:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=timeout,
                )
            writer.write(raw_bytes)
            await writer.drain()
            response = await asyncio.wait_for(reader.read(65536), timeout=timeout)
            writer.close()
            duration_ms = (time.monotonic() - start) * 1000
            self.session.log_request("RAW", f"{host}:{port}", None, module, duration_ms)
            return response
        except Exception:
            duration_ms = (time.monotonic() - start) * 1000
            self.session.log_request("RAW", f"{host}:{port}", None, module, duration_ms)
            raise

    async def websocket_connect(
        self,
        url: str,
        headers: dict[str, str] | None = None,
        module: str = "unknown",
    ):
        """Open a WebSocket connection. Returns a websockets connection object.
        Requires the 'websockets' package."""
        try:
            import websockets
        except ImportError:
            raise ImportError(
                "The 'websockets' package is required for WebSocket testing. "
                "Install it with: pip install websockets"
            )

        extra_headers = dict(headers or {})
        _, cfg_headers = _session_net_config(self.session)
        for k, v in cfg_headers.items():
            extra_headers.setdefault(k, v)
        extra_headers.setdefault("User-Agent", DEFAULT_USER_AGENT)

        creds = self._get_creds()
        if creds:
            extra_headers = creds.inject_into_headers(extra_headers)

        start = time.monotonic()
        try:
            ws = await websockets.connect(
                url,
                additional_headers=extra_headers,
                close_timeout=self._timeout,
                open_timeout=self._timeout,
            )
            duration_ms = (time.monotonic() - start) * 1000
            self.session.log_request("WS_CONNECT", url, None, module, duration_ms)
            return ws
        except Exception:
            duration_ms = (time.monotonic() - start) * 1000
            self.session.log_request("WS_CONNECT", url, None, module, duration_ms)
            raise

    async def close(self):
        if self._client:
            await self._client.aclose()
            self._client = None
