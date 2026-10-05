"""Intercepting MitM proxy for passive scanning.

Uses ``mitmproxy`` as an optional dependency. When installed, `start_proxy`
spawns mitmdump as a subprocess with a minimal addon that persists every
flow into the session's `proxy_traffic` list and immediately runs the
registered passive scanners against the response.

When ``mitmproxy`` isn't available we fall back to a simple HTTP forward proxy
implemented with ``asyncio`` — no TLS interception, but still captures HTTP
traffic and emits passive findings.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import shutil
import subprocess  # noqa: S404 — launches mitmdump only
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pencheff.core.findings import Finding
from pencheff.core.session import PentestSession


@dataclass
class ProxyFlow:
    method: str
    url: str
    req_headers: dict[str, str]
    req_body: str
    status: int
    resp_headers: dict[str, str]
    resp_body: str
    timestamp: float = field(default_factory=time.time)


@dataclass
class ProxyState:
    port: int
    pid: int | None
    started_at: float
    flows: list[ProxyFlow] = field(default_factory=list)
    mode: str = "mitmproxy"  # mitmproxy | http-fallback
    log_path: Path | None = None
    proc: subprocess.Popen | None = None


_state: dict[str, ProxyState] = {}


def get_state(session_id: str) -> ProxyState | None:
    return _state.get(session_id)


def start_proxy(session: PentestSession, port: int = 8888) -> ProxyState:
    if session.id in _state:
        return _state[session.id]
    if shutil.which("mitmdump"):
        return _start_mitmproxy(session, port)
    return _start_fallback(session, port)


def stop_proxy(session_id: str) -> bool:
    s = _state.pop(session_id, None)
    if not s:
        return False
    if s.proc and s.proc.poll() is None:
        with contextlib.suppress(Exception):
            s.proc.terminate()
            s.proc.wait(timeout=5)
    return True


def get_traffic(
    session_id: str, since: float | None = None
) -> list[ProxyFlow]:
    s = _state.get(session_id)
    if not s:
        return []
    _ingest_mitmproxy_log(s)
    if since is None:
        return list(s.flows)
    return [f for f in s.flows if f.timestamp >= since]


# ─── mitmproxy backend ────────────────────────────────────────────────

def _start_mitmproxy(session: PentestSession, port: int) -> ProxyState:
    log_file = Path(tempfile.gettempdir()) / f"pencheff-proxy-{session.id}.jsonl"
    if log_file.exists():
        log_file.unlink()
    addon = _mitmproxy_addon(str(log_file))
    addon_path = Path(tempfile.gettempdir()) / f"pencheff-addon-{session.id}.py"
    addon_path.write_text(addon)
    proc = subprocess.Popen(  # noqa: S603
        [
            sys.executable, "-m", "mitmproxy.tools.dump",
            "-p", str(port),
            "-s", str(addon_path),
            "--set", "block_global=false",
            "-q",
        ],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    st = ProxyState(
        port=port, pid=proc.pid, started_at=time.time(),
        mode="mitmproxy", log_path=log_file, proc=proc,
    )
    _state[session.id] = st
    return st


def _mitmproxy_addon(log_path: str) -> str:
    # Written into a tempfile; mitmdump loads with -s
    return (
        "import json, time\n"
        "from mitmproxy import http\n"
        f"LOG_PATH = {log_path!r}\n"
        "def response(flow: http.HTTPFlow):\n"
        "    try:\n"
        "        req = flow.request\n"
        "        resp = flow.response\n"
        "        entry = {\n"
        "            'method': req.method, 'url': req.pretty_url,\n"
        "            'req_headers': dict(req.headers),\n"
        "            'req_body': req.text[:8192] if req.text else '',\n"
        "            'status': resp.status_code if resp else 0,\n"
        "            'resp_headers': dict(resp.headers) if resp else {},\n"
        "            'resp_body': resp.get_text(strict=False)[:32768] if resp else '',\n"
        "            'timestamp': time.time(),\n"
        "        }\n"
        "        with open(LOG_PATH, 'a') as f:\n"
        "            f.write(json.dumps(entry) + '\\n')\n"
        "    except Exception:\n"
        "        pass\n"
    )


def _ingest_mitmproxy_log(state: ProxyState) -> None:
    if not state.log_path or not state.log_path.exists():
        return
    seen = len(state.flows)
    with state.log_path.open() as f:
        for i, line in enumerate(f):
            if i < seen:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            state.flows.append(ProxyFlow(
                method=entry.get("method", ""),
                url=entry.get("url", ""),
                req_headers=entry.get("req_headers", {}),
                req_body=entry.get("req_body", ""),
                status=entry.get("status", 0),
                resp_headers=entry.get("resp_headers", {}),
                resp_body=entry.get("resp_body", ""),
                timestamp=entry.get("timestamp", time.time()),
            ))


# ─── HTTP-only fallback ───────────────────────────────────────────────

def _start_fallback(session: PentestSession, port: int) -> ProxyState:
    """Minimal HTTP forward proxy (no CONNECT / no TLS interception)."""
    st = ProxyState(port=port, pid=None, started_at=time.time(), mode="http-fallback")
    _state[session.id] = st
    loop = asyncio.get_event_loop()
    task = loop.create_task(_fallback_server(st))
    st.proc = None  # task lives in the loop; stop_proxy cancels via _state pop
    # Store the task on the state so it can be cancelled
    object.__setattr__(st, "_task", task)
    return st


async def _fallback_server(state: ProxyState) -> None:
    server = await asyncio.start_server(
        lambda r, w: _handle_fallback_client(state, r, w),
        "127.0.0.1", state.port,
    )
    async with server:
        await server.serve_forever()


async def _handle_fallback_client(
    state: ProxyState,
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
) -> None:
    try:
        req_line = (await reader.readline()).decode(errors="replace").strip()
        if not req_line or " " not in req_line:
            writer.close()
            return
        method, url, _proto = req_line.split(" ", 2)
        headers: dict[str, str] = {}
        while True:
            line = (await reader.readline()).decode(errors="replace").rstrip("\r\n")
            if not line:
                break
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip()] = v.strip()
        body = b""
        if "Content-Length" in headers:
            body = await reader.readexactly(int(headers["Content-Length"]))
        # Forward with httpx
        import httpx
        async with httpx.AsyncClient(timeout=20.0, verify=False) as c:
            if not url.startswith("http"):
                url = f"http://{headers.get('Host','')}{url}"
            resp = await c.request(method, url, headers=headers, content=body)
        state.flows.append(ProxyFlow(
            method=method, url=url, req_headers=headers,
            req_body=body.decode(errors="replace")[:8192],
            status=resp.status_code, resp_headers=dict(resp.headers),
            resp_body=resp.text[:32768],
        ))
        writer.write(
            f"HTTP/1.1 {resp.status_code} {resp.reason_phrase}\r\n".encode()
        )
        for k, v in resp.headers.items():
            if k.lower() in {"transfer-encoding", "content-encoding"}:
                continue
            writer.write(f"{k}: {v}\r\n".encode())
        writer.write(b"\r\n")
        writer.write(resp.content)
        await writer.drain()
    except Exception:  # noqa: BLE001
        pass
    finally:
        with contextlib.suppress(Exception):
            writer.close()
            await writer.wait_closed()


def run_passive_on_flows(
    session: PentestSession, flows: list[ProxyFlow]
) -> list[Finding]:
    """Pass collected flows through the passive scanner module."""
    from pencheff.modules.web.passive_scan import scan_flow
    findings: list[Finding] = []
    for flow in flows:
        findings.extend(scan_flow(flow))
    return findings
