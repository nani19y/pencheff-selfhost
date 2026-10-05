"""Pencheff LSP server — JSON-RPC 2.0 over stdio.

Spec covered:
  * initialize / initialized / shutdown / exit
  * textDocument/didOpen
  * textDocument/didSave
  * textDocument/didChange (no-op — we don't run scans on each keystroke)
  * textDocument/publishDiagnostics (server → client)
  * pencheff/refresh (custom — client tells server "rescan history")

The server only consumes existing scan output. It does NOT run scans
itself — that's a deliberate design choice. Running a full DAST scan
on every keystroke would be a disaster; instead, the workflow is:

  1. Developer runs ``pencheff scan --target ...`` from the terminal
     (or a CI scan publishes results back via the API).
  2. Scan results land in ~/.pencheff/history/.
  3. The LSP server picks the change up on its next poll (1s) and
     republishes diagnostics for every open document.

The polling cost is one ``stat`` per second on a directory that rarely
has more than a few dozen files — well below noise.
"""
from __future__ import annotations

import json
import logging
import os
import sys
import threading
import time
from pathlib import Path
from typing import Any

from pencheff.core.scan_history import _history_dir
from pencheff.lsp.diagnostics import findings_to_diagnostics_by_uri


log = logging.getLogger("pencheff.lsp")

_PROTOCOL_VERSION = "1.0.0"
_REFRESH_INTERVAL_SEC = 1.0


# ── JSON-RPC framing ────────────────────────────────────────────────


def _read_message(stream) -> dict[str, Any] | None:
    """Read one LSP message (Content-Length framed) from ``stream``."""
    headers: dict[str, str] = {}
    while True:
        line = stream.readline()
        if not line:
            return None
        line = line.decode("ascii", errors="replace").rstrip("\r\n")
        if not line:
            break
        if ":" in line:
            k, _, v = line.partition(":")
            headers[k.strip().lower()] = v.strip()
    length = int(headers.get("content-length", "0"))
    if length <= 0:
        return None
    body = stream.read(length)
    if not body:
        return None
    try:
        return json.loads(body)
    except json.JSONDecodeError:
        return None


def _write_message(stream, payload: dict[str, Any]) -> None:
    body = json.dumps(payload).encode("utf-8")
    header = f"Content-Length: {len(body)}\r\n\r\n".encode("ascii")
    stream.write(header)
    stream.write(body)
    stream.flush()


# ── Scan-history loader ─────────────────────────────────────────────


def _load_recent_findings(limit: int = 50) -> list[dict[str, Any]]:
    """Read the latest scan files from ``~/.pencheff/history/`` and merge
    their findings, preferring the most recent occurrence of each
    ``finding_id`` to deduplicate across rescans of the same target.
    """
    hist = _history_dir()
    files = sorted(
        (p for p in hist.glob("*.json") if p.is_file()),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )[:limit]
    seen: set[str] = set()
    out: list[dict[str, Any]] = []
    for f in files:
        try:
            data = json.loads(f.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        for finding in data.get("findings") or []:
            fid = finding.get("id") or finding.get("title", "")
            if fid in seen:
                continue
            seen.add(fid)
            out.append(finding)
    return out


def _history_signature() -> tuple:
    """Cheap fingerprint of the history directory used to detect change.

    We only republish diagnostics when this fingerprint changes — sub-
    second polls are essentially free.
    """
    hist = _history_dir()
    files = list(hist.glob("*.json"))
    return tuple(sorted((p.name, p.stat().st_mtime, p.stat().st_size) for p in files))


# ── Server state ────────────────────────────────────────────────────


class PencheffLSP:
    def __init__(self, stdin, stdout) -> None:
        self.stdin = stdin
        self.stdout = stdout
        self.workspace_root: Path = Path.cwd()
        self.open_uris: set[str] = set()
        self.published: dict[str, list[dict[str, Any]]] = {}
        self._last_signature: tuple = ()
        self._shutdown_received = False
        self._stop = threading.Event()
        self._poll_thread: threading.Thread | None = None

    # ── lifecycle ────────────────────────────────────────────────

    def serve_forever(self) -> int:
        self._poll_thread = threading.Thread(
            target=self._poll_history, name="pencheff-lsp-poll", daemon=True,
        )
        self._poll_thread.start()
        try:
            while not self._shutdown_received:
                msg = _read_message(self.stdin)
                if msg is None:
                    break
                self._dispatch(msg)
        except (BrokenPipeError, KeyboardInterrupt):
            pass
        finally:
            self._stop.set()
        return 0

    def _poll_history(self) -> None:
        """Background thread: refresh diagnostics when history changes."""
        while not self._stop.is_set():
            time.sleep(_REFRESH_INTERVAL_SEC)
            try:
                sig = _history_signature()
            except OSError:
                continue
            if sig != self._last_signature:
                self._last_signature = sig
                self._republish_all()

    # ── dispatch ─────────────────────────────────────────────────

    def _dispatch(self, msg: dict[str, Any]) -> None:
        method = msg.get("method")
        msg_id = msg.get("id")
        params = msg.get("params") or {}
        if method == "initialize":
            self._on_initialize(msg_id, params)
        elif method == "initialized":
            self._republish_all()
        elif method == "shutdown":
            self._shutdown_received = True
            self._reply(msg_id, None)
        elif method == "exit":
            sys.exit(0)
        elif method == "textDocument/didOpen":
            uri = (params.get("textDocument") or {}).get("uri")
            if uri:
                self.open_uris.add(uri)
                self._send_diagnostics_for_uri(uri)
        elif method == "textDocument/didClose":
            uri = (params.get("textDocument") or {}).get("uri")
            if uri:
                self.open_uris.discard(uri)
                # Clear the diagnostics for this file in the client.
                self._publish(uri, [])
                self.published.pop(uri, None)
        elif method == "textDocument/didSave":
            uri = (params.get("textDocument") or {}).get("uri")
            if uri:
                self._send_diagnostics_for_uri(uri)
        elif method == "textDocument/didChange":
            # No-op: scan results don't change on edit; we wait for a
            # save / new scan / explicit refresh.
            pass
        elif method == "pencheff/refresh":
            self._republish_all(force=True)
            self._reply(msg_id, {"status": "ok"})
        elif msg_id is not None:
            # Unknown request — return MethodNotFound (-32601).
            self._error(msg_id, -32601, f"Method not found: {method}")

    # ── handlers ─────────────────────────────────────────────────

    def _on_initialize(self, msg_id: Any, params: dict[str, Any]) -> None:
        # Resolve the workspace root from the client's ``rootUri``.
        root_uri = params.get("rootUri") or ""
        if root_uri.startswith("file://"):
            self.workspace_root = Path(root_uri[len("file://"):]).resolve()
        elif params.get("workspaceFolders"):
            wf = params["workspaceFolders"][0]
            uri = wf.get("uri", "")
            if uri.startswith("file://"):
                self.workspace_root = Path(uri[len("file://"):]).resolve()
        else:
            cwd = os.environ.get("PENCHEFF_LSP_WORKSPACE")
            if cwd:
                self.workspace_root = Path(cwd).resolve()
        log.info("Pencheff LSP initialised, workspace=%s", self.workspace_root)
        self._reply(msg_id, {
            "capabilities": {
                "textDocumentSync": {
                    "openClose": True,
                    "save":      {"includeText": False},
                    "change":    1,  # full sync — but we ignore changes
                },
            },
            "serverInfo": {"name": "pencheff-lsp", "version": _PROTOCOL_VERSION},
        })

    def _send_diagnostics_for_uri(self, uri: str) -> None:
        diags = self.published.get(uri, [])
        self._publish(uri, diags)

    def _republish_all(self, force: bool = False) -> None:
        findings = _load_recent_findings()
        by_uri = findings_to_diagnostics_by_uri(findings, self.workspace_root)
        # Files that previously had diagnostics but no longer do still need
        # an empty publish so the client clears its decorations.
        prev = set(self.published)
        new = set(by_uri)
        for uri in prev - new:
            self._publish(uri, [])
        for uri, diags in by_uri.items():
            if force or self.published.get(uri) != diags:
                self._publish(uri, diags)
        self.published = by_uri

    # ── wire helpers ─────────────────────────────────────────────

    def _reply(self, msg_id: Any, result: Any) -> None:
        if msg_id is None:
            return
        _write_message(self.stdout, {
            "jsonrpc": "2.0", "id": msg_id, "result": result,
        })

    def _error(self, msg_id: Any, code: int, message: str) -> None:
        _write_message(self.stdout, {
            "jsonrpc": "2.0", "id": msg_id,
            "error": {"code": code, "message": message},
        })

    def _publish(self, uri: str, diagnostics: list[dict[str, Any]]) -> None:
        _write_message(self.stdout, {
            "jsonrpc": "2.0",
            "method": "textDocument/publishDiagnostics",
            "params": {"uri": uri, "diagnostics": diagnostics},
        })


def run() -> int:
    """Entrypoint invoked by ``pencheff lsp``."""
    logging.basicConfig(
        level=logging.INFO,
        stream=sys.stderr,
        format="[%(asctime)s] %(levelname)s %(name)s: %(message)s",
    )
    server = PencheffLSP(sys.stdin.buffer, sys.stdout.buffer)
    return server.serve_forever()
