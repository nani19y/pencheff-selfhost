"""Safe subprocess execution for system tools — no shell=True."""

from __future__ import annotations

import asyncio
import shutil
import time
from contextlib import contextmanager
from dataclasses import dataclass


@dataclass
class ToolResult:
    stdout: str
    stderr: str
    returncode: int

    @property
    def success(self) -> bool:
        return self.returncode == 0


def tool_available(name: str) -> bool:
    """Check if a system tool is available on PATH."""
    return shutil.which(name) is not None


@contextmanager
def _tool_span(args: list[str]):
    """Open an OTel span around a subprocess invocation.

    The span name is ``tool.{argv[0]}`` and attributes capture argument
    *count* and a SHA-256 *hash* of the joined args — never the raw
    args, since hydra/sqlmap/nuclei routinely receive credentials on
    the command line. Operators can match invocations by hash; the
    secret material never leaves the operator's process.

    A no-op when the OTel SDK is absent or observability is disabled.
    """
    span = None
    start = time.monotonic()
    try:
        from opentelemetry import trace
        from pencheff.observability.redact import hash_argv
        tracer = trace.get_tracer("pencheff.tool_runner")
        tool_name = args[0] if args else "unknown"
        span_cm = tracer.start_as_current_span(
            f"tool.{tool_name}",
            attributes={
                "tool.name": tool_name,
                "tool.argv.count": len(args),
                "tool.argv.hash": hash_argv(args),
            },
        )
        span = span_cm.__enter__()
    except Exception:
        span_cm = None

    try:
        yield span
    finally:
        if span_cm is not None:
            try:
                span_cm.__exit__(None, None, None)
            except Exception:
                pass


def _set_attrs(span, **kwargs) -> None:
    if span is None:
        return
    try:
        for k, v in kwargs.items():
            span.set_attribute(k, v)
    except Exception:
        pass


async def run_tool(
    args: list[str],
    timeout: float = 60.0,
    stdin_data: str | None = None,
) -> ToolResult:
    """Run a system tool safely with array args (no shell injection)."""
    with _tool_span(args) as span:
        try:
            proc = await asyncio.create_subprocess_exec(
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                stdin=asyncio.subprocess.PIPE if stdin_data else None,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(input=stdin_data.encode() if stdin_data else None),
                timeout=timeout,
            )
            result = ToolResult(
                stdout=stdout.decode(errors="replace"),
                stderr=stderr.decode(errors="replace"),
                returncode=proc.returncode or 0,
            )
            _set_attrs(
                span,
                **{
                    "tool.exit_code": result.returncode,
                    "tool.stdout.size": len(stdout),
                    "tool.stderr.size": len(stderr),
                    "tool.success": result.success,
                },
            )
            return result
        except asyncio.TimeoutError:
            proc.kill()
            _set_attrs(span, **{"tool.exit_code": -1, "tool.timeout": True})
            return ToolResult(stdout="", stderr="Timeout exceeded", returncode=-1)
        except FileNotFoundError:
            _set_attrs(span, **{"tool.exit_code": -1, "tool.error": "not_found"})
            return ToolResult(stdout="", stderr=f"Tool not found: {args[0]}", returncode=-1)
