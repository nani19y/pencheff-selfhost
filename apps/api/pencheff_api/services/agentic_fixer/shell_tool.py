"""Shell ``bash`` tool with allowlist + secret redaction.

The bash tool is the escape hatch the agent needs for git/gh/linters/
tests. Without it we'd need a dedicated tool per binary, which is
hostile to LLM ergonomics and impossible to anticipate (every repo
has different test commands).

We trade flexibility for a binary allowlist: the first token of the
command must be in ``BASH_ALLOWLIST``. Argument parsing is deliberately
NOT performed — we'd have to anticipate every flag-format quirk and
it would still leak via composed commands (``git; rm -rf /``). Instead
we forbid shell-interpolation characters (semicolon, ampersand, pipe,
dollar, backtick, and friends)
so the command can only be a single program invocation.

For the destructive flag (``-rf``, ``--force``, etc.) we rely on the
allowlist + path-confinement combination: the agent is running in the
clone directory; ``rm -rf`` against that path destroys our own workspace,
which fails the run but doesn't escape it.
"""
from __future__ import annotations

import asyncio
import logging
import shlex
import shutil
from dataclasses import dataclass
from pathlib import Path

from .file_tools import ToolResult
from .redaction import redact

log = logging.getLogger("pencheff.agentic_fixer.tools.shell")


BASH_ALLOWLIST: set[str] = {
    # Version control / GitHub.
    "git", "gh",
    # Node / Python / Ruby / Go / Rust toolchains the agent might
    # need to install deps or run tests after a fix.
    "npm", "yarn", "pnpm", "node", "npx",
    "python", "python3", "pip", "pip3", "pytest", "uv", "poetry",
    "ruby", "bundle", "bundler",
    "go", "cargo", "rustc", "rustup",
    "make", "cmake",
    # Linters + formatters the agent commonly reaches for.
    "ruff", "black", "mypy", "eslint", "prettier", "gofmt",
    # Scanners the agent can rerun to verify its fix.
    "semgrep", "gitleaks", "trivy", "osv-scanner", "bandit", "gosec",
    # Shell builtins masquerading as binaries on macOS / Linux.
    "echo", "cat", "head", "tail", "wc", "ls", "pwd", "find",
}


# Characters that enable shell interpolation / chaining. Reject any
# command containing them — the agent has to call ``bash`` once per
# binary invocation. We allow `*` and `?` since some commands take
# glob patterns as args, but we don't shell-expand the command
# string (we pass argv directly to ``Process``).
_BANNED_CHARS = set(";&|`$\n\r")


@dataclass
class BashRequest:
    command: str
    cwd: str | None = None  # workspace-root-relative; None = workspace root
    timeout_sec: float = 120.0


async def tool_bash(workspace_root: Path, args: dict) -> ToolResult:
    """Run a single binary from the allowlist, capturing stdout+stderr.

    Returns ``ToolResult.ok`` with redacted output on zero exit.
    Returns ``ToolResult.err`` on non-zero exit, including a
    redacted snippet of stderr.
    """
    command = args.get("command")
    if not command or not isinstance(command, str):
        return ToolResult.err("bash: 'command' is required (string)")
    timeout_sec = float(args.get("timeout_sec", 120.0))
    timeout_sec = max(1.0, min(timeout_sec, 600.0))

    if any(ch in command for ch in _BANNED_CHARS):
        return ToolResult.err(
            "bash: command contains shell-meta chars (; & | ` $ newline). "
            "Call bash once per binary; no chaining or substitution."
        )
    try:
        argv = shlex.split(command)
    except ValueError as e:
        return ToolResult.err(f"bash: failed to parse command: {e}")
    if not argv:
        return ToolResult.err("bash: empty command")
    binary = argv[0]
    if binary not in BASH_ALLOWLIST:
        return ToolResult.err(
            f"bash: '{binary}' is not in the allowlist. Allowed: "
            f"{', '.join(sorted(BASH_ALLOWLIST))}"
        )
    resolved = shutil.which(binary)
    if resolved is None:
        return ToolResult.err(f"bash: '{binary}' not found on PATH")

    cwd_arg = args.get("cwd")
    if cwd_arg:
        cwd_path = (workspace_root / cwd_arg).resolve()
        try:
            cwd_path.relative_to(workspace_root.resolve())
        except ValueError:
            return ToolResult.err(f"bash: cwd '{cwd_arg}' resolves outside workspace")
        if not cwd_path.is_dir():
            return ToolResult.err(f"bash: cwd '{cwd_arg}' is not a directory")
    else:
        cwd_path = workspace_root

    try:
        proc = await asyncio.create_subprocess_exec(
            resolved, *argv[1:],
            cwd=str(cwd_path),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except OSError as e:
        return ToolResult.err(f"bash: spawn failed: {e}")

    try:
        stdout_b, stderr_b = await asyncio.wait_for(
            proc.communicate(),
            timeout=timeout_sec,
        )
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        return ToolResult.err(
            f"bash: '{binary}' timed out after {timeout_sec:.0f}s"
        )

    stdout = redact(stdout_b.decode("utf-8", errors="replace"))
    stderr = redact(stderr_b.decode("utf-8", errors="replace"))

    # Cap each stream so a chatty tool can't blow the token budget.
    def _cap(s: str, limit: int = 12_000) -> str:
        return s if len(s) <= limit else s[:limit] + f"\n...[truncated {len(s) - limit} bytes]"

    body_lines = [f"$ {command}", f"exit {proc.returncode}"]
    out_capped = _cap(stdout)
    err_capped = _cap(stderr)
    if out_capped:
        body_lines.append("--- stdout ---")
        body_lines.append(out_capped.rstrip())
    if err_capped:
        body_lines.append("--- stderr ---")
        body_lines.append(err_capped.rstrip())
    body = "\n".join(body_lines)

    if proc.returncode != 0:
        return ToolResult(content=body, is_error=True)
    return ToolResult.ok(body)
