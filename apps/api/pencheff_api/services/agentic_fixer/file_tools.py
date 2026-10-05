"""Filesystem tools for the agentic fixer.

Each tool returns a ``ToolResult`` (content + is_error) the dispatcher
hands to Anthropic. Paths are resolved through ``workspace.resolve_within``
so the agent can't escape the run's clone directory.

Tools implemented:
* ``read_file`` — read with optional offset/limit (line-paged).
* ``write_file`` — create new files; refuses to overwrite (use edit_file).
* ``edit_file`` — string replacement; ``replace_all`` flag like Claude Code.
* ``grep`` — ripgrep-like search. Falls back to a Python implementation
  when the ``rg`` binary isn't installed in the worker image.
* ``glob`` — standard glob semantics rooted at the workspace.
"""
from __future__ import annotations

import asyncio
import fnmatch
import logging
import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .workspace import PathOutsideWorkspace, resolve_within

log = logging.getLogger("pencheff.agentic_fixer.tools.file")


@dataclass
class ToolResult:
    """Common return shape for tool execution."""

    content: str
    is_error: bool = False

    @classmethod
    def ok(cls, content: str) -> "ToolResult":
        return cls(content=content, is_error=False)

    @classmethod
    def err(cls, msg: str) -> "ToolResult":
        return cls(content=msg, is_error=True)


# ---------- read_file ----------

async def tool_read_file(workspace_root: Path, args: dict) -> ToolResult:
    path = args.get("path")
    if not path:
        return ToolResult.err("read_file: 'path' is required")
    try:
        full = resolve_within(workspace_root, path)
    except PathOutsideWorkspace as e:
        return ToolResult.err(f"read_file: {e}")
    if not full.exists():
        return ToolResult.err(f"read_file: '{path}' does not exist")
    if full.is_dir():
        return ToolResult.err(f"read_file: '{path}' is a directory; use glob")

    offset = max(int(args.get("offset", 0)), 0)
    limit = args.get("limit")
    try:
        with full.open("r", encoding="utf-8", errors="replace") as fh:
            if limit is None:
                # No limit; read whole file but cap at 1MB so a stray
                # giant file doesn't blow up the token budget.
                data = fh.read(1_048_576 + 1)
                if len(data) > 1_048_576:
                    return ToolResult.err(
                        f"read_file: '{path}' exceeds 1 MB — page with offset/limit"
                    )
                return ToolResult.ok(data if data else f"(file '{path}' is empty)")
            # Line-paged read.
            lines: list[str] = []
            for i, line in enumerate(fh):
                if i < offset:
                    continue
                if len(lines) >= int(limit):
                    break
                lines.append(line)
            # Sarvam (and every OpenAI-compatible provider) rejects
            # tool messages with empty content. Return a clear
            # marker when the requested range is past the end of
            # file so the agent knows to stop paging.
            body = "".join(lines)
            if not body:
                return ToolResult.ok(
                    f"(no lines in '{path}' at offset={offset}; "
                    f"the file is shorter than that)"
                )
            return ToolResult.ok(body)
    except OSError as e:
        return ToolResult.err(f"read_file: {e}")


# ---------- write_file ----------

async def tool_write_file(workspace_root: Path, args: dict) -> ToolResult:
    path = args.get("path")
    content = args.get("content")
    if not path or content is None:
        return ToolResult.err("write_file: 'path' and 'content' are required")
    try:
        full = resolve_within(workspace_root, path)
    except PathOutsideWorkspace as e:
        return ToolResult.err(f"write_file: {e}")
    if full.exists():
        return ToolResult.err(
            f"write_file: '{path}' already exists; use edit_file"
        )
    try:
        full.parent.mkdir(parents=True, exist_ok=True)
        full.write_text(content, encoding="utf-8")
        return ToolResult.ok(f"wrote {full.stat().st_size} bytes to {path}")
    except OSError as e:
        return ToolResult.err(f"write_file: {e}")


# ---------- edit_file ----------

async def tool_edit_file(workspace_root: Path, args: dict) -> ToolResult:
    path = args.get("path")
    old = args.get("old_string")
    new = args.get("new_string")
    replace_all = bool(args.get("replace_all", False))
    if not path or old is None or new is None:
        return ToolResult.err(
            "edit_file: 'path', 'old_string', 'new_string' are required"
        )
    try:
        full = resolve_within(workspace_root, path)
    except PathOutsideWorkspace as e:
        return ToolResult.err(f"edit_file: {e}")
    if not full.exists():
        return ToolResult.err(f"edit_file: '{path}' does not exist")

    try:
        text = full.read_text(encoding="utf-8")
    except OSError as e:
        return ToolResult.err(f"edit_file: {e}")

    count = text.count(old)
    if count == 0:
        return ToolResult.err(
            f"edit_file: 'old_string' not found in {path}"
        )
    if count > 1 and not replace_all:
        return ToolResult.err(
            f"edit_file: 'old_string' matches {count} places in {path}; "
            "set replace_all=true or provide a longer unique substring"
        )

    updated = text.replace(old, new) if replace_all else text.replace(old, new, 1)
    try:
        full.write_text(updated, encoding="utf-8")
    except OSError as e:
        return ToolResult.err(f"edit_file: {e}")
    return ToolResult.ok(
        f"replaced {count if replace_all else 1} occurrence(s) in {path}"
    )


# ---------- grep ----------

async def tool_grep(workspace_root: Path, args: dict) -> ToolResult:
    pattern = args.get("pattern")
    if not pattern:
        return ToolResult.err("grep: 'pattern' is required")
    glob_arg = args.get("glob")
    case_insensitive = bool(args.get("-i", False) or args.get("case_insensitive", False))
    path = args.get("path", ".")

    try:
        root = resolve_within(workspace_root, path)
    except PathOutsideWorkspace as e:
        return ToolResult.err(f"grep: {e}")

    # Prefer ripgrep when available — much faster on big repos.
    rg = shutil.which("rg")
    if rg is not None:
        cmd = [rg, "-n", "--no-heading", "--with-filename"]
        if case_insensitive:
            cmd.append("-i")
        if glob_arg:
            cmd.extend(["-g", glob_arg])
        cmd.extend(["-e", pattern, str(root)])
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            out, err = await proc.communicate()
        except OSError as e:
            return ToolResult.err(f"grep: {e}")
        if proc.returncode not in (0, 1):  # 1 = no matches
            return ToolResult.err(
                f"grep: rg exited {proc.returncode}: {err.decode(errors='replace')[:400]}"
            )
        text = out.decode(errors="replace")
        # Strip the resolved workspace prefix so the LLM sees relative
        # paths. realpath-resolve both sides — macOS /var/folders
        # symlinks to /private/var/folders, which would otherwise leak
        # through.
        root_real = str(Path(os.path.realpath(str(workspace_root))))
        text = text.replace(root_real + "/", "")
        if not text:
            return ToolResult.ok("(no matches)")
        # Cap to ~200 lines to stay within token budget.
        lines = text.splitlines()
        if len(lines) > 200:
            return ToolResult.ok(
                "\n".join(lines[:200])
                + f"\n... ({len(lines) - 200} more matches truncated)"
            )
        return ToolResult.ok(text)

    # Pure-Python fallback.
    try:
        regex = re.compile(pattern, re.IGNORECASE if case_insensitive else 0)
    except re.error as e:
        return ToolResult.err(f"grep: bad pattern: {e}")
    matches: list[str] = []
    for dirpath, _dirs, files in os.walk(root):
        for fname in files:
            if glob_arg and not fnmatch.fnmatch(fname, glob_arg):
                continue
            fpath = Path(dirpath) / fname
            try:
                rel = fpath.relative_to(workspace_root)
            except ValueError:
                rel = fpath
            try:
                with fpath.open("r", encoding="utf-8", errors="ignore") as fh:
                    for lineno, line in enumerate(fh, start=1):
                        if regex.search(line):
                            matches.append(f"{rel}:{lineno}:{line.rstrip()}")
                            if len(matches) >= 200:
                                matches.append(
                                    "... (truncated at 200 matches)"
                                )
                                return ToolResult.ok("\n".join(matches))
            except OSError:
                continue
    return ToolResult.ok("\n".join(matches) if matches else "(no matches)")


# ---------- glob ----------

async def tool_glob(workspace_root: Path, args: dict) -> ToolResult:
    pattern = args.get("pattern")
    if not pattern:
        return ToolResult.err("glob: 'pattern' is required")
    path = args.get("path", ".")
    try:
        root = resolve_within(workspace_root, path)
    except PathOutsideWorkspace as e:
        return ToolResult.err(f"glob: {e}")
    # Use Path.rglob for ``**`` patterns, glob otherwise.
    if "**" in pattern:
        # rglob expects the trailing portion; split on the first '**'.
        suffix = pattern.split("**/", 1)[-1] if "**/" in pattern else pattern
        matches = sorted(root.rglob(suffix))
    else:
        matches = sorted(root.glob(pattern))
    # Drop directories — glob is for files. Cap output. Use realpath
    # for the workspace_root anchor because macOS /var/folders is a
    # symlink to /private/var/folders; without resolving both ends,
    # relative_to() raises ValueError on legitimate workspace files.
    root_real = Path(os.path.realpath(str(workspace_root)))
    rels: list[str] = []
    for p in matches:
        if not p.is_file():
            continue
        p_real = Path(os.path.realpath(str(p)))
        try:
            rels.append(str(p_real.relative_to(root_real)))
        except ValueError:
            # Files that resolve outside the workspace (via symlink)
            # are skipped silently — the agent shouldn't see them.
            continue
    if not rels:
        return ToolResult.ok("(no matches)")
    if len(rels) > 200:
        return ToolResult.ok(
            "\n".join(rels[:200]) + f"\n... ({len(rels) - 200} more)"
        )
    return ToolResult.ok("\n".join(rels))
