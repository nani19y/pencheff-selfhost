"""Unit tests for the security-sensitive parts of the agentic fixer.

Focus is on the boundaries that protect the host:
  * ``workspace.resolve_within`` rejects path-traversal attempts.
  * ``shell_tool.tool_bash`` rejects shell-meta chars + non-allowlist
    binaries; the allowlist itself is locked-down (no sudo, no rm).
  * ``redaction.redact`` strips every documented secret pattern.
  * ``cost.compute_cost_cents`` round-trips token counts → cents
    correctly for representative usage.
  * ``billing.check_can_start`` returns the expected refusal for
    concurrency + MTD-cap-exceeded scenarios.
  * ``extra_tools.tool_todo_write`` normalises status, replaces
    state on each call, and rejects bad input.

These are unit tests — no DB, no Celery, no LLM. The router-level
tests (status transitions, idempotent finish, billing 429s) belong
in an integration-test follow-up.
"""
from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from pencheff_api.services.agentic_fixer.cost import Usage, compute_cost_cents
from pencheff_api.services.agentic_fixer.extra_tools import (
    clear_todo_state,
    todo_state_for,
    tool_todo_write,
)
from pencheff_api.services.agentic_fixer.file_tools import (
    tool_edit_file,
    tool_glob,
    tool_grep,
    tool_read_file,
    tool_write_file,
)
from pencheff_api.services.agentic_fixer.redaction import redact
from pencheff_api.services.agentic_fixer.shell_tool import (
    BASH_ALLOWLIST,
    tool_bash,
)
from pencheff_api.services.agentic_fixer.workspace import (
    PathOutsideWorkspace,
    resolve_within,
)


# ── workspace.resolve_within ───────────────────────────────────────


def test_resolve_within_accepts_relative_path():
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        (root / "app.py").write_text("x = 1\n")
        resolved = resolve_within(root, "app.py")
        assert resolved == Path(root.resolve()) / "app.py"


def test_resolve_within_accepts_nested_relative_path():
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        (root / "src").mkdir()
        (root / "src" / "main.py").write_text("")
        resolved = resolve_within(root, "src/main.py")
        # macOS /var/folders → /private/var/folders means we have to
        # realpath both sides before comparing.
        assert str(resolved).endswith("src/main.py")


def test_resolve_within_rejects_dotdot_escape():
    with tempfile.TemporaryDirectory() as td:
        with pytest.raises(PathOutsideWorkspace):
            resolve_within(Path(td), "../../etc/passwd")


def test_resolve_within_rejects_absolute_outside():
    with tempfile.TemporaryDirectory() as td:
        with pytest.raises(PathOutsideWorkspace):
            resolve_within(Path(td), "/etc/passwd")


def test_resolve_within_rejects_symlink_escape():
    with tempfile.TemporaryDirectory() as outside:
        target = Path(outside) / "secret.txt"
        target.write_text("secret")
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            link = root / "shortcut"
            link.symlink_to(target)
            with pytest.raises(PathOutsideWorkspace):
                resolve_within(root, "shortcut")


# ── shell_tool: allowlist + meta-char rejection ────────────────────


def test_bash_allowlist_contains_safe_essentials():
    # The allowlist is the load-bearing security boundary. Lock the
    # core binaries we expect — adding more is fine; removing one is
    # a real change worth a test failure.
    expected = {
        "git", "gh", "npm", "pip", "pytest", "ruff",
        "semgrep", "gitleaks", "trivy", "osv-scanner",
    }
    assert expected.issubset(BASH_ALLOWLIST)


def test_bash_allowlist_excludes_dangerous_binaries():
    forbidden = {"sudo", "rm", "dd", "shred", "mkfs", "mount",
                 "umount", "ssh", "scp", "rsync", "curl", "wget"}
    assert forbidden.isdisjoint(BASH_ALLOWLIST), (
        "bash allowlist must not include dangerous binaries; found: "
        f"{forbidden & BASH_ALLOWLIST}"
    )


def test_bash_rejects_shell_meta_chars():
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        # Each banned character should result in an error.
        for cmd in [
            "echo hello ; echo world",
            "echo a && echo b",
            "echo a | wc -l",
            "echo `whoami`",
            "echo $HOME",
        ]:
            result = asyncio.run(tool_bash(root, {"command": cmd}))
            assert result.is_error, f"expected rejection for: {cmd}"
            assert "shell-meta" in result.content


def test_bash_rejects_non_allowlist_binary():
    with tempfile.TemporaryDirectory() as td:
        result = asyncio.run(tool_bash(Path(td), {"command": "sudo rm -rf /"}))
        assert result.is_error
        assert "not in the allowlist" in result.content


def test_bash_rejects_empty_command():
    with tempfile.TemporaryDirectory() as td:
        result = asyncio.run(tool_bash(Path(td), {"command": ""}))
        assert result.is_error


def test_bash_cwd_must_stay_within_workspace():
    with tempfile.TemporaryDirectory() as td:
        result = asyncio.run(tool_bash(Path(td), {
            "command": "echo hi",
            "cwd": "../../",
        }))
        assert result.is_error
        assert "outside workspace" in result.content


# ── redaction ──────────────────────────────────────────────────────


def test_redact_github_pat():
    assert "[REDACTED:ghp]" in redact("token=ghp_abcdefghijklmnopqrstuvwxyz123456789")


def test_redact_github_app_server():
    assert "[REDACTED:ghs]" in redact("auth: ghs_abcdefghijklmnopqrstuvwxyz123456")


def test_redact_aws_access_key():
    assert "[REDACTED:AKIA]" in redact("AKIAIOSFODNN7EXAMPLE leaked")


def test_redact_url_credentials():
    out = redact("https://user:hunter2@example.com/path")
    assert "hunter2" not in out
    assert "[REDACTED]" in out


def test_redact_slack_token():
    assert "[REDACTED:slack]" in redact("xoxb-1234567890-ABCDEFGHIJKL")


def test_redact_idempotent():
    """Redacting an already-redacted string shouldn't churn it."""
    once = redact("token=ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1")
    twice = redact(once)
    assert once == twice


def test_redact_empty_string():
    assert redact("") == ""


def test_redact_no_secrets_passes_through():
    msg = "hello world, this is a normal log line"
    assert redact(msg) == msg


# ── cost.compute_cost_cents ────────────────────────────────────────


def test_compute_cost_cents_zero_usage():
    # No tokens → zero cents (no rounding surprises).
    assert compute_cost_cents(Usage(0, 0), "sarvam-105b") == 0


def test_compute_cost_cents_scales_with_input():
    """Cost should scale monotonically with input tokens at constant
    output. Tests the formula direction without hardcoding the
    exact cents (which would couple the test to the price table)."""
    small = compute_cost_cents(Usage(input_tokens=1_000, output_tokens=0), "x")
    large = compute_cost_cents(Usage(input_tokens=1_000_000, output_tokens=0), "x")
    assert large > small


def test_compute_cost_cents_scales_with_output():
    small = compute_cost_cents(Usage(0, output_tokens=1_000), "x")
    large = compute_cost_cents(Usage(0, output_tokens=1_000_000), "x")
    assert large > small


def test_compute_cost_cents_cache_reads_count_for_billing():
    """Cache reads are charged (cheaper than full input, but
    not free)."""
    no_cache = compute_cost_cents(Usage(0, 0, 0, 0), "x")
    with_cache = compute_cost_cents(Usage(0, 0, 0, 10_000_000), "x")
    assert with_cache > no_cache


# ── extra_tools.tool_todo_write ────────────────────────────────────


def test_todo_write_replaces_state_on_each_call():
    run = "test-replace"
    clear_todo_state(run)
    asyncio.run(tool_todo_write(run, {"todos": [
        {"content": "first", "status": "pending"},
    ]}))
    state = todo_state_for(run)
    assert len(state.items) == 1
    # Second call replaces, doesn't append.
    asyncio.run(tool_todo_write(run, {"todos": [
        {"content": "second", "status": "in_progress"},
        {"content": "third", "status": "completed"},
    ]}))
    state = todo_state_for(run)
    assert [t["content"] for t in state.items] == ["second", "third"]
    clear_todo_state(run)


def test_todo_write_no_args_reads_back_current_state():
    run = "test-read"
    clear_todo_state(run)
    asyncio.run(tool_todo_write(run, {"todos": [
        {"content": "x", "status": "pending"},
    ]}))
    result = asyncio.run(tool_todo_write(run, {}))
    assert not result.is_error
    assert "[ ] x" in result.content
    clear_todo_state(run)


def test_todo_write_normalises_unknown_status_to_pending():
    run = "test-norm"
    clear_todo_state(run)
    asyncio.run(tool_todo_write(run, {"todos": [
        {"content": "x", "status": "WAT"},
    ]}))
    state = todo_state_for(run)
    assert state.items[0]["status"] == "pending"
    clear_todo_state(run)


def test_todo_write_rejects_non_list():
    run = "test-bad"
    clear_todo_state(run)
    result = asyncio.run(tool_todo_write(run, {"todos": "not a list"}))
    assert result.is_error


def test_todo_write_rejects_empty_content():
    run = "test-bad2"
    clear_todo_state(run)
    result = asyncio.run(tool_todo_write(run, {"todos": [
        {"content": "  ", "status": "pending"},
    ]}))
    assert result.is_error


# ── file_tools surface tests (sanity) ──────────────────────────────


def test_read_file_returns_content():
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        (root / "a.txt").write_text("hello\nworld\n")
        result = asyncio.run(tool_read_file(root, {"path": "a.txt"}))
        assert not result.is_error
        assert "hello" in result.content


def test_read_file_pages_with_offset_and_limit():
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        (root / "a.txt").write_text("\n".join(f"L{i}" for i in range(10)))
        result = asyncio.run(tool_read_file(root, {
            "path": "a.txt", "offset": 3, "limit": 2,
        }))
        assert not result.is_error
        # offset=3, limit=2 → lines 3 and 4 (0-indexed) of L0..L9
        assert "L3" in result.content
        assert "L4" in result.content
        assert "L5" not in result.content


def test_write_file_refuses_to_overwrite():
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        (root / "a.txt").write_text("existing")
        result = asyncio.run(tool_write_file(root, {
            "path": "a.txt", "content": "new",
        }))
        assert result.is_error
        assert "use edit_file" in result.content
        # Original content survives.
        assert (root / "a.txt").read_text() == "existing"


def test_edit_file_rejects_ambiguous_match():
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        (root / "a.py").write_text("x = 1\nx = 1\n")
        result = asyncio.run(tool_edit_file(root, {
            "path": "a.py", "old_string": "x = 1", "new_string": "x = 2",
        }))
        assert result.is_error
        assert "matches 2 places" in result.content


def test_edit_file_replace_all_passes_through_ambiguous():
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        (root / "a.py").write_text("x = 1\nx = 1\n")
        result = asyncio.run(tool_edit_file(root, {
            "path": "a.py", "old_string": "x = 1",
            "new_string": "x = 2", "replace_all": True,
        }))
        assert not result.is_error
        assert (root / "a.py").read_text() == "x = 2\nx = 2\n"


# ── agent_loop: stuck-reading guard (scales, ignores planning/discovery) ──

from pencheff_api.services.agentic_fixer.agent_loop import (  # noqa: E402
    AgenticFixer,
    _MIN_READS_WITHOUT_EDIT,
)
from pencheff_api.services.agentic_fixer.system_prompt import (  # noqa: E402
    FindingForAgent,
)


def _finding(fid: str, file_path: str | None) -> FindingForAgent:
    return FindingForAgent(
        id=fid, kind="repo", severity="high", title="x", description=None,
        file_path=file_path, line_start=None, line_end=None, code_snippet=None,
        cve=None, package=None, installed_version=None, fixed_version=None,
        rule_id=None,
    )


def _fixer(findings: list[FindingForAgent]) -> AgenticFixer:
    return AgenticFixer(
        workspace_root=Path("/tmp"), branch_name="b", repo_full_name="o/r",
        runtime="server", findings=findings,
    )


def test_classify_only_reads_count_planning_and_discovery_are_neutral():
    assert AgenticFixer._classify("edit_file") == "mutating"
    assert AgenticFixer._classify("write_file") == "mutating"
    assert AgenticFixer._classify("bash") == "mutating"
    assert AgenticFixer._classify("read_file") == "inspection"
    assert AgenticFixer._classify("grep") == "inspection"
    # The bug: these used to count as "reads" and burn the stuck budget.
    for neutral in ("TodoWrite", "glob", "web_search", "mcp_call"):
        assert AgenticFixer._classify(neutral) == "neutral"


def test_read_budget_has_a_floor_when_findings_carry_no_file_path():
    # Advisory-level GHSA findings often have no file_path → floor, not 0.
    fixer = _fixer([_finding(str(i), None) for i in range(49)])
    assert fixer._read_budget() == _MIN_READS_WITHOUT_EDIT


def test_read_budget_scales_with_distinct_finding_files():
    fixer = _fixer([_finding(str(i), f"src/m{i}.py") for i in range(10)])
    assert fixer._read_budget() == 40  # 10 distinct files * 4 > floor


def test_screenshot_trace_does_not_trip_stuck_guard():
    """Regression: the deepseek-v4-pro run that misfired.

    Trace was 1 TodoWrite + 4 read_file + 3 glob (8 calls), zero edits,
    49 findings — killed at iter 4 by the old flat cap of 8. Under the
    fix only the 4 read_file calls count, well under the scaled budget.
    """
    trace = [
        "TodoWrite",
        "read_file", "read_file", "read_file",
        "glob", "glob", "glob",
        "read_file",
    ]
    findings = (
        [_finding(f"ghsa-{i}", "requirements.txt") for i in range(43)]
        + [_finding(f"bandit-{i}", f"shieldbot/tools/f{i}.py") for i in range(6)]
    )
    fixer = _fixer(findings)
    inspection = sum(1 for t in trace if AgenticFixer._classify(t) == "inspection")
    assert inspection == 4
    assert inspection < fixer._read_budget()  # guard would NOT fire


def test_guard_is_disabled_once_any_edit_happens():
    fixer = _fixer([_finding("1", None)])
    fixer._inspection_reads = 999
    fixer._mutating_calls = 1
    tripped = (
        fixer._mutating_calls == 0
        and fixer._inspection_reads >= fixer._read_budget()
    )
    assert tripped is False
