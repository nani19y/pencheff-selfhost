"""System prompt + initial user message assembly.

Kept in its own module so prompt-engineering iterations don't churn
the agent loop. The prompt is short on purpose — sarvam-105b's
4096-token output cap rewards concise instruction sets that leave
room for tool-call sequences.

Two pieces:
* ``build_system_prompt(run, findings)`` — sets the agent's role,
  tool usage rules, PR conventions, and the workspace layout summary.
* ``build_initial_user_message(findings)`` — the kickoff message
  listing every finding the agent must address.

Both functions are pure — no I/O. The caller passes already-loaded
finding rows; we just format them.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class FindingForAgent:
    """Minimal finding shape the prompt builder needs. The caller
    populates this from DAST ``Finding`` or repo ``RepoFinding``
    rows — both kinds normalise into the same struct.
    """

    id: str
    kind: str          # "dast" | "repo"
    severity: str      # critical | high | medium | low | info
    title: str
    description: str | None
    file_path: str | None
    line_start: int | None
    line_end: int | None
    code_snippet: str | None
    cve: str | None
    package: str | None
    installed_version: str | None
    fixed_version: str | None
    rule_id: str | None


def build_system_prompt(
    *,
    branch_name: str,
    repo_full_name: str | None,
    runtime: str,
) -> str:
    """Return the system prompt for one agent run."""
    runtime_note = {
        "server": (
            "You are running on Pencheff's server-side worker against a fresh "
            "clone of the repository. The workspace is the only writable area; "
            "writes outside it will fail."
        ),
        "desktop": (
            "You are running locally on the user's Mac via Pencheff Studio "
            "against the user's existing checkout. Treat all changes as "
            "permanent — there is no sandbox separating you from their files."
        ),
    }.get(runtime, "")

    return f"""You are Pencheff Agent, a security-focused code-fix assistant.

Your job: address every security finding listed in the user message
by editing the affected files. Use the supplied tools to read, edit,
and verify code. Be precise — change only what is needed to remediate
the vulnerability without altering unrelated behaviour.

{runtime_note}

Tools you have:
- read_file / write_file / edit_file — file I/O.
- grep / glob — locate code patterns and files.
- bash — run git, gh, linters, scanners. The bash allowlist forbids
  shell-meta chars; call bash once per binary. No chaining.

Workflow — be aggressive about taking action:
1. Read the affected file ONCE. Do not re-read the same file unless
   you've made an edit since the last read.
2. After at most one read per file, you MUST either:
   (a) call edit_file with a real fix, OR
   (b) move to the next finding if the existing code is already safe /
       the finding is a false positive.
3. If 60% of your iterations have passed without any edits, you are
   stuck — pick the most obvious finding and edit it.
4. After every 5-10 findings are addressed, run `bash git status` to
   confirm your edits landed, then `bash git add -A` + `bash git
   commit -m "..."` so progress is preserved.
5. After all findings are addressed (or you've decided which to skip),
   make sure all changes are committed on branch "{branch_name}",
   then end your turn with a short summary.

Concrete first move:
- Read 1-2 most-affected files
- Make at least one edit_file call before iteration 5
- Commit early and often via bash

Constraints:
- Never push to the default branch directly.
- Never amend or force-push.
- Never edit lock files unless the finding is a dep upgrade.
- Never disable scanners, suppress findings, or comment them out.
- DO NOT re-read the same file multiple times. If you need to remind
  yourself what a file looks like, scroll back in your own context —
  read_file consumes your iteration budget.

Repository: {repo_full_name or "(local path)"}
Branch to create: {branch_name}
"""


def build_initial_user_message(findings: list[FindingForAgent]) -> str:
    """Format the kickoff user message — the list of findings the
    agent must address.
    """
    lines = [
        f"There are {len(findings)} security findings to address. "
        "Work through them one by one.",
        "",
    ]
    for idx, f in enumerate(findings, start=1):
        lines.append(f"### Finding {idx} — {f.severity.upper()} — {f.title}")
        if f.rule_id:
            lines.append(f"- rule: `{f.rule_id}`")
        if f.cve:
            lines.append(f"- CVE: `{f.cve}`")
        if f.file_path:
            loc = f.file_path
            if f.line_start:
                loc += f":{f.line_start}"
                if f.line_end and f.line_end != f.line_start:
                    loc += f"-{f.line_end}"
            lines.append(f"- location: `{loc}`")
        if f.package:
            pkg = f.package
            if f.installed_version:
                pkg += f" {f.installed_version}"
            if f.fixed_version:
                pkg += f" → {f.fixed_version}"
            lines.append(f"- package: {pkg}")
        if f.description:
            lines.append("")
            lines.append(_truncate(f.description, 600))
        if f.code_snippet:
            lines.append("")
            lines.append("```")
            lines.append(_truncate(f.code_snippet, 800))
            lines.append("```")
        lines.append("")

    lines.append(
        "Begin by reading the most-affected files. After fixing all "
        "findings, commit + push + open a PR. End your turn with a "
        "summary."
    )
    return "\n".join(lines)


def _truncate(s: str, limit: int) -> str:
    if len(s) <= limit:
        return s
    return s[:limit] + f"\n…[truncated {len(s) - limit} bytes]"
