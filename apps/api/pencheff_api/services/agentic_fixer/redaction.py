"""Secret redaction for tool output.

The agent's bash tool can run arbitrary commands within its allowlist
(``git``, ``gh``, linters, …). Some of those legitimately print
secrets — ``gh auth status`` shows the token prefix, ``git remote
-v`` shows URLs with embedded credentials. Before we hand bash output
back to the LLM (and persist it in ``agentic_fix_steps``), we redact
known secret patterns.

This is a defence-in-depth measure. The bash allowlist is the
primary boundary; redaction protects against the agent prompting an
allowed binary into emitting secrets, and against the operator's
environment shipping creds in unexpected ways.
"""
from __future__ import annotations

import re


# Patterns are ordered by specificity (most specific first) so a
# token doesn't get double-redacted.
_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    # GitHub PATs + GitHub App tokens.
    ("github_pat", re.compile(r"ghp_[A-Za-z0-9]{30,}"), "[REDACTED:ghp]"),
    ("github_oauth", re.compile(r"gho_[A-Za-z0-9]{30,}"), "[REDACTED:gho]"),
    ("github_app_user", re.compile(r"ghu_[A-Za-z0-9]{30,}"), "[REDACTED:ghu]"),
    ("github_app_server", re.compile(r"ghs_[A-Za-z0-9]{30,}"), "[REDACTED:ghs]"),
    ("github_refresh", re.compile(r"ghr_[A-Za-z0-9]{30,}"), "[REDACTED:ghr]"),
    # GitLab personal access tokens.
    ("gitlab_pat", re.compile(r"glpat-[A-Za-z0-9_-]{20,}"), "[REDACTED:glpat]"),
    # AWS access keys.
    ("aws_access_key_id", re.compile(r"AKIA[0-9A-Z]{16}"), "[REDACTED:AKIA]"),
    ("aws_secret_key",
     re.compile(r"(?<![A-Za-z0-9])[A-Za-z0-9/+]{40}(?![A-Za-z0-9/+=])"),
     "[REDACTED:aws_secret]"),
    # Slack tokens.
    ("slack_token",
     re.compile(r"xox[abprs]-[A-Za-z0-9-]{10,}"),
     "[REDACTED:slack]"),
    # Anthropic / OpenAI API keys.
    ("anthropic_key", re.compile(r"sk-ant-[A-Za-z0-9_\-]{30,}"), "[REDACTED:anthropic]"),
    ("openai_key", re.compile(r"sk-[A-Za-z0-9]{40,}"), "[REDACTED:openai]"),
    # Generic credentials in URLs: scheme://user:password@host
    ("url_credentials",
     re.compile(r"(https?://[^/\s:@]+:)([^/\s@]+)(@[^\s]+)"),
     r"\1[REDACTED]\3"),
]


def redact(text: str) -> str:
    """Return ``text`` with every known secret pattern replaced.

    Cheap: O(n * patterns). Safe to call on every tool output before
    persistence.
    """
    if not text:
        return text
    for _name, pattern, replacement in _PATTERNS:
        text = pattern.sub(replacement, text)
    return text
