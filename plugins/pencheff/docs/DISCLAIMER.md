# Pencheff Authorization & Use Notice

Pencheff is a penetration testing tool intended **only** for authorized
security assessments. Adapted from
[0xSteph/pentest-ai-agents](https://github.com/0xSteph/pentest-ai-agents)'s
DISCLAIMER, the rules below are enforced in code by
`pencheff.core.scope_guard.ScopeGuard`:

- Every Tier 2 (execution) command requires a `--scope FILE` declaration
  describing authorized IP ranges, domains, URLs, cloud accounts, and OAST
  callbacks.
- Each target is validated against the scope before any active operation.
- Tier 1 (advisory) commands work without scope but never make targeted
  network calls beyond DNS resolution and public OSINT databases.
- Destructive operations (e.g. file deletion, account lockout, ransomware
  proof-of-concepts) require `allow_destructive: true` in the scope file.

You are solely responsible for ensuring you have written authorization
before scanning, exploiting, or otherwise targeting any system. Do **not**
use pencheff against infrastructure you do not own or have explicit
permission to test.

The authors and contributors disclaim all liability for misuse.
