# Agentic Fixer — Design Spec

**Status:** Approved — implementation spans multiple sessions
**Owner:** balasriharsha
**Date:** 2026-05-23

---

## 1. Goal

Replace today's per-finding fix-all flow (`fix_proposer.propose_fix` →
LLM-suggests-one-diff → `fix_applier` opens PR via GitHub App) with an
**agentic** fixer modelled after Claude Code / Cursor Agent mode:

- The LLM receives the full set of findings as one task, plus a tool set.
- The LLM iterates: reads files, makes multi-file edits, runs commands,
  re-reads to verify.
- When done, the agent commits on a new branch and opens a PR via
  `gh pr create` (preferred) or the GitHub REST API (fallback).
- Same UX on webapp and desktop.

## 1a. LLM backend (updated 2026-05-23)

The agent talks to an **OpenAI-compatible chat-completions endpoint**
— not Anthropic's Messages API. Default backend is **Sarvam AI's
`sarvam-105b`** (https://api.sarvam.ai/v1), the same provider the
scan-agent fallback already uses, so we know function-calling works
on this endpoint.

Why OpenAI-shaped rather than Anthropic-shaped:
- Sarvam ships the OpenAI shape; we're not adding a new backend.
- The scan agent in `services/agent_swarm/agent_loop.py` already
  exercises this format against sarvam-105b — the new code rides on
  a well-trodden path.
- Operators on a different provider override
  `AGENTIC_FIX_BASE_URL` / `AGENTIC_FIX_MODEL`; the rest of the
  agent loop is provider-agnostic.

Implication for max-tokens: Sarvam's starter tier caps `max_tokens` at
**4096** for sarvam-105b. The agent loop is designed for many short
turns rather than long planning monologues — this constraint mostly
shows up in the system prompt (encourage concise tool-call sequences).

## 2. Non-goals (for this spec)

- Replacing the existing scan engine.
- Replacing the existing per-finding fix proposals — the new flow is
  **additive**; the old flow stays available as "legacy fix".
- Supporting non-GitHub SCMs in v1 (GitLab/Bitbucket are follow-ups).
- Implementing custom MCP servers — we only host an MCP **client** that
  can dial out to user-configured external servers.

## 3. High-level architecture

Two runtimes share one protocol:

```
┌─────────────────────────────────────────────────────────────────────┐
│ SERVER-SIDE (Celery worker)                                          │
│                                                                       │
│   POST /fix-tasks/agentic                                             │
│      │                                                                │
│      ▼                                                                │
│   AgenticFixRun row (status=queued)                                   │
│      │                                                                │
│      ▼                                                                │
│   Celery task: agentic_fix_task                                       │
│      ├─ git clone (cloud-provider repos)                              │
│      │  OR use local_path (local-provider mirror reachable by         │
│      │  worker — only when worker shares the host filesystem)         │
│      ├─ Run agent loop (Anthropic Messages API + tools)               │
│      ├─ Tool dispatch (read/edit/bash/…) scoped to clone path         │
│      ├─ git branch + commit + push                                    │
│      ├─ gh pr create (fallback: GitHub PR API)                        │
│      └─ Update AgenticFixRun row + AgenticFixUsage                    │
└─────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│ DESKTOP-SIDE (Pencheff Studio, Swift)                                 │
│                                                                       │
│   "Fix all (agent)" button                                            │
│      │                                                                │
│      ▼                                                                │
│   Pre-check: API key fetched from server bridge endpoint              │
│      (server stores Anthropic key; desktop never sees it raw)         │
│      │                                                                │
│      ▼                                                                │
│   POST /fix-tasks/agentic/begin → returns run_id + session_token      │
│      │                                                                │
│      ▼                                                                │
│   AnthropicProxyClient streams Messages API responses                 │
│      via POST /llm/proxy (server signs requests with shared key)     │
│      │                                                                │
│      ▼                                                                │
│   ToolDispatcher executes locally:                                    │
│      ├─ FileTools: read/edit at repo.localPath                        │
│      ├─ ShellTool: NSTask running git/gh/linters                      │
│      └─ TodoWriteTool: in-memory                                      │
│      │                                                                │
│      ▼                                                                │
│   POST /fix-tasks/agentic/{id}/step (per iteration) for observability │
└─────────────────────────────────────────────────────────────────────┘
```

**Why this split:**

- Local-provider repos live only on the user's Mac. The server can't
  see them. So the desktop must execute the agent loop locally.
- Cloud-provider repos are reachable by the worker (it has GitHub App
  tokens). Server-side execution is simpler — no client install
  required.
- The Anthropic API key never leaves the server. The desktop talks to
  a `POST /llm/proxy` endpoint that re-issues the request to Anthropic
  using Pencheff's key. This lets us bill per-workspace and apply
  plan-tier limits centrally.

## 4. Data model

### 4.1 `AgenticFixRun`

New table. Rows are created when the user kicks off an agentic fix.

| Column | Type | Notes |
|---|---|---|
| `id` | UUID PK | |
| `org_id` | UUID FK orgs | |
| `workspace_id` | UUID FK workspaces | |
| `user_id` | UUID FK users | Who triggered |
| `scan_id` | UUID FK scans, nullable | DAST scan; NULL for repo scans |
| `repo_scan_id` | UUID FK repo_scans, nullable | Repo scan; NULL for DAST |
| `runtime` | varchar(16) | `server` \| `desktop` |
| `status` | varchar(16) | `queued` / `cloning` / `running` / `committing` / `pushing` / `done` / `failed` / `canceled` |
| `findings_count` | int | snapshotted at run start |
| `iterations` | int | how many agent loop iterations completed |
| `current_step` | text | short human label (e.g. "reading app.py") |
| `branch_name` | varchar(255), nullable | set when branch is created |
| `pr_url` | text, nullable | set when PR opens |
| `error` | text, nullable | terminal failure message |
| `system_prompt` | text | snapshot of system prompt for this run |
| `model` | varchar(64) | claude-opus-4-7 or override |
| `created_at` | timestamptz | |
| `started_at` | timestamptz, nullable | |
| `completed_at` | timestamptz, nullable | |

Constraint: exactly one of `(scan_id, repo_scan_id)` is non-null.

### 4.2 `AgenticFixUsage`

Token accounting. One row per Messages API call.

| Column | Type | Notes |
|---|---|---|
| `id` | UUID PK | |
| `run_id` | UUID FK agentic_fix_runs | |
| `workspace_id` | UUID FK | denormalised for fast aggregation |
| `iteration` | int | which loop iteration produced this call |
| `model` | varchar(64) | |
| `input_tokens` | int | |
| `output_tokens` | int | |
| `cache_read_input_tokens` | int default 0 | |
| `cache_creation_input_tokens` | int default 0 | |
| `cost_usd_cents` | int | computed at row-write time using model price table |
| `created_at` | timestamptz | |

### 4.3 `AgenticFixStep`

Audit trail of agent tool calls — drives the progress UI + the audit log.

| Column | Type | Notes |
|---|---|---|
| `id` | UUID PK | |
| `run_id` | UUID FK | |
| `iteration` | int | |
| `step_index` | int | order within the iteration |
| `tool_name` | varchar(64) | "read_file", "bash", "TodoWrite", … |
| `tool_input` | jsonb | redacted of secrets where possible |
| `tool_output_truncated` | text | first 8 KiB of output |
| `tool_error` | text, nullable | |
| `duration_ms` | int | |
| `created_at` | timestamptz | |

### 4.4 Migration plan

Alembic revision adds the three tables. Existing `BulkFixTask` /
`FixProposal` rows stay untouched — the legacy flow keeps working.

## 5. API surface

All new endpoints sit under the existing `/fix-tasks/*` namespace +
a new `/llm/proxy` endpoint.

### 5.1 Start a run

`POST /fix-tasks/agentic`

```jsonc
{
  "scan_id": "uuid"  | "repo_scan_id": "uuid",  // exactly one
  "runtime": "server" | "desktop"               // default "server"
}
```

Response: `AgenticFixRunOut` with `id`, `status`, `runtime`. If
`runtime=server`, a Celery task is queued. If `runtime=desktop`, the
caller (desktop) is responsible for driving the loop via the proxy.

Server picks runtime when the caller doesn't specify:
- Cloud-provider repo → `server`.
- Local-provider repo (`provider="local"`) → must be `desktop`; server
  rejects with 400 if `runtime=server` is requested.

### 5.2 Stream progress (SSE)

`GET /fix-tasks/agentic/{run_id}/stream?workspace_id=…`

Emits events on each `AgenticFixStep` insert + on terminal status
changes. Event shapes:

```
event: step
data: {"iteration":3,"tool_name":"edit_file","tool_input":{...},
       "duration_ms":42}

event: status
data: {"status":"pushing","pr_url":null}

event: terminal
data: {"status":"done","pr_url":"https://github.com/…/pull/123"}
```

Reuses the existing scan SSE infrastructure
(`apps/api/.../routers/scans.py::stream_scan` pattern).

### 5.3 Cancel

`POST /fix-tasks/agentic/{run_id}/cancel` — sets `status=canceled`,
the running Celery task checks the flag between iterations.

### 5.4 Status fetch

`GET /fix-tasks/agentic/{run_id}` — `AgenticFixRunOut` + last 50
`AgenticFixStep` rows + usage rollup.

### 5.5 LLM proxy (for desktop runtime)

`POST /llm/proxy/messages` — wraps Anthropic Messages API. Desktop
sends the exact Messages API body; server validates the request,
charges the workspace, forwards to Anthropic with the shared key,
streams the response back.

Why a proxy instead of just handing the desktop a temporary key:
- API keys can't be safely scoped per-workspace by Anthropic.
- A proxy lets us enforce plan-tier limits per call, not just
  post-hoc.
- All token usage flows through one accounting choke point.

The proxy authenticates with the same Bearer token + `X-Workspace-Id`
as every other API call.

## 6. Tool surface

**Verified Claude Code parity inventory.** All tools listed below are
implemented on both runtimes (server-side Python + desktop Swift)
unless marked otherwise.

| Tool | Server | Desktop | Notes |
|---|---|---|---|
| `read_file` | ✓ | ✓ | Offset/limit paging supported |
| `write_file` | ✓ | ✓ | New files only; rejects existing paths |
| `edit_file` | ✓ | ✓ | String replacement; `replace_all` flag |
| `grep` | ✓ | ✓ | Ripgrep-compatible patterns |
| `glob` | ✓ | ✓ | Standard glob semantics |
| `bash` | ✓ | ✓ | Per-tool timeout (default 120s, max 600s). **Allowlist:** git, gh, npm, pip, pytest, cargo, go, make, semgrep, gitleaks, trivy, osv-scanner. Other commands rejected. |
| `TodoWrite` | ✓ | ✓ | In-run state, surfaces in progress UI. |
| `web_search` | ✓ | ✗ | Anthropic-native web search tool. Desktop omits — adds little value for fixes. |
| `mcp_call` | ✓ | ✗ | Server-side only in v1. Per-workspace MCP-server allowlist in settings. |

**Path safety:** every read/write/edit/grep/glob path is resolved with
`os.path.realpath` and verified to live under the run's workspace root.
Any path that resolves outside → tool error.

## 7. Agent loop

Pseudo-Python for the server-side worker (OpenAI chat-completions
shape — see `services/agentic_fixer/llm_client.py`):

```python
async def run_agent(run: AgenticFixRun, repo_path: Path) -> None:
    findings = await load_findings(run)
    system = build_system_prompt(findings, repo_path)
    messages: list[dict] = [build_initial_user_message(findings)]

    for iteration in range(MAX_ITERATIONS):  # default 30
        if await is_canceled(run.id):
            raise Canceled()
        response = await llm.create_message(
            system=system,
            tools=tool_catalog_openai(runtime="server"),
            messages=messages,
            max_tokens=4096,  # Sarvam-105b starter-tier cap
        )
        await log_usage(run, iteration, response.usage)

        if not response.tool_uses:
            # Agent returned text only → done.
            break

        # Echo the assistant's full message (including tool_calls)
        # back into the history so the model can pair its requests
        # with the tool results.
        messages.append({
            "role": "assistant",
            "content": response.text,
            "tool_calls": [
                {"id": tu.call_id, "type": "function",
                 "function": {"name": tu.name,
                              "arguments": json.dumps(tu.input)}}
                for tu in response.tool_uses
            ],
        })

        for tu in response.tool_uses:
            output = await dispatch_tool(
                run, repo_path, iteration, tu.name, tu.input,
            )
            messages.append({
                "role": "tool",
                "tool_call_id": tu.call_id,
                "content": output.content,
            })

    await finalize_pr(run, repo_path)
```

Same structure in Swift.

**Iteration cap:** 30 by default (configurable per workspace). If the
agent hits the cap without emitting a stop reason, mark `failed` and
surface the partial state.

**Token budget:** soft cap of 500K input + 50K output per run. Exceed →
abort + mark `failed:budget_exceeded`. Hard cap raised for enterprise
tier.

## 8. PR creation

Once the agent emits its final text turn (stop reason `end_turn`):

```bash
# Server-side worker (in the clone dir):
git checkout -b pencheff/agentic-fix-{run_id_prefix}
git add -A
git commit -m "fix: agentic security fixes for scan {scan_id_prefix}

{N} findings addressed:
{compact bullet list — top 10}

Co-authored-by: Pencheff Agent <agent@pencheff.com>"

# Try gh first:
if command -v gh >/dev/null && gh auth status >/dev/null; then
  git push -u origin HEAD
  gh pr create --title "..." --body "@bodyfile"
else
  # Fallback: GitHub PR API via installation token.
  git push -u origin HEAD
  curl -X POST https://api.github.com/repos/{full_name}/pulls ...
fi
```

PR body includes:
- Summary of findings addressed (link back to scan in Pencheff)
- Per-finding bullets with file:line anchors
- TodoWrite checklist of what the agent decided to do
- Agent's final assistant-turn text (its own summary)
- Footer: "Generated by Pencheff Agentic Fix · {run_id}"

## 9. LLM proxy + billing

### 9.1 Proxy semantics

`POST /llm/proxy/messages` is a near-passthrough to the Anthropic
Messages API:

1. Read `Bearer <pencheff_token>` + `X-Workspace-Id`.
2. Authorize: caller must have `fix_proposals:write` scope.
3. Refuse if the workspace's month-to-date `AgenticFixUsage` cost ≥
   plan-tier limit (see 9.3).
4. Forward to Anthropic with the server's `ANTHROPIC_API_KEY`.
5. Stream the response back unchanged (SSE).
6. On stream completion, parse `message.usage` and insert an
   `AgenticFixUsage` row keyed to the caller's active `run_id`
   (passed as a custom header `X-Agentic-Run-Id`).

### 9.2 Cost calculation

Server holds a price table per model (USD per million tokens). Updated
alongside Anthropic price changes. The row writer computes
`cost_usd_cents` as `(in*price_in + out*price_out - cache_read*price_cr) * 100`.

### 9.3 Plan-tier limits

Settings: per plan tier monthly budget cap. Defaults:

| Plan | Monthly cap (USD) | Iteration cap | Concurrent runs |
|---|---|---|---|
| Free | $5 | 10 | 1 |
| Pro | $50 | 30 | 3 |
| Team | $200 | 50 | 10 |
| Enterprise | configurable | configurable | configurable |

When a run starts: pre-flight check against month-to-date.
Mid-run: a usage-after-call hook re-checks and signals cancellation if
the cumulative cost crosses the cap.

A workspace setting `agentic_fix_user_key` (optional) lets enterprise
workspaces supply their own Anthropic key. When set, requests use that
key and bypass plan-tier dollar caps (but still honor iteration caps).

### 9.4 Settings UI

`/settings/agentic-fix`:

- Current MTD spend + remaining budget bar
- Last 20 runs table (status, finding count, tokens, cost)
- "Own Anthropic key" override (textarea, masked)
- "Allowed MCP servers" multi-text input

## 10. Security model

The agent has powerful tools. Constrain blast radius:

- **Path traversal:** all paths resolved + checked against workspace
  root. Symlinks resolved before the check.
- **bash allowlist:** binary lookup via PATH; reject if not in
  allowlist. Arguments are NOT validated (the LLM needs flexibility);
  the allowlist is the boundary.
- **No network from bash** (server-side): worker container runs with
  `--network=none` for bash subprocesses. `git push` happens via a
  privileged side-car. Desktop runs as the user — no equivalent
  constraint; documented in user-facing terms ("the agent can do
  anything you can do from a terminal").
- **No external file access (server-side):** clone dir is the only
  writable mount.
- **Secret redaction:** the bash tool's output is scanned for
  `AKIA[0-9A-Z]{16}`, `ghp_*`, `glpat-*`, etc. before being fed back
  to the LLM. Redacted bytes are replaced with `[REDACTED]`.
- **Audit:** every tool call → `AuditLog` (entity_type=`agentic_fix_run`).
- **PRs always go to a new branch.** Never push to default branch.
- **Never amend or force-push.** Branch is owned by the agent for the
  duration of the run.

## 11. UX

### 11.1 Webapp

Existing `FixAllSheet`-style modal grows a second tab:

```
┌─ Fix all findings ─────────────────────────────┐
│ [Legacy: per-finding]  [Agent (beta)]          │
│                                                 │
│ Findings: 14    Estimated cost: ~$0.40         │
│ MTD spend: $3.20 / $50.00                      │
│                                                 │
│ Tool transcript (live):                         │
│   📖 read_file app.py                           │
│   ✏️  edit_file app.py: lines 42-48             │
│   📖 read_file user.py                          │
│   ⚡ bash: git diff                              │
│   ...                                           │
│                                                 │
│ [Cancel]                          [Run]         │
└─────────────────────────────────────────────────┘
```

When `runtime=desktop` is selected for a local-provider repo, the
modal shows a "Install Pencheff Studio" prompt if the desktop isn't
detected (deep-link `pencheff-studio://fix-all?run=…`).

### 11.2 Desktop

New view (sibling to `LocalScanProgressSheet`) that:
- Streams `AgenticFixStep` rows in real time.
- Shows the agent's TodoWrite checklist.
- Links to the PR URL when created.
- Surfaces tool errors inline.

## 12. Observability

- Every run inserts a span into `/observability/scans/{scan_id}/trace`
  with kind=`agentic_fix` so the existing trace view shows it
  alongside scan stages.
- Audit log entries per tool call.
- Cost dashboard at `/settings/agentic-fix`.

## 13. Rollout

Behind a feature flag `agentic_fixer_enabled` (default false).
Per-workspace opt-in via Settings. Once stable, default to true for
Pro+ tiers.

## 14. Open questions

1. **Concurrency model:** parallel tool calls (Anthropic supports
   parallel tool_use blocks). v1: sequential dispatch within an
   iteration. v2: parallelize read-only tools.
2. **Model selection:** start with `claude-opus-4-7`. Allow override
   per workspace once we've baselined cost.
3. **MCP server allowlist:** how granular — allowlist by exact URL?
   Per-workspace audit? Keep simple in v1: comma-separated URL list
   in workspace settings, no per-call confirmation.
4. **Desktop key handling:** v1 ferries via server proxy. v2 may
   support BYO-key on the desktop directly.

## 15. Implementation order (across multiple sessions)

Tasks tracked in TaskList (#35–#42).

1. Spec doc (this file) — done.
2. Server-side core: DB + endpoints + agent loop scaffolding.
3. Core tools server-side (read/edit/grep/glob/bash).
4. Claude Code parity tools (TodoWrite/web search/MCP).
5. PR creation flow (gh + API fallback).
6. Token tracking + plan-tier enforcement.
7. Desktop Swift agent runtime.
8. UI wiring (webapp + desktop).
9. Tests + observability.

Each task ends with a commit on `feat/pencheff-studio` (or a sibling
`feat/agentic-fixer` branch — open question for the user at task #35
start).
