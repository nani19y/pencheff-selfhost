# Deterministic Workflows

Pencheff ships five workflow templates that drive the orchestrator end-to-end
with no model in the loop. Each is invokable from CLI and from the
`run_workflow` MCP tool.

| Workflow         | CLI                              | What it does                                        |
|------------------|----------------------------------|-----------------------------------------------------|
| `auto_pentest`   | `pencheff auto-pentest --target` | bug-bounty pipeline → CVE intel → red-team narrative |
| `bug_bounty`     | `pencheff bb-recon --target`     | Surface enum + scan + triage                        |
| `ctf_solve`      | `pencheff ctf-solve --challenge` | Classify + decode/extract; pure-python first        |
| `cve_intel`      | `pencheff cve-correlate --findings` | Map findings to CVEs (offline overlay + live feed) |
| `red_team`       | `pencheff redteam-narrative`     | MITRE ATT&CK section-by-section narrative           |

## Anatomy of a workflow

A workflow is just a coroutine. It composes the orchestrator's primitives:

```python
async def run(target: str, *, intensity: str = "default") -> dict:
    orch = Orchestrator()
    sub_result = await orch.run_tool_with_fallback(
        primary_tool="subfinder",
        target=target,
        objective="discovery",
        target_profile="web",
    )
    ...
```

`run_tool_with_fallback` consults:

1. `selector.candidates(profile, objective)` — picks the tool.
2. `fallback.resolve(tool)` — picks an installed alternative if the primary
   isn't on PATH.
3. `param_optimizer.args_for(tool, tier=...)` — composes the argv.
4. `cache.get(key)` — short-circuits if a fresh result exists.
5. `throttle.before_request_async()` — sleeps just enough to honour the
   current rate cap.
6. `result_normalizer.normalize(tool, stdout, target)` — turns stdout
   into `Finding` objects.

The workflow itself only orchestrates *order*. It does not contain
decisions about which tool, which args, or which back-off — those are all
delegated to the policy layer.

## Adding a new workflow

1. Drop a file under `pencheff/workflows/` with a `run(...)` coroutine.
2. Register it in `workflows/__init__.py` `_REGISTRY`.
3. Add a CLI subcommand in `__main__.py`.
4. Add tests under `tests/orchestrator/`.

## Determinism guarantees

For any pair of identical (target, intensity, policy versions, scope)
runs, a workflow will produce the same set of stages, the same selected
tools, and the same Finding categories. Times and request bodies will
differ; decisions will not.
