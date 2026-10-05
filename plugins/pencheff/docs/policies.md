# Decision-Table Policies

Pencheff's deterministic orchestrator consults seven YAML files under
`pencheff/data/policies/`. Each file ships pre-validated; users can override
any of them at runtime via `PENCHEFF_POLICY_DIR=/path/to/overrides` (the
loader checks the override path first, then falls back to package data).

| File                     | Drives                                                    |
|--------------------------|-----------------------------------------------------------|
| `tool_selection.yaml`    | Which tool runs for `(target_profile, objective)`         |
| `parameters.yaml`        | What CLI args each tool gets at each intensity tier       |
| `chains.yaml`            | Multi-step attack templates                               |
| `fallbacks.yaml`         | Tool→tool fallback chains for graceful degradation        |
| `throttle.yaml`          | AIMD rate-control parameters and HTTP-status triggers     |
| `cve_correlation.yaml`   | Banner→CVE offline overlay (live feed is the fallback)    |
| `confidence.yaml`        | Signal weights for finding confidence scoring             |

## Versioning

Every file has a top-level `version: N`. The orchestrator records the
version of each policy that participated in a run. Bump the version when a
change would alter run output; tests guard against accidental drift.

## Editing rules

1. **Cite sources.** Each entry should be defensible from the wrapped
   tool's own documentation. Add a `# source: ...` header comment when in
   doubt. Do not import from any third-party orchestrator's source.
2. **Prefer additive changes.** New profile? New tool? Add an entry. Don't
   change the meaning of existing keys.
3. **Test the edit.** `pytest plugins/pencheff/tests/orchestrator/` runs in
   ~0.5 s; the suite covers every public selector/optimizer behaviour.

## Authoring example

Add a new objective `discovery_kerberos` for the `network` target profile:

```yaml
# tool_selection.yaml
profiles:
  network:
    discovery_kerberos:
      - { tool: kerbrute,  confidence: 0.95, ttl: 600,  notes: "user-list brute" }
      - { tool: nmap,      confidence: 0.70, ttl: 1800, notes: "nmap krb5-enum-users" }
```

Then add tool args:

```yaml
# parameters.yaml
tools:
  kerbrute:
    stealth:    ["userenum", "--dc", "{dc_ip}", "--rate", "10"]
    default:    ["userenum", "--dc", "{dc_ip}", "--rate", "100"]
    aggressive: ["userenum", "--dc", "{dc_ip}", "--rate", "500"]
```

That is the entire change. The orchestrator picks it up automatically.

## When **not** to use the policy layer

- One-off conditional logic per workflow → put it in `workflows/<name>.py`.
- Anything that genuinely needs runtime context the YAML cannot capture
  (e.g. response-shape inspection) → goes in the orchestrator's Python
  layer, not in YAML. The line is: data → YAML, control flow → Python.
