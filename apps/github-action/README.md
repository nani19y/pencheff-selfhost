# Pencheff GitHub Action

Run a Pencheff scan against a preview deployment and fail the build on findings above a chosen severity threshold. Posts an inline summary on the triggering PR.

```yaml
name: Security
on:
  pull_request:
    branches: [main]

jobs:
  pencheff:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write
    steps:
      - uses: actions/checkout@v4
      - uses: pencheff/pencheff-action@v1
        with:
          target: https://preview-${{ github.event.pull_request.number }}.example.com
          profile: cicd
          fail-on: high
```

## Inputs

| Input | Default | Notes |
|---|---|---|
| `target` | (required) | URL or HOST:PORT to scan. |
| `profile` | `cicd` | One of `quick`, `standard`, `deep`, `api-only`, `compliance`, `cicd`. |
| `fail-on` | `high` | Build fails if any finding meets or exceeds this severity. |
| `engagement-id` | `""` | Optional engagement id; ties findings into a multi-day engagement. |
| `api-base` | `""` | Set when running against a hosted Pencheff backend. |
| `api-token` | `""` | Bearer token for the Pencheff API. |
| `pr-comment` | `true` | Post a Markdown summary as a PR comment. |

## Outputs

- `report-path` — path to the JSON+Markdown report on the runner.
- `worst-severity` — `critical | high | medium | low | info | none | error`.
