# Pencheff — LLM Red Team Grafana dashboard

Eight-panel dashboard for the OWASP LLM Top 10 red-team scan output:

- Total failures (stat)
- Failures by OWASP LLM category (bar gauge)
- Failures by severity (donut)
- Failures by attack strategy (table)
- Regression rate over 7 days (line)
- Top-10 failed techniques (table)
- Probe latency p50 / p95 / p99 (line)
- Token cost trend (line, USD)

## Prerequisites

Pencheff exports Prometheus metrics from `reporting.render_prometheus_metrics`. Wire your scraper at one of:

1. **Push gateway** — POST the rendered metrics block to a Prometheus push gateway after each scan completes. Pencheff's GitHub Actions workflow (`.github/workflows/pencheff-llm-redteam.yml`) does this when `PUSHGATEWAY_URL` is set.
2. **Pull endpoint** — host the rendered metrics at `/metrics` on a small sidecar that re-renders the latest scan's findings on demand. The exporter is a pure function so this is ~30 lines of FastAPI.

Either way, your Prometheus instance ends up with these series:

```
pencheff_llm_redteam_failures_total{target="..."}
pencheff_llm_redteam_failures_by_category{target, category}
pencheff_llm_redteam_failures_by_severity{target, severity}
pencheff_llm_redteam_failures_by_strategy{target, strategy}
```

The latency histogram and cost counter (`pencheff_llm_redteam_probe_latency_ms_bucket`, `pencheff_llm_redteam_cost_usd_total`) are emitted by future engine telemetry — the dashboard panels render gracefully when those series don't yet exist (Grafana shows "No data" rather than failing).

## Install

Grafana 11.x:

1. **Dashboards → Import** → upload `pencheff-llm-redteam.json`.
2. Pick your Prometheus datasource at the prompt (the `${prometheus_ds}` template variable).
3. Optional: edit the `target` template variable's regex to scope the dashboard to a single environment.

The dashboard is tagged `pencheff`, `llm-redteam`, `owasp-llm-top-10` so it shows up in the relevant tag-filtered library.

## Refresh & data window

Default refresh: 1 minute. Default time range: last 7 days. Both adjustable per panel.

## Out of scope

Real-time per-finding tail logs aren't here — those live in the scan SSE stream. This dashboard is for population-level trends, not per-scan triage.
