# Pencheff Sentry

Runtime LLM guardrail. Sits between your application and the model
provider (or as a LiteLLM plugin / MCP middleware) and blocks prompt
injection, PII exfiltration, secret leakage, and tool-authz violations
*as they happen* — instead of catching them post-hoc on a Pencheff scan.

Sentry reuses the same detector library as the Pencheff red-team
scanner. Anything the scanner finds offline, Sentry blocks online,
with the same OWASP-LLM-Top-10 taxonomy.

## Modes

| Mode | What it is | When to use |
| --- | --- | --- |
| **HTTP proxy sidecar** | A FastAPI service in front of your LLM endpoint | OpenAI-compatible providers; drop-in URL change |
| **LiteLLM plugin** | A `pre_call` / `post_call` hook | Existing LiteLLM stack; one-line install |
| **MCP middleware** | Wraps the MCP tool-call path | LLM agents calling tools; blocks unsafe tool args inline |

The default judge is **IBM Granite Guardian** (Apache-2.0). Llama
Guard 3 is opt-in and requires `PENCHEFF_LLAMA_GUARD_ENABLED=1` per
the Llama Community License (≤700 M MAU + attribution).

## Quick start (HTTP proxy)

```bash
pip install pencheff-sentry

pencheff-sentry serve \
    --upstream https://api.openai.com/v1 \
    --port 4242 \
    --judge openai-moderation \
    --judge-endpoint https://api.openai.com/v1/moderations
```

Point your application at `http://localhost:4242` instead of the
upstream URL. Requests/responses flow through the detector chain;
unsafe ones are blocked with a `403 Sentry: <reason>` and logged to
the configured sink.

## What it blocks

| Category | Detector |
| --- | --- |
| LLM01 — Prompt injection | Regex + judge ensemble |
| LLM02 — Sensitive info disclosure | PII regex (SSN, card, email, phone) + judge |
| LLM05 — Improper output handling | XSS / `<script>` / iframe in model output |
| LLM06 — Excessive agency | Tool-call argument inspection (MCP middleware mode) |
| LLM10 — Unbounded consumption | Token / latency / cost ceilings |

The full detector list is configurable per-deployment via
`config.yaml`.

## License

MIT. See `LICENSE` at the Pencheff repo root.
