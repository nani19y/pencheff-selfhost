# API Methodology (REST / GraphQL / gRPC)

## Discovery
- Spec import: OpenAPI / Swagger / Postman → `pencheff api --spec spec.json`
- GraphQL introspection: `query { __schema { types { name } } }`
- Burp/Caido sitemap, JS endpoint extraction, `kiterunner` against gobuster wordlists

## Authentication
- API keys in URL/header — leak via Referer / logs
- JWT: alg=none, weak HS256, kid traversal, JKU header injection
- OAuth/OIDC: insufficient scope checks, ROPC, token introspection abuse
- mTLS bypass via direct backend access

## Authorization (BOLA / function-level)
- Object-level: swap IDs for another tenant's
- Function-level: hidden /admin endpoints
- Field-level: GraphQL field-level authz checks

## OWASP API Top 10 (2023)
- API1 BOLA, API2 Broken Auth, API3 Broken Object Property Level Auth,
  API4 Unrestricted Resource Consumption, API5 BFLA,
  API6 Unrestricted Access to Sensitive Business Flows, API7 SSRF,
  API8 Security Misconfiguration, API9 Improper Inventory,
  API10 Unsafe Consumption of APIs

## Mass assignment
- Send extra fields like `is_admin`, `role`, `verified` and observe response state.

## Rate limit / DoS
- Hit endpoint at high concurrency, depth-bomb GraphQL queries, batch query abuse.

## Webhook abuse
- SSRF via webhook URL, signature replay, timing attacks on hash compare.
