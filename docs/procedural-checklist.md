# Procedural items — Phases 0.6, 4.3, 4.4, 4.5

Phase 0.6 and Phase 4.3-4.5 of the IP-clean expansion plan don't
touch the codebase. They're tracked here so they stay visible while
the engineering team works on the code-substantive sub-items.

## Phase 0.6 — Trademark searches

Owner: external IP counsel.
Budget: ~$25k one-time.
Wall time: ~3 months from instruction → registered.

### Action items

| Item | Status | Notes |
| --- | --- | --- |
| USPTO search — `Pencheff` (Class 9 + 42) | not started | Wordmark + logo |
| USPTO search — `Pencheff Sentry` | not started | Phase 3.1 working name |
| USPTO search — `Pencheff Suggest` | not started | Phase 3.3 PR-bot working name |
| EUIPO search — same three marks | not started | EU coverage |
| Madrid Protocol filing | not started | International cover |
| File trademarks on the marks that survive search | not started | After search results |

If `Pencheff Sentry` collides (Lakera Guard / Protect AI / Robust
Intelligence Layer all live in adjacent space — likely some collision
risk), fall back to alternatives the team has pre-vetted: `Pencheff
Aegis`, `Pencheff Ward`, `Pencheff Veil`. Same for `Pencheff Suggest`
if it conflicts with anything in the GitHub ecosystem.

## Phase 4.3 — GitHub Secret Scanning Partner program

Owner: security engineering.
Budget: ~$0 — application + integration work only.
Wall time: ~3 months acceptance + ~2 weeks integration.

### Action items

| Item | Status | Notes |
| --- | --- | --- |
| Apply via https://github.com/secret-scanning-partner | not started | Requires a publishable secret-pattern doc |
| Document Pencheff-issued secret shapes | not started | API keys (`pencheff_pat_…`), ingest tokens |
| Implement the partner verification endpoint | not started | GitHub posts candidate matches; we verify and respond |
| Production-ready endpoint at `/api/secret-scanning/verify` | not started | Reuses Phase 1.2 HMAC primitive for signature verification |

Phase 4.3 only blocks customers who want auto-revoke for leaked
**Pencheff** secrets. The Phase 4.1 admission webhook + the existing
gitleaks scanner cover the customer-secret leakage case independently.

## Phase 4.4 — SOC 2 Type II + ISO 27001:2022

Owner: compliance lead (hire pending — see 4.5).
Budget: ~$60k Year-1 audit fees + Vanta/Drata seat (~$15k/yr).
Wall time: 9 months SOC 2 Type II report; ISO 27001 Stage 1 in Q4 of
Year 1, Stage 2 in Q1 of Year 2.

### Action items

| Item | Status | Notes |
| --- | --- | --- |
| Pick evidence-collection vendor (Vanta vs Drata) | not started | Both auto-ingest GitHub / AWS / GitHub Apps |
| Hire compliance lead | not started | See Phase 4.5 |
| Pre-audit readiness sweep | not started | ~3 months work |
| Audit window opens | scheduled | Q3 Year 1 |
| Audit window closes / report issued | scheduled | Q4 Year 1 |
| ISO 27001 Stage 1 | scheduled | Q4 Year 1 |
| ISO 27001 Stage 2 | scheduled | Q1 Year 2 |
| HIPAA BAA-ready (cycle continues) | scheduled | Year 2 |

The licensing / DCO / SBOM machinery shipped in Phase 0.4 + 1.3 maps
directly onto SOC 2 CC8.1 (change-management) + CC7.1 (vulnerability
management) + ISO 27001 A.5.21 (supply-chain controls). Auditors
typically accept these at face value — the work below is the
*remaining* organisational evidence (access reviews, incident
runbooks, BCP/DR test logs, training records).

## Phase 4.5 — Customer support tier hires

Owner: head of engineering.
Budget: ~$280k Year 1 (2 SecOps eng + 1 CSM).
Wall time: ~3-4 months per role.

### Action items

| Item | Status | Notes |
| --- | --- | --- |
| Define tier SLAs (community Slack / Email-NBD / 24×7 + Slack Connect) | not started | Documented in pricing once defined |
| Hire SecOps engineer #1 | not started | Q1 |
| Hire SecOps engineer #2 | not started | Q2 |
| Hire CSM | not started | Q3 |
| Stand up Slack Connect | not started | After first Team-tier customer |
| 24×7 on-call rotation | not started | Once 2nd SecOps is onboard |

The community Slack and Email-NBD tiers can run on the existing
engineering rotation while the team is small; 24×7 is the gate that
needs the second SecOps hire.

---

Last reviewed: 2026-05-08. Update this file in the same PR that
moves any of these line items between states.
