# Landing Page Content Inventory

> **Contract:** every item below must appear on the redesigned landing page.
> Wording is preserved verbatim unless explicitly changed. Only layout, visuals,
> component structure, and section ordering are open for redesign.
>
> Source: `apps/web/app/page.tsx` + `components/nav.tsx` (MarketingNav) +
> `components/pricing-content.tsx` (PricingPlans, PricingDeliverables,
> PricingComparison, PricingFAQ). Extracted 2026-04-19.

---

## 1. Marketing navigation (top of page)

- **Brand monogram** — letter **"P"** in a bordered square, followed by wordmark **"Pencheff"**. Links to `/`. Aria label: `Pencheff`.
- **Nav link:** `Pricing` → `/#pricing`
- **When signed-out (auth-gated):**
  - Nav link: `Sign in` → `/login`
  - Button (pink): `Open an account` → `/signup`
- **When signed-in (auth-gated):**
  - Nav link: `Dashboard` → `/dashboard`
  - Clerk `UserButton` (avatar menu)

---

## 2. Hero section

- **Eyebrow:** `Pencheff · Report № 2026 — Volume I`
- **Headline (H1), two lines, last phrase italicised in gilt:**
  - Line 1: `Adversarial security assessments,`
  - Line 2: `delivered with the` *`rigour of an audit.`*
- **Body paragraph:**
  > Pencheff examines your web applications and APIs with the discipline of a professional penetration test — and returns a letter grade, evidence-backed findings, and a formal report your auditors, engineers, and executives can read on the same page.
- **Primary CTA (pink button):** `Open an account` → `/signup`
- **Secondary CTA (lime button):** `Sign in` → `/login`
- **CTA helper text:** `Complimentary tier · no credit card required.`

### 2a. Specimen report card (hero right column)

- **Eyebrow:** `Specimen assessment`
- **Mono caption (top-right):** `Report № 0241-A`
- **Grade badge (large):** letter **`A`**
- **Severity summary row (5 columns: label / count):**
  - `Critical` — `0`
  - `High` — `1`
  - `Medium` — `3`
  - `Low` — `4`
  - `Info.` — `12`
- **Footer mono line:**
  > Issued 2026-04-18 · Methodology v4.2 · Instruments 49 · Framework mapping: OWASP Top 10 · SOC 2 · PCI-DSS · NIST · ISO 27001 · HIPAA

---

## 3. Section divider — `Methodology`

Decorative `§` rule separator, aria label `Methodology`.

---

## 4. Pillars (3 columns)

### Pillar 01
- Eyebrow: `§ 01 — Methodology`
- Title: `An assessment, not a scan.`
- Body: `Pencheff follows an adversarial methodology modelled on manual penetration testing — reconnaissance, authenticated coverage, business-logic probing, and exploit chaining — delivered with the consistency of automation.`

### Pillar 02
- Eyebrow: `§ 02 — Coverage`
- Title: `Forty-nine instruments. One verdict.`
- Body: `Injection, access control, authentication, cryptography, client-side, infrastructure, cloud, and API — examined with Pencheff's first-party probes. Auxiliary security tools are optional and operator-managed.`

### Pillar 03
- Eyebrow: `§ 03 — Reporting`
- Title: `Audit-ready, the moment it finishes.`
- Body: `Every assessment yields a formal report with executive summary, letter grade, and evidence — mapped to OWASP Top 10, SOC 2, PCI-DSS, NIST 800-53, ISO 27001, and HIPAA categories.`

---

## 5. Section divider — `Process`

---

## 6. Process section

- Eyebrow: `§ Process`
- Heading (H2): `Four steps, every engagement.`

### Step 01 — Register
`Provide a target URL and, optionally, credentials for authenticated coverage. All secrets are encrypted at rest.`

### Step 02 — Assess
`Commission a quick, standard, or deep assessment. Progress streams live; stages are logged for review.`

### Step 03 — Review
`Triage findings with full request/response evidence. Re-examine any finding after remediation with a single action.`

### Step 04 — Remediate
`Download a formal DOCX or PDF report, dispatch to ticketing, and close out with verified evidence.`

---

## 7. Section divider — `Pricing`

---

## 8. Pricing section (anchor `#pricing`)

- Eyebrow: `§ Subscriptions`
- Heading (H2): `Transparent pricing, per engineering organisation.`
- Body: `The deterministic Pencheff methodology is free and unlimited — every scan module, formal DOCX/PDF reports, compliance mapping, RBAC. Pro and Team add the autonomous layer on top: per-finding walkthroughs, automated false-positive triage, audit-style grade attestation, and engine-driven adaptive scanning.`

### 8a. Plans (3 cards)

#### Free (highlighted — gilt ribbon)
- Eyebrow: `Complimentary · Forever`
- Name: `Free`
- Price: `$0` · Cadence: `no card required`
- Tagline: `The full deterministic Pencheff methodology — every module, every report, every compliance mapping — free and unlimited. The only thing it does not include is the autonomous layer.`
- Bullets:
  1. `Unlimited organisations, workspaces, seats and targets`
  2. `Unlimited assessments per workspace per month`
  3. `Every scan module — recon, injection, auth, authz, OAuth, business logic, cloud, API, file handling, websocket, subdomain takeover`
  4. `Formal DOCX & PDF reporting`
  5. `Per-finding re-examination`
  6. `Authenticated coverage with encrypted credentials`
  7. `Compliance mapping (OWASP · PCI-DSS · SOC 2 · NIST · ISO 27001 · HIPAA)`
  8. `Finding suppression & workflow`
  9. `Role-based access (owner · admin · member)`
  10. `Heuristic letter grade, findings register, JSON & CSV export`
- CTA: `Open an account` → `/signup`

#### Pro (Coming soon)
- Eyebrow: `Coming soon`
- Name: `Pro`
- Price: `$49` · Cadence: `per month`
- Tagline: `Everything in Free, plus the autonomous layer: per-finding walkthroughs, automated false-positive triage, audit-style grade attestation, and engine-driven adaptive scanning.`
- Bullets:
  1. `Per-finding walkthroughs (overview · impact · prevention · attack scenarios)`
  2. `Automated false-positive triage at scan time`
  3. `Audit-style grade attestation with executive rationale`
  4. `Engine-driven adaptive scanning`
  5. `Everything in Free — unlimited`
  6. `Correspondence within 24 hours`
- CTA: `Notify me at launch` (disabled)

#### Team (Coming soon)
- Eyebrow: `Coming soon`
- Name: `Team`
- Price: `$199` · Cadence: `per month`
- Tagline: `Pro plus the org-wide knobs — single sign-on, branded reporting, and a dedicated correspondence channel for shared security responsibility.`
- Bullets:
  1. `Everything in Pro — including the full autonomous layer`
  2. `Branded reporting`
  3. `Single sign-on (forthcoming)`
  4. `Dedicated Slack correspondence channel`
  5. `Priority vulnerability response`
- CTA: `Notify me at launch` (disabled)

### 8b. Deliverables

- Eyebrow: `§ Deliverables`
- Heading (H3): `Contents of the formal report.`

**Card A — For engineering · "The technical dossier."**
- `Request & response evidence for every finding.`
- `CVSS 3.1 score and vector.`
- `CWE classification.`
- `Remediation guidance with illustrative code.`
- `On-demand re-examination to confirm a fix.`

**Card B — For audit & executive · "The executive dossier."**
- `Executive summary with letter grade and severity counts.`
- `Findings mapped to OWASP Top 10 (2021) categories.`
- `SOC 2 CC6 / CC7 control mapping.`
- `PCI-DSS 4.0, NIST 800-53, ISO 27001:2022, HIPAA mapping.`
- `Audit-ready DOCX and PDF.`

### 8c. Comparison table

- Eyebrow: `§ Comparison`
- Heading (H3): `Subscription tiers in detail.`

| Provision | Free | Pro · soon | Team · soon |
|---|---|---|---|
| Unlimited assessments per workspace | · | · | · |
| Unlimited workspaces / seats / targets | · | · | · |
| Every deterministic scan module | · | · | · |
| Formal DOCX / PDF reporting | · | · | Branded |
| Compliance mapping (OWASP · PCI · SOC 2 · NIST · ISO · HIPAA) | · | · | · |
| Authenticated assessments (stored credentials) | · | · | · |
| Per-finding re-examination | · | · | · |
| Finding suppression & workflow | · | · | · |
| Role-based access (owner / admin / member) | · | · | · |
| Heuristic letter grade | · | · | · |
| JSON / CSV export | · | · | · |
| AI per-finding walkthroughs | — | · | · |
| AI false-positive triage | — | · | · |
| Grade attestation (executive rationale) | — | · | · |
| Engine-driven adaptive scanning | — | · | · |
| Single sign-on | — | — | Forthcoming |
| Dedicated correspondence channel | — | — | · |

### 8d. FAQ

- Eyebrow: `§ Enquiries`
- Heading (H3): `Frequently considered questions.`

1. **Q:** `Is this authorised?`
   **A:** `Pencheff is for applications you own or have been granted written permission to assess. It is an instrument of assurance, not a means of unauthorised access. Please direct it only at systems within your mandate.`

2. **Q:** `What does Pro unlock?`
   **A:** `Autonomous features only. The deterministic methodology — every scan module, formal DOCX/PDF reports, compliance mapping, RBAC, suppression workflow, recheck, and unlimited scans — is free forever. Pro adds per-finding walkthroughs, automated false-positive triage, audit-style grade attestation, and engine-driven adaptive scanning.`

3. **Q:** `What constitutes a single assessment?`
   **A:** `One complete engagement against a target — reconnaissance, infrastructure, injection, client-side, authentication, authorisation, advanced web, API, business logic, cloud, file handling, websocket, subdomain takeover, and exploit chaining. Re-examination of individual findings is unlimited on every plan.`

4. **Q:** `How long does an assessment take?`
   **A:** `Quick profile: 2–5 minutes. Standard: 10–25 minutes. Deep: 30–90 minutes, contingent on application breadth.`

5. **Q:** `May these reports be used for SOC 2, PCI, or ISO audits?`
   **A:** `Yes. DOCX and PDF reports include evidence-backed mapping to OWASP Top 10 (2021), PCI-DSS 4.0, NIST 800-53, SOC 2 (CC6/CC7), ISO 27001:2022, and HIPAA Security Rule — accepted by auditors as evidentiary material. This is part of Free.`

6. **Q:** `Is self-hosting supported?`
   **A:** `Yes. Pencheff is distributed as a Docker Compose stack under the GNU AGPL-3.0 licence. Set the organisation's plan to self_hosted to enable AI features locally with your own LLM_API_KEY. Refer to the repository documentation for installation.`

7. **Q:** `How are credentials handled?`
   **A:** `Credentials are encrypted at rest with Fernet (AES-128 in CBC mode with HMAC-SHA256). Removing a target removes its credentials immediately.`

---

## 9. Section divider — `Closing`

---

## 10. Closing CTA

- Eyebrow: `§ Begin`
- Heading (H2): `Commission your first assessment.`
- Body: `A complimentary assessment takes under three minutes to commission and under thirty to complete. No credit card, no sales call.`
- Primary button (pink): `Open an account` → `/signup`
- Secondary button (lime): `Review pricing` → `/pricing`

---

## 11. Footer

- Left (body font): `Pencheff · {CURRENT_YEAR} · All rights reserved.`  *(year rendered dynamically — preserve the pattern)*
- Right (mono, muted): `For authorised testing only.`

---

## Tokens & named styles referenced (preserve or re-express)

- Color tokens: `ink`, `slate`, `mist`, `gilt`, `graphite`, `paper`, `vellum`, `hairline`
- Type families: `font-display`, `font-body`, `font-mono`
- Reusable utility classes named in markup: `eyebrow`, `eyebrow-gilt`, `rule`, `rule-section`, `formal-surface-elev`, `gilt-ribbon`, `shadow-report`, `brutal-table`
- Buttons: `Button` with variants `pink`, `lime` (from `@/components/brutal`)
- `GradeBadge` component with `grade` (A–F) and `size` prop

## Links inventory (every outbound path)

- `/` (brand)
- `/signup`
- `/signup?plan=pro`
- `/signup?plan=team`
- `/login`
- `/dashboard`
- `/pricing`
- `/#pricing`

## Dynamic / auth-gated behavior (must be preserved)

- MarketingNav swaps sign-in/open-account for Dashboard + UserButton when `isSignedIn`.
- Pro pricing card shows a gilt ribbon and elevated shadow in marketing mode.
- Footer year is the current year, computed at render.
