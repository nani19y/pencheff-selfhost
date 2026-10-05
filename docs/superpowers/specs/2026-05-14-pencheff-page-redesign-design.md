# Design: Pencheff App Page Redesign

**Date:** 2026-05-14  
**Status:** Approved — implementing

---

## Goal

Redesign all 8 main app pages + nav header to match the editorial/broadsheet visual system from 10 approved UI mockups, while preserving all existing data-loading logic and API integrations.

---

## Design System

**Palette:** ink `#1A1713`, paper `#FFFFFF`, vellum `#F5F5F5`, hairline `#C8BFA6`, gilt `#C9A24E`, graphite `#3A362C`, slate `#6B6454`, mist `#94A3B8`

**Type:** Fraunces (display headings) · Source Sans 3 (body) · JetBrains Mono (code/data)

**Pattern per page:**
- Eyebrow: `font-mono text-[11px] uppercase tracking-[0.18em] text-gilt` — e.g. "§ WORKSPACE — DASHBOARD"
- Heading: `font-display text-[40px] text-ink leading-[1.05]`
- Subtitle: `font-body text-[14px] text-slate`
- Stat bar: row of stat cards (number + label + optional delta/badge)
- Main content area + right intelligence panel (~300px, `border-l border-hairline`)
- Actions: primary = `bg-ink text-paper` button, secondary = `border border-ink text-ink bg-paper`

---

## Shared Components (new)

| Component | File | Purpose |
|-----------|------|---------|
| `StatCard` | `components/app/stat-card.tsx` | Number + label + optional subtext, used in stat bars |
| `PageHeader` | `components/app/page-header.tsx` | Eyebrow + title + subtitle + action slot |
| `IntelPanel` | `components/app/intel-panel.tsx` | Right sidebar with title + content slot |
| `AppTable` | `components/app/app-table.tsx` | Consistent table with header row + body rows |

---

## Nav Header Updates

- **"AI AGENTS N ONLINE"**: green dot `bg-green-400` + `font-mono text-[11px]` label, shown in header between search and user controls
- User display: first name + "Owner" role label (already implemented in previous session)
- Plan badge: `+FREE` or `+PRO` style (already implemented)

---

## Page Designs

### Dashboard (`/dashboard`)

**Stat bar (6 cards):** Security Grade · Total Targets · Active Assessments · Exploitable Findings · Coverage Score · Est. Remediation Impact  
*Data from:* `targets.length`, `scans`, computed from scan summaries

**Two-column layout:**
- Left (main): Recent assessments table (target, grade, status, findings breakdown), Register Target CTA if no targets
- Right panel (~300px): Risk heatmap by severity × source, recent findings stream

---

### Targets (`/targets`)

**Stat bar (3 cells):** Web / API count · Repo count · LLM / AI count  
*Derived from:* `targets.filter(t => kind === 'url').length` etc.

**Main area:**
- Filter tabs: All · URL · Repo · LLM
- Risk table: name · URL/repo · kind badge · credentials badge · actions (Commission Scan · Edit · Delete)

**Right panel:** Exposure intelligence — top exposed targets, coverage gaps

---

### Findings (`/findings`)

**Stat bar (6 cells):** Critical · High · Medium · Low · Suppressed · KEV  
*Derived from:* page total counts by severity + suppressed flag

**Main area:**
- Filter bar: source chips (SAST/DAST/SCA/IaC/Secret) · severity pills · reachability pills · suppressed toggle
- Table: severity pill · title · source badge · CVSS/EPSS · location · CWE

**Right panel:** Triage intelligence — SSVC breakdown, top CWE categories

---

### Assessments (`/scans`)

**Stat bar (4 cells):** Total · Running · Scheduled · Completed  
*Derived from:* `scans.filter(s => s.status === x).length`

**Main area:**
- Table: grade badge · report № · target · date · status dot · finding counts · Review/Delete actions

**Right panel:** Assessment intelligence — grade distribution, avg findings per scan

---

### Schedules (`/schedules`)

**Stat bar (3 cells):** Active schedules · Next run · Targets covered

**Main area:** Schedules table — name · target · cron expression · last run · next run · status · actions

**Right panel:** Automation intelligence — schedule coverage, upcoming runs timeline

---

### Integrations (`/integrations`)

**Main area:** Category-grouped integration cards (Connected/Degraded/Available) — icon + name + status badge + Connect/Configure button

**Right panel:** Event stream — recent webhook events, integration health

---

### Team (`/org/settings`)

**Main area:** Members table — avatar · name · email · role badge · MFA · SSO · last active · actions

**Right panel:** Access intelligence — role distribution, pending invites

---

### API Keys (`/settings/api-keys`)

**Main area:** Keys table — prefix · name · scopes · created · last used · status · Revoke action; Create key form below

**Right panel:** Access risk — scope usage, recent API activity

---

## Implementation Order

1. Shared components (StatCard, PageHeader, IntelPanel, AppTable)
2. Nav header ("AI AGENTS N ONLINE" badge)
3. Dashboard — most complex, sets patterns
4. Targets → Findings → Assessments → Schedules → Integrations → Team → API Keys

---

## Constraints

- All existing `api()` calls, `useState`, `useEffect`, filtering logic preserved as-is
- No new npm packages
- TypeScript strict — no `any` unless already present
- `cn()` from `@/lib/cn`, `Button`/`Input`/`GradeBadge`/`SeverityPill` from `@/components/brutal`
- Intelligence panels show computed/summarized data from already-loaded API responses — no extra API calls
