---
title: pencheff-blog-creation skill redesign — short reads, comparison mode, images
date: 2026-05-16
status: approved
target: /Users/balasriharsha/.claude/skills/pencheff-blog-creation/SKILL.md
---

# pencheff-blog-creation skill redesign

## Motivation

The current skill produces a single output shape: a 2,000+ word, 8-section deep-dive
security research post. Two real-world needs are unserved:

1. **Short, scannable 5-minute reads** for routine vulnerability writeups, weekly
   security notes, and short technical posts where a 2,000-word format is overkill
   and slows authoring.
2. **Comparison-style posts** ("top 10 pentesting tools", "Pencheff vs Tool X") that
   place Pencheff in an honest, mid-rank position with a transparent rubric — useful
   for marketing pages and SEO without slipping into astroturf.

The redesign keeps the existing deep-dive workflow available as an opt-in mode and
adds two new modes (`short`, `comparison`) with new structure, length, image, and
honesty contracts. It also tightens the existing writing-quality rules around
truthfulness, intuitive structure, and accessibility ("easy to understand").

## Current state and gap

- Current file: `/Users/balasriharsha/.claude/skills/pencheff-blog-creation/SKILL.md` (17.4 KB).
- Renderer at `apps/blog/` already supports markdown with images, tables, code,
  video, and audio. Image references like `images/x.png` are rewritten to
  `/api/asset/images/x.png` automatically.
- Existing skill has 5 phases: parse input, optional topic discovery, deep research
  with 4 parallel agents, optional `/browse` screenshot, write the post, save.
- Gap: only one mode; no comparison support; image capture is described as optional
  and rarely runs; no word-count or asset-count verification on save.

## Architecture: Approach A — single file, mode router

One redesigned `SKILL.md` (~22 KB). Phase 0 detects mode and routes to mode-specific
branches in later phases. Slug rules, save logic, and the save report are shared.
This is the closest shape to the current skill and minimizes the risk that Claude
follows the wrong branch.

## Phase 0 — Parse input and detect mode

Apply detection in this order; first match wins. Then strip the matched mode prefix
from `TOPIC` before continuing.

| Priority | Signal | Mode |
|---|---|---|
| 1 | `ARGUMENTS` is empty | `short` (run topic discovery first) |
| 2 | starts with `deep:` or contains `mode=deep` | `deep` |
| 3 | starts with `comparison:` / `compare:` or contains `mode=comparison` | `comparison` |
| 4 | matches `/\btop\s+\d+\b/i`, `/\bvs\.?\b/i`, `/\bcompar(e\|ison)\b/i`, `/\bbest\s+\d+\b/i` | `comparison` |
| 5 | otherwise | `short` |

Announce one line to the user:

```
Topic: <TOPIC> | Mode: <short|deep|comparison> | Slug: <SLUG>
```

### Slug rules (clarified)

The legacy skill's slug rules were internally inconsistent — their stated steps
strip hyphens (so `CVE-2025-12345` becomes `cve202512345`), but the worked
examples in the same file keep them as `cve_2025_12345`. The plan resolves this
in favor of the examples (the intended behavior). The clarified rules are:

1. Lowercase the entire string.
2. Replace every character that is not `a-z` or `0-9` with `_`.
3. Collapse runs of `_` into a single `_`.
4. Trim leading and trailing `_`.

Examples (now consistent with the rules):

- `"CVE-2025-12345: SQL injection in Django"` → `cve_2025_12345_sql_injection_in_django`
- `"top 10 pentesting tools"` → `top_10_pentesting_tools`
- `"Pencheff vs Burp Suite"` → `pencheff_vs_burp_suite`

## Frontmatter (all modes)

```yaml
---
title: "<headline>"
date: "<YYYY-MM-DD>"
description: "<two-sentence SEO summary>"
author: "Pencheff Security Team"
mode: "<short|deep|comparison>"
read_time: "<N> min"
topics: ["<tag1>", "<tag2>", "<tag3>"]
hero_image: "images/<slug>-hero.png"   # only if a real file was saved
---
```

`mode` and `read_time` are new machine-readable fields the renderer can later use
for filters and read-time chips. `hero_image` is omitted when no real image file
was saved (placeholders do not get this field, so the renderer never references a
missing asset).

## Word-count and asset contracts

| Mode | Body word target | Hard ceiling | Min code blocks | Min tables | Min images |
|---|---|---|---|---|---|
| short | 800–1,200 | 1,300 | 2 | 1 | 1 (hero) — placeholder OK if capture failed |
| deep | 2,000+ | none | 3 | 1 | optional |
| comparison | 1,200–1,800 | 2,000 | 1 (PoC for #1 tool only) | 2 (rubric + ranking) | 1 logo strip — text fallback OK |

Phase 5 enforces these contracts with a bounded retry loop (see below).

## Comparison mode rules

### N detection

- Default `N = 10`.
- `/top\s+(\d+)/i` in `TOPIC` overrides → `N = clamp(matched, 3, 15)`.

### Pencheff rank

- Default `pencheff_rank = 3`.
- Configurable via `pencheff_rank=N` token in `ARGUMENTS`
  (example: `comparison: top 8 SAST tools pencheff_rank=4`).
- Clamped to `[2, ceil(N/2)]`. This prevents:
  - rank 1 (looks like marketing),
  - bottom-half (defeats the purpose of the post).

### Scoring rubric (printed in every comparison post)

Pick 5 criteria from this fixed bank, weighted to sum to exactly 100. Print as
a table near the top of the post titled "Here's how we scored each tool."

| Criterion | Default weight | When to include |
|---|---|---|
| Coverage breadth (surfaces tested) | 25 | Always |
| Detection accuracy / false-positive rate | 20 | Always |
| AI / automation capability | 20 | If AI relevant to category |
| Reporting & remediation guidance | 15 | Always |
| Ease of setup & integration | 10 | Always |
| Pricing model transparency | 10 | If pricing data is reachable |
| Open-source / self-host option | 10 | If OSS tools are in the list |

If a chosen criterion's data is unavailable for a tool, mark that cell "n/a" rather
than guessing.

### Per-tool research (new Phase 1.5)

Spawn `N` parallel `general-purpose` Agent calls — one per tool — in a single
message. Each agent task: find official site URL, founding year, deployment model
(SaaS / self-host / hybrid), top 3 sourced strengths, top 2 sourced weaknesses,
pricing tier if public. Return structured.

**Special case for Pencheff:** the Pencheff agent reads
`/Users/balasriharsha/BalaSriharsha/pencheff/README.md` and recent git commits
instead of web-searching. This is the source of truth for Pencheff's strengths and
weaknesses.

### Honesty requirements (mandatory in every comparison post)

1. Each entry shows ≥1 weakness, including Pencheff.
2. Tools ranked above Pencheff must have ≥1 weakness Pencheff doesn't share,
   named explicitly. Example: "Tool A has stronger SAST language coverage; Pencheff
   focuses on web DAST + LLM red teaming."
3. Disclosure callout near the top:
   > Disclosure: Pencheff is the publisher of this post. We placed ourselves at
   > rank N based on the criteria below. Rankings reflect our editorial view; you
   > should weigh the criteria against your own priorities.
4. No claim about a competitor that wasn't found in the research agent's sources.
   Every claim has an inline source link.

### Per-tool entry template

```markdown
### #N — <Tool name>
![<Tool name> logo](images/<slug>-logo-<vendor-slug>.png)
*<one-line tagline>*

**Strengths**
- <strength 1 with inline source>
- <strength 2 with inline source>
- <strength 3 with inline source>

**Weaknesses**
- <weakness 1 with inline source>
- <weakness 2 with inline source> *(optional)*

**Best for:** <one line>
```

## Image strategy

### Short mode

- After research, attempt `/browse` to screenshot the primary evidence URL
  (CVE detail page, GitHub Security Advisory, vendor bulletin).
- Save to `/Users/balasriharsha/BalaSriharsha/pencheff/blog-content/images/<slug>-hero.png`.
- Reference once near the top of the post:
  `![<descriptive caption>](images/<slug>-hero.png)` plus a source caption line.
- If `/browse` fails or is unavailable, emit the same markdown reference but do
  NOT include `hero_image` in the frontmatter; the save report flags this so the
  user can drop in art later.

### Comparison mode

- For each tool, attempt to fetch a logo in this order (stop at first success):
  1. Common logo paths on the official site: `/logo.svg`, `/static/logo.svg`,
     `/logo.png`, `/static/logo.png`, `/assets/logo.png`.
  2. `<meta property="og:image">` from the official site's homepage (often a
     branded banner; acceptable when no dedicated logo is found).
  3. `/favicon.ico` or `/favicon.png` (last resort; small, but always available
     for any live site).
- Save each to `images/<slug>-logo-<vendor-slug>.png` (or `.svg` if SVG).
- If all three tiers fail, fall back to a plain text header for that tool — no
  broken image references in the published post.

### Deep mode

- Behavior unchanged from the current skill. Images are optional.

### Save report

The Phase 5 report includes an explicit image inventory:

```
Images captured: <I>/<expected>  (placeholders: <P>)
```

so the user knows what to fill in manually after the skill runs.

## Per-mode body structure

### Short mode (800–1,200 words)

1. **Hook** (~75 words) — one concrete fact: named CVE / named victim / specific
   stat. No generalizations.
2. **What happened, in plain language** (~150 words) — plain-English summary that
   precedes any jargon. Define every acronym on first use inline.
3. **Technical detail** (~250 words) — includes the CVE metadata table and one
   fenced code block (vulnerable pattern or payload).
4. **What to do today** (~200 words) — patch, workaround, detection. Bullets, not
   prose.
5. **How Pencheff catches it** (~100 words) — which scan profile, two sentences,
   one link to signup.
6. **Sources** (~50 words) — bulleted list of every URL actually fetched.

### Comparison mode (1,200–1,800 words; scales with N)

1. **Hook + disclosure** (~100 words) — one-line statement of who we are, one-line
   statement of how we ranked. Disclosure callout box.
2. **How we scored** (~150 words) — the rubric table with weights summing to 100.
3. **The list** (N × ~100 words) — per-tool entries using the template above.
4. **When to use which** (~150 words) — decision guidance. "Pick #1 if X. Pick
   Pencheff if Y."
5. **Sources** — inline per tool plus a closing consolidated list.

### Deep mode

Unchanged from the current skill (8 sections: TOC, Introduction, Background,
Technical analysis, Attack walkthrough, Reproduction steps, Defense and
remediation, Detection with Pencheff, Summary).

## Writing quality additions ("truthful, intuitive, easy to understand")

Append to the existing writing-quality block:

- **Define every acronym on first use, inline.** Not in a glossary at the end.
- **One concept per sentence.** No stacking three clauses.
- **Every external claim hyperlinked** to the source the research agent actually
  fetched. No invented citations. No guessed CVE IDs, CVSS scores, or version
  numbers.
- **Numbers and named entities in the opening sentence.** "47 million Maven
  downloads," not "many downloads."
- **One callout box per post maximum.** No callout-stacking.
- **Plain-English summary precedes every technical section.** A reader can stop
  after the summary and still know what happened.

Existing rules retained: no marketing fluff; no em dashes in prose; specific not
generic; code blocks have language tags; tables carry real data only.

## Phase 5 — Save and verify (replaces current Phase 5)

```
1. Write file to /Users/balasriharsha/BalaSriharsha/pencheff/blog-content/<SLUG>.md
2. Compute body word count, excluding frontmatter (awk between '---' fences).
3. Count fenced code blocks (``` lines / 2), table rows (lines starting with |),
   image references (![).
4. Check against the contract for the detected mode (see contracts table).
5. If under min words → expand the weakest section, re-save, re-verify.
6. If over hard ceiling → tighten the longest section, re-save, re-verify.
7. If under min images for short mode AND /browse never ran → run image phase.
8. Bounded retry: at most two re-saves. After two failures, stop and report which
   section is blocked rather than looping forever.
9. Emit final save report:

   Blog saved: blog-content/<SLUG>.md
   Mode: <mode> | Words: <W> (target <T>) | Code blocks: <C> | Tables: <Tb>
   Images captured: <I>/<expected>  (placeholders: <P>)
   Live at: http://localhost:3002/<SLUG>
```

## Out of scope

- No changes to `apps/blog/` rendering. The renderer already supports everything
  the new modes need.
- No new asset generation (AI image generation, mermaid rendering). Only `/browse`
  screenshots and WebFetch logo downloads.
- No backend changes to support filtering by `mode` or display of `read_time`.
  Those frontmatter fields are written for forward compatibility only.
- No bulk regeneration of existing blog posts. Existing posts keep their current
  shape.

## Open questions and risks

- **Logo fetch reliability.** Favicons exist but are often 16×16; press-kit logos
  vary in availability. WebFetch may return HTML rather than image bytes for some
  sites. The fallback chain (favicon → og:image → text header) is the safety net,
  but the save report's image inventory is the user-visible signal.
- **Rubric drift.** With 5 criteria chosen from a 7-item bank, two consecutive
  comparison posts on similar topics could pick slightly different rubrics. This
  is acceptable for v1; if it becomes a problem, freeze the rubric per category.
- **Deep-mode discovery.** Topic discovery (current Phase 1) runs only when
  `ARGUMENTS` is empty, which now defaults to `short`. To produce a discovered
  deep-dive topic, the user types `deep:` with no topic — the skill then runs
  discovery and writes deep-mode. This is documented in Phase 0 of the new skill.

## Implementation file map

- Edit only: `/Users/balasriharsha/.claude/skills/pencheff-blog-creation/SKILL.md`.
- No other files in the skill directory. No new files in the pencheff repo
  (except this spec). The blog renderer is untouched.

## Acceptance criteria

The redesigned skill is accepted when, on three sample invocations, it:

1. `<empty ARGUMENTS>` → produces a `short`-mode post, 800–1,200 words, with one
   hero image (real or placeholder), at least one table, at least two code
   blocks.
2. `deep: <topic>` → produces an unchanged-shape deep-dive post matching the
   existing 8-section structure and ≥2,000 words.
3. `top 10 pentesting tools` → produces a `comparison`-mode post with Pencheff at
   rank 3 by default, a rubric table summing to 100, ≥1 weakness per tool
   including Pencheff, the disclosure callout, and a logo for each tool (or a
   text fallback).

All three save reports must show counts that satisfy the contract for the
detected mode.
