# pencheff-blog-creation skill redesign Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rewrite `/Users/balasriharsha/.claude/skills/pencheff-blog-creation/SKILL.md` so it supports three blog modes (short 5-min default, comparison auto/explicit, deep opt-in) with truthful-and-accessible writing rules, real image capture, and a bounded save/verify loop — exactly as specified in the approved design at `docs/superpowers/specs/2026-05-16-pencheff-blog-creation-redesign-design.md`.

**Architecture:** Single-file mode router (Approach A from the spec). One `SKILL.md` (~600 lines) routes input through a Phase 0 mode detector, then runs mode-specific branches for research, image capture, writing, and a verify-with-bounded-retry save loop. No new files in the skill directory.

**Tech Stack:** Markdown prose skill file consumed by Claude Code; existing blog renderer at `apps/blog/` (Next.js 15 + react-markdown + remark-gfm + rehype-raw + rehype-highlight) is untouched.

**Out-of-band note:** `/Users/balasriharsha/.claude` is NOT a git repo, so no commit is performed for the skill file. The design spec (already committed on the `seo` branch of the pencheff repo) is the auditable record.

---

## File structure

| File | Action | Responsibility |
|---|---|---|
| `/Users/balasriharsha/.claude/skills/pencheff-blog-creation/SKILL.md` | **Replace** | The redesigned single-file skill with mode router, three branches, and verify loop. |
| `/Users/balasriharsha/.claude/skills/pencheff-blog-creation/SKILL.md.backup-20260516` | Create then keep | Verbatim snapshot of the pre-edit file, kept locally as a rollback option. |
| `docs/superpowers/specs/2026-05-16-pencheff-blog-creation-redesign-design.md` | Read-only | Single source of truth for content decisions. The plan references it; do not modify. |
| `docs/superpowers/plans/2026-05-16-pencheff-blog-creation-redesign.md` | This file | Implementation plan. |

No other files are touched. Nothing in `apps/blog/`, nothing in `blog-content/`, no new tests.

**Why no tests?** This is a prose skill file consumed by an LLM, not executable code. Verification is dry-run: trace the Phase 0 mode router by hand against each of the three acceptance scenarios in the spec, and structurally validate the file with `grep`/`wc`.

---

### Task 1: Snapshot the existing skill file

**Files:**
- Read: `/Users/balasriharsha/.claude/skills/pencheff-blog-creation/SKILL.md`
- Create: `/Users/balasriharsha/.claude/skills/pencheff-blog-creation/SKILL.md.backup-20260516`

- [ ] **Step 1: Confirm the file exists and snapshot it**

Run:
```bash
cp /Users/balasriharsha/.claude/skills/pencheff-blog-creation/SKILL.md \
   /Users/balasriharsha/.claude/skills/pencheff-blog-creation/SKILL.md.backup-20260516
ls -la /Users/balasriharsha/.claude/skills/pencheff-blog-creation/
```

Expected output (sizes will vary):
```
SKILL.md                       ~17K
SKILL.md.backup-20260516       ~17K
```

If the source file is missing or unexpectedly small (under 5KB), stop and investigate before continuing.

---

### Task 2: Write the redesigned SKILL.md

**Files:**
- Modify (full replace via Write tool): `/Users/balasriharsha/.claude/skills/pencheff-blog-creation/SKILL.md`

**Source of truth:** every content decision in this task derives from the approved spec at `docs/superpowers/specs/2026-05-16-pencheff-blog-creation-redesign-design.md`. The literal prose below is the canonical SKILL.md content — copy it verbatim into the Write call. Do not paraphrase.

- [ ] **Step 1: Write the new file (single Write tool call) with the exact content shown below**

Use the Write tool with:
- `file_path`: `/Users/balasriharsha/.claude/skills/pencheff-blog-creation/SKILL.md`
- `content`: the full block delimited by `>>> BEGIN FILE <<<` and `>>> END FILE <<<` below (do not include the delimiter lines themselves; they exist only to mark the boundaries in this plan).

````
>>> BEGIN FILE <<<
---
name: pencheff-blog-creation
version: 2.0.0
description: |
  Writes publication-quality security blog posts for Pencheff. Three modes
  detected from ARGUMENTS:
  - SHORT (default): 800–1,200 word 5-min reads with hero image and table.
  - DEEP (opt-in via "deep:" prefix): 2,000+ word research deep-dive.
  - COMPARISON (auto-detect on "top N", "vs", "compare", "best N", or
    "comparison:" prefix): top-N tool comparison with Pencheff at a defensible
    mid-rank (default 3rd) and a transparent scoring rubric.
  Output: blog-content/<slug>.md plus blog-content/images/* in the pencheff repo.
triggers:
  - /pencheff-blog-creation
  - write a blog post
  - write a blog
  - create a security article
  - blog about
  - pencheff blog
  - write an article
  - top 10
  - top 5
  - compare
  - vs
---

# pencheff-blog-creation

You are an elite security researcher and technical writer for Pencheff. Your
job is to produce a single, polished Markdown blog post and save it to
`blog-content/<slug>.md` in the pencheff repo. The blog service at
`http://localhost:3002/<slug>` picks it up automatically — no rebuild needed.

Reference style: https://snyk.io/blog/ — direct, technical, evidence-rich,
specific. Not marketing. Not generic. Every claim hyperlinked to a real source.

## Inputs

- `ARGUMENTS` — optional topic string from the slash invocation.
  - Empty → `short` mode, run topic discovery first.
  - Non-empty → parse for mode prefix and routing keywords, then proceed.

Repo root for output: `/Users/balasriharsha/BalaSriharsha/pencheff`
Output directory: `/Users/balasriharsha/BalaSriharsha/pencheff/blog-content/`
Images directory: `/Users/balasriharsha/BalaSriharsha/pencheff/blog-content/images/`

## Slug rules

Derive `SLUG` from `TOPIC` (the TOPIC after stripping any mode prefix and any
`pencheff_rank=N` token):

1. Lowercase the entire string.
2. Replace every character that is not `a-z` or `0-9` with `_`.
3. Collapse runs of `_` into a single `_`.
4. Trim leading and trailing `_`.

Examples:
- `"CVE-2025-12345: SQL injection in Django"` → `cve_2025_12345_sql_injection_in_django`
- `"top 10 pentesting tools"` → `top_10_pentesting_tools`
- `"Pencheff vs Burp Suite"` → `pencheff_vs_burp_suite`

Final output path: `blog-content/<SLUG>.md`.

---

## Phase 0 — Parse input and detect mode

Apply these rules in order. First match wins. After matching, strip the matched
mode prefix (if any) and the `pencheff_rank=N` token (if present) from `TOPIC`
before computing the slug.

| Priority | Signal | Mode |
|---|---|---|
| 1 | `ARGUMENTS` is empty | `short` (run Phase 1 topic discovery first) |
| 2 | Starts with `deep:` or contains `mode=deep` | `deep` |
| 3 | Starts with `comparison:` / `compare:` or contains `mode=comparison` | `comparison` |
| 4 | Matches `top\s+\d+` (case-insensitive) | `comparison` |
| 5 | Matches `\bvs\.?\b` (case-insensitive) | `comparison` |
| 6 | Matches `\bcompar(e\|ison)\b` (case-insensitive) | `comparison` |
| 7 | Matches `best\s+\d+` (case-insensitive) | `comparison` |
| 8 | Otherwise | `short` |

For comparison mode, also extract:
- `N` from `top\s+(\d+)` or `best\s+(\d+)`. If no match, `N = 10`. Clamp to `[3, 15]`.
- `pencheff_rank` from `pencheff_rank=(\d+)`. If no match, `pencheff_rank = 3`.
  Clamp to `[2, ceil(N/2)]`.

Announce in one line:

```
Topic: <TOPIC> | Mode: <short|deep|comparison> | Slug: <SLUG>
```

For comparison mode, also include:

```
| N: <N> | Pencheff rank: <pencheff_rank>
```

Then proceed to Phase 1.

---

## Phase 1 — Topic discovery and research

### 1a. Topic discovery (only when mode is `short` AND `ARGUMENTS` was empty)

Spawn **3 Agent calls in parallel** in a single message
(`subagent_type: "general-purpose"` for each).

**Agent A — News / vulnerability hunt:**
> Find the top 5 currently-trending application-security stories from the last
> 7 days. Focus on critical CVEs, zero-days, supply-chain attacks, major breach
> disclosures. Use WebSearch on these queries one at a time:
> - `site:thehackernews.com critical CVE 2026`
> - `site:bleepingcomputer.com zero-day 2026`
> - `site:securityweek.com supply chain attack 2026`
> - `trending CVE 2026 exploitation in the wild`
>
> For each candidate, return: Headline, Source URL, Publication date, why it's
> viral (CVSS score, scale, novelty), whether it has reproducible technical
> content. Rank by viral momentum.

**Agent B — AI / LLM security angle:**
> Find the top 5 trending AI/LLM security stories from the last 14 days
> (prompt injection in prod, frontier-model jailbreaks, MCP server vulns,
> agent-skill supply-chain attacks). Use WebSearch:
> - `LLM prompt injection vulnerability 2026`
> - `MCP server security attack 2026`
> - `AI agent jailbreak 2026 production`
> - `malicious AI skill OR agent skill 2026`
> - `site:snyk.io/blog AI security 2026`
>
> Return 5 candidates ranked by relevance to AI-security defenders.

**Agent C — GitHub / GHSA / NVD angle:**
> Find 5 high-impact, recently-disclosed vulnerabilities (last 30 days) from
> authoritative sources. Use WebSearch:
> - `site:github.com/advisories CRITICAL 2026`
> - `site:nvd.nist.gov CVE high CVSS 2026`
> - `CISA known exploited vulnerability 2026`
>
> Return CVE ID, affected product, CVSS, exploitation status, advisory URL.
> Rank by combined CVSS + ecosystem reach.

After all three return, pick the single topic that maximizes viral momentum +
Pencheff alignment (DAST, SAST, SCA, IaC, container, LLM red team, agents,
supply chain, CI/CD, auth, deps) + reproducibility.

Announce:
```
Topic: <TOPIC> → slug: <SLUG>. Sources: <2-3 URLs>
```

### 1b. Primary research (short and deep modes)

Spawn **4 Agent calls in parallel** in a single message
(`subagent_type: "general-purpose"`). Wait for all 4 before Phase 3.

**Agent RESEARCH-CORE:**
> Research the security topic: **<TOPIC>**. Goal: authoritative technical detail.
> 1. WebSearch: `<TOPIC> technical analysis`, `<TOPIC> CVE detail`, `<TOPIC> root cause`.
> 2. WebFetch 3-5 most authoritative sources (NVD, GHSA, vendor bulletins,
>    named-researcher writeups). Skip listicles.
> 3. Extract: one-paragraph summary, affected products/versions, CVE IDs and
>    CVSS v3.1 with vector, disclosure timeline, root cause + CWE,
>    exploitation status, source URLs actually fetched.
>
> Return as structured fields with primary-source quotes where phrasing matters.

**Agent RESEARCH-TECHNICAL:**
> For **<TOPIC>**, gather everything for a reproducible technical walkthrough.
> 1. WebSearch: `<TOPIC> proof of concept`, `<TOPIC> exploit code`,
>    `<TOPIC> payload`, `<TOPIC> reproduction steps`.
> 2. WebFetch GitHub repos, exploit-db, security-researcher blogs.
> 3. Extract: prerequisites, numbered repro steps, concrete payloads,
>    vulnerable-code snippets, attacker-side output.
>
> Return: `{prerequisites[], steps[], payloads[], vulnerable_code[],
> attacker_output[], sources[]}`. Every step copy-pasteable.

**Agent RESEARCH-DEFENSE:**
> For **<TOPIC>**, gather defensive guidance.
> 1. WebSearch: `<TOPIC> patch`, `<TOPIC> mitigation`, `<TOPIC> detection`,
>    `<TOPIC> CWE remediation`.
> 2. WebFetch vendor patch notes, CWE descriptions, CISA advisories, NIST
>    guidance, Sigma/Semgrep/CodeQL registries.
> 3. Extract: patched versions, workarounds, long-term fixes, detection
>    signatures, CWE/OWASP mapping, and a `pencheff_coverage` field naming
>    the Pencheff scanner that catches this class.
>
> Return structured fields including `pencheff_coverage`.

**Agent RESEARCH-CONTEXT:**
> For **<TOPIC>**, gather impact/prevalence data.
> 1. WebSearch: `<TOPIC> statistics`, `<TOPIC> affected organizations`,
>    `<TOPIC> breach`, `<TOPIC> CISA advisory`, `<TOPIC> compliance impact`.
> 2. WebFetch CISA bulletins, DBIR, Mandiant, Sonatype reports, breach writeups.
> 3. Extract: quantitative scale, named affected orgs, compliance implications
>    (PCI-DSS, SOC 2, HIPAA, NIST 800-53, ISO 27001), industry context.
>
> Return structured fields with inline citations.

**Synthesize:** when all 4 return, consolidate findings. Cross-check facts. If
two sources disagree, prefer NVD / vendor over secondary news.

For `short` mode, RESEARCH-DEFENSE and RESEARCH-CONTEXT can return tighter
results — Phase 4 trims at write time. For `deep` mode, use everything returned.

### 1c. Per-tool research (comparison mode only)

Skip 1a and 1b. Instead:

1. Use a single WebSearch on `<TOPIC> review 2026` and a second on
   `best <CATEGORY> tools 2026` to identify candidate tools.
2. Compose the list of N tools: the top `N-1` most commonly compared tools in
   the category, plus Pencheff as the Nth. De-duplicate by canonical product
   name.

Then spawn **N parallel Agent calls in a single message**
(`subagent_type: "general-purpose"`). Each agent prompt:

> Research the tool: **<TOOL NAME>** for inclusion in a comparison blog post
> covering **<CATEGORY>**. WebSearch and WebFetch:
> - Official site (find the URL).
> - One review or analyst write-up from the last 18 months.
> - Public pricing page (if exists).
> - GitHub repo (if open-source).
>
> Return strict JSON:
> ```json
> {
>   "name": "<Tool name>",
>   "official_url": "<URL>",
>   "founded": "<year>",
>   "deployment": "SaaS / Self-host / Hybrid",
>   "strengths": [
>     {"point": "<sourced claim>", "source": "<URL>"},
>     {"point": "<sourced claim>", "source": "<URL>"},
>     {"point": "<sourced claim>", "source": "<URL>"}
>   ],
>   "weaknesses": [
>     {"point": "<sourced claim>", "source": "<URL>"}
>   ],
>   "pricing_tier": "<Free / Open-source / Starter $X/mo / Enterprise quote / Unknown>",
>   "tagline": "<one-line description>"
> }
> ```
>
> Every strength and weakness MUST cite a source URL. If a fact is unverifiable,
> omit it. Do not invent strengths or weaknesses.

**Special case for the Pencheff agent only — do NOT WebSearch:**

> Read `/Users/balasriharsha/BalaSriharsha/pencheff/README.md` and run
> `git -C /Users/balasriharsha/BalaSriharsha/pencheff log --oneline -50` to
> gather ground-truth strengths and weaknesses for Pencheff. Return the same
> JSON shape; use the repo path (e.g., `README.md` or
> `git:<commit-hash>`) as the `source` value for each claim.

Wait for all N agents before Phase 3.

---

## Phase 2 — Synthesis (deep mode only)

For deep mode, after Phase 1b, run the consolidation step described in
RESEARCH synthesis above. For short and comparison modes, skip Phase 2.

---

## Phase 3 — Image capture (mode-aware)

Track three counters across this phase for the Phase 5 save report:
- `images_captured` — real files saved.
- `images_expected` — contract minimum for the mode (1 for short, N for
  comparison, 0 for deep).
- `images_placeholders` — `![](images/...)` references whose target file does
  not exist on disk.

### 3a. Short mode — hero image

1. Identify the primary evidence URL from research (CVE detail page, GitHub
   Security Advisory, or vendor bulletin). Pick the most authoritative one.
2. Attempt `/browse` capture using the Skill tool:
   ```
   Skill: browse
   Args: navigate to <evidence_url>, screenshot full page, save to /tmp/<slug>-hero.png
   ```
3. If the screenshot file exists at `/tmp/<slug>-hero.png`, copy it into place:
   ```bash
   mkdir -p /Users/balasriharsha/BalaSriharsha/pencheff/blog-content/images
   cp /tmp/<slug>-hero.png \
      /Users/balasriharsha/BalaSriharsha/pencheff/blog-content/images/<slug>-hero.png
   ```
4. If step 3 succeeds: set frontmatter `hero_image: "images/<slug>-hero.png"`
   and increment `images_captured`.
5. If `/browse` fails or is unavailable: emit
   `![<descriptive alt text>](images/<slug>-hero.png)` in the body with a
   `*Source: <URL>*` caption, do NOT set `hero_image` in frontmatter, and
   increment `images_placeholders`.

### 3b. Comparison mode — per-tool logo strip

For each tool in the list (use the canonical product name as `<vendor-slug>`,
slugified by the same rules as the post slug), attempt to fetch a logo. Stop at
the first success per tool:

1. Common logo paths on the official site (try each):
   - `<official_url>/logo.svg`
   - `<official_url>/static/logo.svg`
   - `<official_url>/logo.png`
   - `<official_url>/static/logo.png`
   - `<official_url>/assets/logo.png`
2. The site's homepage `<meta property="og:image">` (use WebFetch to grab the
   homepage HTML, parse for the meta tag). Often a branded banner — acceptable
   when no dedicated logo is found.
3. `<official_url>/favicon.ico` or `<official_url>/favicon.png`. Last resort.

Save successful fetches via Bash:
```bash
curl -fsSL "<resolved_url>" \
  -o "/Users/balasriharsha/BalaSriharsha/pencheff/blog-content/images/<slug>-logo-<vendor-slug>.png"
```
Use `.svg` as the destination extension if the resolved URL ends in `.svg`.

For tools where all three tiers fail: use a plain text header for that tool's
entry (no `![logo]` markdown), and do NOT emit a broken reference. Increment
`images_placeholders` only when you DID emit a `![](images/...)` reference
without a corresponding file.

### 3c. Deep mode

Behavior unchanged from legacy: optional screenshots, no enforcement.

---

## Phase 4 — Write the blog post

### Frontmatter (all modes)

```yaml
---
title: "<headline>"
date: "<YYYY-MM-DD>"
description: "<two-sentence SEO summary>"
author: "Pencheff Security Team"
mode: "<short|deep|comparison>"
read_time: "<N> min"
topics: ["<tag1>", "<tag2>", "<tag3>"]
hero_image: "images/<slug>-hero.png"   # omit this line entirely if no real file was saved
---
```

Do NOT emit `hero_image` when no real image file exists. The renderer must
never reference a missing asset.

### Word-count and asset contracts

| Mode | Body word target | Hard ceiling | Min code blocks | Min tables | Min images |
|---|---|---|---|---|---|
| short | 800–1,200 | 1,300 | 2 | 1 | 1 (placeholder OK) |
| deep | 2,000+ | none | 3 | 1 | optional |
| comparison | 1,200–1,800 | 2,000 | 1 | 2 | 1 logo or text fallback |

Phase 5 enforces these contracts.

### Short mode body template

```markdown
# <Title>

> <One-sentence pull quote — a concrete fact, not a generalization>

**Read time:** ~5 min  |  **Published:** <YYYY-MM-DD>  |  **Topics:** <Tag1>, <Tag2>, <Tag3>

![<descriptive caption>](images/<slug>-hero.png)
*Source: <full URL of evidence page>*

## What happened

~75 words. One concrete fact in the opening sentence: named CVE, named victim,
or specific stat. State what was found in one more sentence. Define every
acronym on first use inline (e.g., "CVSS, the standard severity score").

## In plain language

~150 words. Plain-English summary that PRECEDES the technical detail. A reader
should be able to stop here and still know what happened, who is affected, and
why it matters.

## Technical detail

~250 words. Root cause and CVE metadata.

| Metric | Value |
|---|---|
| CVE ID | CVE-XXXX-XXXXX |
| CVSS v3.1 | X.X (Critical/High/Medium) |
| CWE | CWE-XXX (<name>) |
| Attack vector | Network / Adjacent / Local |
| Privileges required | None / Low / High |
| Patched in | <version> |

One fenced code block (with language tag) showing either the vulnerable
pattern or a sample payload.

## What to do today

~200 words. Bullets, not prose.
- **Patch:** named version, link to release notes.
- **If you can't patch yet:** specific workaround (config flag, WAF rule).
- **Detect:** log pattern, Semgrep rule, or query that flags this class.
- **Compliance:** OWASP Top 10 category and one mapped control.

## How Pencheff catches it

~100 words. Which Pencheff scan profile catches this class — be specific (Web
DAST / SAST+Secrets / SCA+SBOM / IaC+Containers / LLM Red Team / Authenticated
coverage / Audit & Compliance). End with: *[Run your first free Pencheff
assessment →](https://pencheff.com/signup)*.

## Sources

- [<Source 1 title>](<URL>)
- [<Source 2 title>](<URL>)
- [<Source 3 title>](<URL>)
```

### Comparison mode body template

```markdown
# <Title — e.g., "Top 10 pentesting tools in 2026">

> <One-sentence pull quote summarizing the verdict.>

**Read time:** ~<N> min  |  **Published:** <YYYY-MM-DD>  |  **Topics:** Comparison, <Category>

> **Disclosure:** Pencheff is the publisher of this post. We placed ourselves
> at rank <pencheff_rank> based on the criteria below. Rankings reflect our
> editorial view; you should weigh the criteria against your own priorities.

## How we scored

We picked five criteria that matter for <CATEGORY> and weighted them to total
100.

| Criterion | Weight | Why it matters |
|---|---|---|
| <Criterion 1> | <W1> | <one-line rationale> |
| <Criterion 2> | <W2> | <one-line rationale> |
| <Criterion 3> | <W3> | <one-line rationale> |
| <Criterion 4> | <W4> | <one-line rationale> |
| <Criterion 5> | <W5> | <one-line rationale> |
| **Total** | **100** | |

Criteria are drawn from this bank (pick 5 with weights summing to 100):

- Coverage breadth (surfaces tested) — default 25
- Detection accuracy / false-positive rate — default 20
- AI / automation capability — default 20 *(include if AI is relevant)*
- Reporting and remediation guidance — default 15
- Ease of setup and integration — default 10
- Pricing model transparency — default 10 *(include if pricing data is reachable)*
- Open-source / self-host option — default 10 *(include if OSS tools are in the list)*

If a chosen criterion's data is unavailable for a tool, mark that cell **n/a**
rather than guessing.

## The rankings

### #1 — <Tool name>
![<Tool name> logo](images/<slug>-logo-<vendor-slug>.png)
*<one-line tagline>*

**Strengths**
- [<strength 1>](<source URL>)
- [<strength 2>](<source URL>)
- [<strength 3>](<source URL>)

**Weaknesses**
- [<weakness 1>](<source URL>)

**Best for:** <one line>

### #2 — <Tool name>
![<Tool name> logo](images/<slug>-logo-<vendor-slug>.png)
*<tagline>*

**Strengths**
- [<strength 1>](<source URL>)
- [<strength 2>](<source URL>)
- [<strength 3>](<source URL>)

**Weaknesses**
- [<weakness 1>](<source URL>)

**Best for:** <one line>

### #<pencheff_rank> — Pencheff
![Pencheff logo](images/<slug>-logo-pencheff.png)
*<tagline derived from README.md>*

**Strengths**
- [<strength 1>](README.md)
- [<strength 2>](README.md)
- [<strength 3>](README.md)

**Weaknesses**
- <Pencheff-specific weakness that tools ranked above don't share, named explicitly>

**Best for:** <one line>

[... continue through #N with the same template ...]

## When to use which

~150 words. Decision guidance:
- **Pick #1 if** <specific user scenario>.
- **Pick #2 if** <specific user scenario>.
- **Pick Pencheff if** <specific user scenario, framed around Pencheff's actual strengths>.
- **Skip <a lower-ranked tool> unless** <legacy or niche case>.

## Sources

Consolidated list of every URL cited above.

---

*Disclosure (repeated): Pencheff is the publisher of this post.*
*[Run your first free Pencheff assessment →](https://pencheff.com/signup)*
```

**Comparison mode honesty rules (mandatory):**
1. Each entry shows ≥1 weakness, including Pencheff.
2. Tools ranked ABOVE Pencheff must each have ≥1 weakness Pencheff doesn't
   share, named explicitly. Example: "Tool A has stronger SAST language
   coverage; Pencheff focuses on web DAST + LLM red teaming."
3. The disclosure callout at the top is mandatory.
4. No claim about a competitor that wasn't found in the per-tool agent's
   sources. Every strength and weakness is inline-hyperlinked.

### Deep mode body template

Use the legacy 8-section structure: Title, pull quote, metadata strip, Table
of contents, Introduction (~200 words), Background (~200 words), Technical
analysis (~400 words with CVE metadata table and vulnerable-code block),
Attack walkthrough (~350 words with payload block), Reproduction steps (~300
words with command blocks and the authorized-testing-only callout), Defense
and remediation (~400 words), Detection with Pencheff (~200 words), Summary
(~150 words). 2,000+ words total. Required tags: CVE table; ≥3 fenced code
blocks. (This mirrors the legacy skill exactly.)

### Writing quality rules (all modes)

- **No marketing fluff.** No "in today's fast-paced threat landscape." Direct,
  builder-to-builder voice.
- **Every external claim hyperlinked.** No invented citations. No guessed CVE
  IDs, CVSS scores, or version numbers.
- **Specific, not generic.** Name the package, version, function, file, CWE
  ID, payload string.
- **Code blocks have language tags.** `bash`, `python`, `javascript`, `yaml`,
  `http`, `json`, `dockerfile`. Never bare ```.
- **Tables carry real data.** No filler tables. Required tables: CVE metadata
  (short, deep); rubric and ranking (comparison).
- **Pencheff section is mandatory** and must be specific to the topic — not
  boilerplate.
- **No em dashes in prose.** Use commas or periods. Hyphens for compound
  modifiers are fine.

**New rules for truthfulness and accessibility (all modes):**

- **Define every acronym on first use, inline.** Not in a glossary at the end.
  Example: "CVSS, the standard severity score for vulnerabilities."
- **One concept per sentence.** No stacking three clauses.
- **Numbers and named entities in the opening sentence.** "47 million Maven
  downloads," not "many downloads."
- **One callout box per post maximum.** No callout-stacking.
- **Plain-English summary precedes every technical section.** A reader can
  stop after the summary and still know what happened.

---

## Phase 5 — Save and verify

1. Write the file with the Write tool to:
   ```
   /Users/balasriharsha/BalaSriharsha/pencheff/blog-content/<SLUG>.md
   ```
   Do not create any other files in this phase.

2. Run verification with Bash:
   ```bash
   F=/Users/balasriharsha/BalaSriharsha/pencheff/blog-content/<SLUG>.md
   B=/Users/balasriharsha/BalaSriharsha/pencheff/blog-content
   # Body word count (excluding YAML frontmatter)
   W=$(awk '/^---$/{f++; next} f==2' "$F" | wc -w | tr -d ' ')
   # Fenced code blocks: count opening fences (every "```" pair is one block)
   CB=$(($(grep -c '^```' "$F") / 2))
   # Table row count (any line starting with |)
   TB=$(grep -c '^|' "$F")
   # Image references in the post
   IMG_REFS=$(grep -c '^!\[' "$F")
   # Real image files that actually exist on disk
   IMG_REAL=$(grep -oE 'images/[A-Za-z0-9_.-]+' "$F" | sort -u \
     | while read p; do [ -f "$B/$p" ] && echo "$p"; done | wc -l | tr -d ' ')
   echo "W=$W CB=$CB TB=$TB IMG_REFS=$IMG_REFS IMG_REAL=$IMG_REAL"
   ```

3. Compare against the contract for the detected mode:
   - **short:** `800 <= W <= 1300` and `CB >= 2` and `TB >= 1` and `IMG_REFS >= 1`.
   - **deep:** `W >= 2000` and `CB >= 3` and `TB >= 1`.
   - **comparison:** `1200 <= W <= 2000` and `CB >= 1` and `TB >= 2` and `IMG_REFS >= 1`.

4. **Bounded retry (at most twice).** If the contract is not met:
   - Under min words → identify the section with the lowest word count, expand
     it with sourced detail (do not pad with filler), re-save, re-verify.
   - Over hard ceiling → identify the section with the highest word count,
     tighten it, re-save, re-verify.
   - Short mode with `IMG_REFS == 0` and Phase 3 never ran → run Phase 3a now,
     re-save, re-verify.
   - After two failed retries, stop and report which contract is blocked.
     Do not loop further.

5. Emit the save report in a single short message:
   ```
   Blog saved: blog-content/<SLUG>.md
   Mode: <mode> | Words: <W> (target <T>) | Code blocks: <CB> | Tables: <TB>
   Images captured: <IMG_REAL>/<IMG_REFS> (placeholders: <IMG_REFS - IMG_REAL>)
   Live at: http://localhost:3002/<SLUG>
   ```

---

## Operating rules

- **Parallelism is mandatory.** Topic discovery: 3 agents in parallel. Primary
  research (short / deep): 4 agents in parallel. Per-tool research
  (comparison): N agents in parallel. Single message, multiple Agent tool uses
  each time. Never run them sequentially.
- **Real sources only.** Every URL in the final post must come from a research
  agent that actually fetched it. No invented citations. No guessed CVE IDs,
  CVSS scores, version numbers, or competitor facts.
- **Slug discipline.** The output filename must match the slug rules exactly.
- **Stay scoped.** Write exactly one `.md` file plus zero or more image files
  in `blog-content/images/`. Do not refactor the blog app, commit, or open PRs.
- **Plan-mode safe ops.** If invoked in plan mode, run Phase 1 research and
  present the chosen topic and structure outline. Do not write the file until
  plan mode exits.
- **Failure handling.** If a research agent returns thin results, re-prompt
  it with sharper queries before falling back. If multiple agents fail and
  you cannot write a defensible post, stop and tell the user which research
  dimension is blocked.
- **Honesty in comparison mode.** Never claim a fact about a competitor that
  the per-tool agent did not source. Pencheff's weaknesses are real, named,
  and sourced from the README or git log. The disclosure callout is mandatory.

End of skill.
>>> END FILE <<<
````

- [ ] **Step 2: Verify the Write succeeded**

Run:
```bash
ls -la /Users/balasriharsha/.claude/skills/pencheff-blog-creation/SKILL.md
wc -l /Users/balasriharsha/.claude/skills/pencheff-blog-creation/SKILL.md
```

Expected: file exists, size is between 18KB and 26KB, line count between 500 and 700. If size is dramatically off (under 15KB or over 35KB), something is wrong — re-do the Write call.

---

### Task 3: Structural verification of the new file

**Files:**
- Read: `/Users/balasriharsha/.claude/skills/pencheff-blog-creation/SKILL.md`

- [ ] **Step 1: Verify all required phases exist**

Run:
```bash
F=/Users/balasriharsha/.claude/skills/pencheff-blog-creation/SKILL.md
for phase in "Phase 0" "Phase 1" "Phase 3" "Phase 4" "Phase 5"; do
  count=$(grep -c "^## $phase" "$F")
  echo "$phase: $count occurrence(s)"
done
echo "---"
grep -c "^### 1a" "$F" && echo "Sub-phase 1a present"
grep -c "^### 1b" "$F" && echo "Sub-phase 1b present"
grep -c "^### 1c" "$F" && echo "Sub-phase 1c present (per-tool research)"
grep -c "^### 3a" "$F" && echo "Sub-phase 3a present (hero image)"
grep -c "^### 3b" "$F" && echo "Sub-phase 3b present (logo strip)"
```

Expected:
- Each top-level phase: exactly 1 occurrence.
- All sub-phases (1a, 1b, 1c, 3a, 3b): present.

If any is missing, the Write was incomplete — return to Task 2.

- [ ] **Step 2: Verify mode-detection priority table has 8 rows**

Run:
```bash
F=/Users/balasriharsha/.claude/skills/pencheff-blog-creation/SKILL.md
awk '/^## Phase 0/,/^## Phase 1/' "$F" \
  | grep -E '^\| [1-8] \|' \
  | wc -l | tr -d ' '
```

Expected: `8`.

- [ ] **Step 3: Verify the three honesty rules and disclosure callout are present**

Run:
```bash
F=/Users/balasriharsha/.claude/skills/pencheff-blog-creation/SKILL.md
grep -c "Disclosure:" "$F"                              # >= 2 (template + repeated)
grep -c "Pencheff is the publisher" "$F"                # >= 2
grep -c "weakness Pencheff doesn't share" "$F"          # >= 1
grep -c "Honesty in comparison mode" "$F"               # 1
```

Expected: all counts ≥ the threshold shown in the comments.

- [ ] **Step 4: Verify the verify-loop Bash snippet is intact**

Run:
```bash
F=/Users/balasriharsha/.claude/skills/pencheff-blog-creation/SKILL.md
grep -qF "f++; next" "$F"           && echo "OK: awk frontmatter strip present"
grep -qF "grep -oE 'images/" "$F"   && echo "OK: image-file existence check present"
grep -qF "Bounded retry" "$F"       && echo "OK: bounded retry section present"
```

Expected: all three `OK:` lines.

---

### Task 4: Dry-run acceptance scenario #1 (empty ARGUMENTS → short)

**Files:** none (this is a manual trace of Phase 0 logic against the spec).

- [ ] **Step 1: Trace the Phase 0 mode router with `ARGUMENTS = ""`**

Walk through the priority table in the file:
- Priority 1: `ARGUMENTS` is empty? **YES** → mode = `short`. Match.

Expected resolution:
- Mode: `short`
- Run topic discovery (Phase 1a)
- N and pencheff_rank: not extracted (not comparison mode).
- Announcement format: `Topic: <discovered> | Mode: short | Slug: <slug>` (no N / Pencheff rank line).

Confirm by reading lines from the file:
```bash
F=/Users/balasriharsha/.claude/skills/pencheff-blog-creation/SKILL.md
grep -A1 "is empty" "$F" | head -5
```

Expected: shows the priority-1 row resolving to `short` and the comment that
Phase 1a will run.

- [ ] **Step 2: Verify the file directs the engine to topic discovery in this case**

Confirm the SKILL.md contains a Phase 1a section that runs only when
"mode is `short` AND `ARGUMENTS` was empty":

```bash
grep -A1 "1a. Topic discovery" "$F"
```

Expected: the section header plus the conditional clause.

Result: **PASS** if mode resolves to `short` and topic discovery is triggered.

---

### Task 5: Dry-run acceptance scenario #2 (`deep: CVE-2025-12345 Django SQL injection` → deep)

**Files:** none.

- [ ] **Step 1: Trace Phase 0 with this input**

Walk through the priority table:
- Priority 1: empty? No.
- Priority 2: starts with `deep:`? **YES** → mode = `deep`. Match.

After stripping the `deep:` prefix and trimming whitespace, TOPIC becomes:
`"CVE-2025-12345 Django SQL injection"`.

Apply slug rules:
1. Lowercase → `"cve-2025-12345 django sql injection"`.
2. Replace non-`[a-z0-9]` with `_` → `"cve_2025_12345_django_sql_injection"`.
3. Collapse runs of `_` → already collapsed.
4. Trim leading/trailing `_` → unchanged.

Expected:
- Mode: `deep`
- Slug: `cve_2025_12345_django_sql_injection`
- Announcement: `Topic: CVE-2025-12345 Django SQL injection | Mode: deep | Slug: cve_2025_12345_django_sql_injection`
- Phase 1a is SKIPPED (only runs when mode is `short` AND ARGUMENTS was empty).
- Phase 1b primary research runs.
- Phase 2 synthesis runs.
- Phase 3a hero image is OPTIONAL (deep mode).
- Phase 4 uses the deep-mode template.
- Phase 5 contract: `W >= 2000`, `CB >= 3`, `TB >= 1`.

- [ ] **Step 2: Verify the file's contract table matches**

Run:
```bash
F=/Users/balasriharsha/.claude/skills/pencheff-blog-creation/SKILL.md
grep -E "^\| deep " "$F"
```

Expected output (whitespace may vary):
```
| deep | 2,000+ | none | 3 | 1 | optional |
```

Result: **PASS** if mode resolves to `deep`, slug rule produces the expected
string, and the deep contract row matches the expected values.

---

### Task 6: Dry-run acceptance scenario #3 (`top 10 pentesting tools` → comparison)

**Files:** none.

- [ ] **Step 1: Trace Phase 0 with this input**

Walk through the priority table:
- Priority 1: empty? No.
- Priority 2: starts with `deep:`? No.
- Priority 3: starts with `comparison:` or `compare:`? No.
- Priority 4: matches `top\s+\d+`? **YES** (`"top 10"` matches). → mode = `comparison`. Match.

Extract N: `top\s+(\d+)` captures `10`. Clamp `[3, 15]` → `10`.
Extract pencheff_rank: no `pencheff_rank=` token. Default `3`. Clamp
`[2, ceil(10/2)] = [2, 5]` → `3`. Unchanged.

TOPIC is unmodified (no prefix to strip). Slug rules on `"top 10 pentesting tools"`:
1. Lowercase → unchanged.
2. Spaces to `_` → `"top_10_pentesting_tools"`.
3. Strip non-allowed → unchanged.
4. Collapse `_` → unchanged.
5. Trim → unchanged.

Expected:
- Mode: `comparison`
- N: 10
- pencheff_rank: 3
- Slug: `top_10_pentesting_tools`
- Announcement: `Topic: top 10 pentesting tools | Mode: comparison | Slug: top_10_pentesting_tools | N: 10 | Pencheff rank: 3`
- Phase 1c (per-tool research with 10 parallel agents) runs.
- Phase 3b (logo strip) runs.
- Phase 4 uses the comparison-mode template with the disclosure callout, the
  rubric table (weights summing to 100), the per-tool template, and Pencheff
  at rank 3 with a real weakness named relative to tools 1 and 2.
- Phase 5 contract: `1200 <= W <= 2000`, `CB >= 1`, `TB >= 2`, `IMG_REFS >= 1`.

- [ ] **Step 2: Verify the file's comparison-mode artifacts exist**

Run:
```bash
F=/Users/balasriharsha/.claude/skills/pencheff-blog-creation/SKILL.md
grep -E "^\| comparison " "$F"                              # contract row
grep -cF "pencheff_rank" "$F"                               # ≥ 3
grep -cF "Disclosure: Pencheff is the publisher" "$F"       # ≥ 2
grep -cF "**Total** | **100**" "$F"                         # 1
grep -cF "1c. Per-tool research" "$F"                       # 1
grep -cF "3b. Comparison mode" "$F"                         # 1
```

Expected: contract row matches `| comparison | 1,200–1,800 | 2,000 | 1 | 2 | 1 logo or text fallback |`, and all `grep -c` outputs meet their thresholds (≥3, ≥2, 1, 1, 1).

- [ ] **Step 3: Verify a custom pencheff_rank token would be respected**

Walk through Phase 0 with input `comparison: top 8 SAST tools pencheff_rank=4`:
- Priority 3 matches (`comparison:` prefix). Mode = `comparison`.
- Strip `comparison:` prefix → `"top 8 SAST tools pencheff_rank=4"`.
- Extract N from `top\s+(\d+)` → `8`. Clamp `[3, 15]` → `8`.
- Extract `pencheff_rank` from `pencheff_rank=(\d+)` → `4`. Clamp `[2, ceil(8/2)] = [2, 4]` → `4`. Unchanged.
- Strip the `pencheff_rank=4` token before computing slug → TOPIC becomes
  `"top 8 SAST tools"` (whitespace around the removed token trimmed).
- Slug: `top_8_sast_tools`.

Expected outcome documented; no further file check needed — the SKILL.md prose
already names this behavior in the Phase 0 section.

Result: **PASS** if the trace resolves to `comparison`, N=10, pencheff_rank=3
for the primary scenario, and the file contains the matching contract and
section headers.

---

### Task 7: Final report (no commit — skill dir is not git-managed)

**Files:** none.

- [ ] **Step 1: Print the final report**

Report to the user, in a single short message:

```
pencheff-blog-creation skill redesigned and verified.

File: /Users/balasriharsha/.claude/skills/pencheff-blog-creation/SKILL.md (vN.M)
Backup: SKILL.md.backup-20260516 (kept for rollback)
Spec:  docs/superpowers/specs/2026-05-16-pencheff-blog-creation-redesign-design.md
Plan:  docs/superpowers/plans/2026-05-16-pencheff-blog-creation-redesign.md

Dry-runs:
  ""                                  → short (Phase 1a runs)         ✓
  "deep: <topic>"                     → deep                          ✓
  "top 10 pentesting tools"           → comparison, N=10, rank=3      ✓

Next: smoke-test the live skill with a real invocation
(e.g., `/pencheff-blog-creation top 5 SAST tools`) once you're ready.
```

If a smoke-test invocation produces a post that fails its Phase 5 contract,
return to the spec and decide whether the contract or the prose needs
adjustment. Re-open this plan or open a fresh one — do not silently relax the
contract.

---

## Plan self-review

**Spec coverage:**
- Phase 0 mode router (spec § "Phase 0 — Parse input and detect mode") → Task 2 Step 1, verified Task 3 Step 2 and Tasks 4–6.
- Frontmatter + word-count contracts (spec § "Frontmatter" and § "Word-count and asset contracts") → Task 2 Step 1, verified Task 5 Step 2 and Task 6 Step 2.
- Comparison rules: N detection, pencheff_rank, scoring rubric, per-tool research, honesty requirements, per-tool template (spec § "Comparison mode rules") → Task 2 Step 1, verified Task 6 Steps 1–3.
- Image strategy: hero capture, logo fallback chain, save report inventory (spec § "Image strategy") → Task 2 Step 1, verified Task 3 Step 1 (sub-phase headers).
- Per-mode body structures (spec § "Per-mode body structure") → Task 2 Step 1.
- Writing quality additions (spec § "Writing quality additions") → Task 2 Step 1.
- Phase 5 save and verify (spec § "Phase 5 — Save and verify") → Task 2 Step 1, verified Task 3 Step 4.
- Acceptance criteria (spec § "Acceptance criteria") → Tasks 4, 5, 6.

No spec section is unaddressed.

**Placeholder scan:** None. All steps contain executable commands, literal
content, or concrete traces with expected values.

**Type / name consistency:** `SLUG`, `TOPIC`, `N`, `pencheff_rank`, `mode`,
`hero_image`, `images_captured`, `images_expected`, `images_placeholders`,
`/browse` skill, `Skill: browse` invocation form, `images/<slug>-hero.png`,
`images/<slug>-logo-<vendor-slug>.png`, contract bounds (`800/1300`, `1200/2000`),
`pencheff_rank=N` token form — all referenced identically across spec, file
content, and verification commands.
