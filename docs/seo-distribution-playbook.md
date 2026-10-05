# Pencheff — Off-page distribution & discoverability playbook

Goal: make Pencheff surface for **DAST, SAST, pentest tools, open-source security platform**
in Google **and** AI answer engines (ChatGPT, Perplexity, Gemini).

On-page SEO is done (term pages, schema, sitemap, llms.txt). Head terms like "DAST"/"SAST"
are authority-gated — they're won by **backlinks + citations + content**, not meta tags.
This is the off-page work that builds that authority. Items marked **[you]** need your
accounts/credentials; **[claude]** I can draft or PR.

---

## 0. BLOCKER FIRST — unblock AI crawlers (highest impact, 5 min) [you]

The Cloudflare zone is injecting a managed `robots.txt` that does `Disallow: /` for
`GPTBot`, `ClaudeBot`, `Google-Extended`, `CCBot`, and sets `Content-Signal: ai-train=no`.
This overrides our own permissive `robots.ts` and **suppresses AI-search visibility**.

- Cloudflare dashboard → the `pencheff.com` zone → **AI Audit / Bots → AI Crawl Control**
  (a.k.a. "Block AI bots" / "Managed robots.txt"). **Turn OFF** the blanket AI-bot block.
- Decide content signals deliberately: keep `ai-train=no` if you don't want model training,
  but allow `ai-input` (grounding/RAG) and `search` so AI _answers_ can cite you.
- Re-fetch `https://pencheff.com/robots.txt` and confirm GPTBot/ClaudeBot/Google-Extended
  no longer have `Disallow: /` in the managed block.

Without this, the rest of the GEO work is throttled at the door.

---

## 1. GitHub — the #1 source AI engines cite for dev tools

- **Repo topics** [you]: add `dast`, `sast`, `penetration-testing`, `pentest`, `vapt`,
  `application-security`, `appsec`, `api-security`, `llm-security`, `ai-red-teaming`,
  `cnapp`, `sbom`, `iac-security`, `vulnerability-scanner`, `security-tools`,
  `owasp`, `self-hosted`. (Repo → ⚙ → Topics.)
- **README** [claude]: ensure the first paragraph literally says
  "open-source, all-in-one security platform — DAST, SAST, VAPT, API security, CNAPP,
  LLM red teaming, SBOM, IaC, compliance. MIT-licensed, self-hostable, free."
  Add a comparison table vs ZAP/Semgrep/Trivy and a feature matrix (AI engines quote these).
- **GitHub release notes** [you]: ship tagged releases — they get indexed and signal activity.
- **`SECURITY.md` + topics + a clear LICENSE (MIT)** [claude/you]: completeness signals.

## 2. "Awesome" lists (high-authority backlinks + AI training corpora) [claude drafts PR]

Open a PR adding Pencheff (one line + link) to:

- `github.com/sindresorhus/awesome` → security section
- `github.com/Hack-with-Github/Awesome-Hacking`
- `github.com/sbilly/awesome-security`
- `github.com/0x90n/InfoSec-Black-Friday` (if seasonal)
- `github.com/TheHive-Project/awesome-incident-response` (if relevant modules)
- `github.com/analyst-collective/awesome-appsec` / `github.com/paragonie/awesome-appsec`
- `github.com/mxssl/sre-interview-prep-guide`-style lists that list scanners
- `github.com/awesome-selfhosted/awesome-selfhosted` → Security (we're self-hostable + MIT)
- Language-specific SAST lists, `awesome-llm-security`, `awesome-ai-security`

PR copy template: `**[Pencheff](https://pencheff.com)** — Open-source, all-in-one security
platform: DAST, SAST, VAPT, API security, CNAPP, LLM red teaming, SBOM, IaC, compliance.
MIT, self-hostable. \`[MIT]\``

## 3. Software directories (AI engines read these for "best X tools") [you submits]

- **OpenAlternative** (openalternative.co) — open-source tool directory, great fit.
- **AlternativeTo** (alternativeto.net) — list Pencheff as an alternative to Burp Suite,
  Snyk, Veracode, Checkmarx, Acunetix; tag DAST/SAST/pentest.
- **Slant** (slant.co) — answer "best open source security/DAST/SAST tools".
- **Product Hunt** — launch ("open-source, all-in-one security platform"). Drives backlinks + buzz.
- **G2 / Capterra / SourceForge** — create vendor listings (category: Application Security,
  DAST, SAST, Penetration Testing). Reviews here are quoted by AI engines.
- **StackShare** — add Pencheff as a tool; link from the GitHub repo.
- **libhunt.com / awesomeopensource.com** — auto-aggregate; ensure topics are set (see §1).
- **Awesome-\* aggregators** (e.g., `trendshift`, `ossinsight`) follow from GitHub stars.

## 4. Answer-engine seeding (GEO/AEO) [you, light]

AI engines synthesize from forums + Q&A. Seed honest, non-spammy presence:

- **Reddit**: r/netsec, r/cybersecurity, r/devops, r/selfhosted, r/opensource —
  a genuine "we built an open-source all-in-one alt to Burp/Snyk" Show-and-Tell.
- **Hacker News**: Show HN: Pencheff — open-source all-in-one security platform (MIT).
- **Stack Overflow / Security StackExchange**: answer relevant "open source DAST/SAST"
  questions where Pencheff is a legitimate answer (disclose affiliation).
- **dev.to / Hashnode / Medium**: cross-post the comparison articles (canonical → blog.pencheff.com).

## 5. Content engine (the durable ranking + citation play) [claude]

Publish comparison/listicle posts on `blog.pencheff.com` targeting the queries new
domains _can_ win and AI engines _do_ cite (tracked in WS2):

- "Best open-source DAST tools (2026)"
- "Best open-source SAST tools (2026)"
- "Best open-source penetration testing tools"
- "SAST vs DAST: what's the difference?"
- "Open-source alternatives to Burp Suite / Snyk / Veracode"
  Each: comparison table, clear "X is…" definitions, FAQ schema, Pencheff at a defensible rank.
  Cross-link to the matching `/platform/*` term page.

## 6. Entity / brand graph (helps AI recognize "Pencheff" as a thing) [you]

- Create + complete: **Crunchbase**, **LinkedIn company page**, **X/Twitter**, **Mastodon (infosec.exchange)**.
- Ensure all link back to pencheff.com and to the GitHub repo (strengthens `sameAs`).
- Add these URLs to `organizationJsonLd().sameAs` in `apps/web/lib/structured-data.ts`
  once the profiles exist (currently only GitHub is listed). [claude can wire once URLs exist]
- **Wikidata** item for Pencheff (software) once there's third-party coverage — AI engines lean on it.

## 7. Measurement [you]

- **Google Search Console**: verify pencheff.com, submit sitemap, watch impressions for
  "dast"/"sast"/"pentest"/"open source security" queries.
- **Bing Webmaster Tools**: verify (Bing powers ChatGPT/Copilot grounding).
- Monthly: ask ChatGPT/Perplexity/Gemini "best open source DAST/SAST tools" and track whether
  Pencheff is cited; iterate content/§2-§4 toward the gaps.

---

### Priority order

1. **§0 Cloudflare AI-bot unblock** (without it, AI work is throttled)
2. **§1 GitHub topics + README** (cheapest authority + most-cited by AI)
3. **§5 comparison content** (durable, ranks long-tail, AI-quotable)
4. **§2 awesome-list PRs + §3 directories** (backlinks + "best X" surfaces)
5. **§6 entity graph + §7 Search Console/Bing** (compounding)
