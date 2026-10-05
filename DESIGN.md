# Pencheff Design System

> Inferred from the live site (2026-05-30) during a design review. This is the
> baseline future work should match. Marketing (pencheff.com) and the app
> (app.pencheff.com) are deliberately distinct surfaces — note the per-surface
> rules below.

## Voice & posture

Editorial, technical, authoritative. Dark, restrained, confident — a security
practice's monograph, not a SaaS landing template. Left-aligned, never centered.
The look earns trust through typographic discipline and a tight palette, not
decoration.

## Typography

Two body sans by surface (intentional split), one display face, one mono:

| Role | Typeface | Where |
|------|----------|-------|
| Display / headings | **Clash Display** (600) | Marketing heroes & section headers |
| Body — marketing | **Satoshi** | pencheff.com prose |
| Body — app | **Geist** | app.pencheff.com UI (`globals.css`: "body stays Geist") |
| Labels / codes / eyebrows | **JetBrains Mono** | uppercase mono labels, finding codes, metadata |

Rules:
- Headings use Clash Display. Never fall back to Inter/Roboto/system for display text.
- Mono is for labels, codes, and eyebrows only — not body copy.
- Type scale (marketing):
  - Hero headline (`.lp-hero-tagline`): `clamp(38px, 4.8vw, 72px)`, weight 600 — **the loudest text on the page**.
  - Section headers (`.lp-h-section`): `clamp(32px, 4.4vw, 64px)`, weight 380 — large editorial statements, but below the hero.
  - Lead paragraph: ~20px. Section body: ~15.5px. Captions/labels: 12–14px.
- Italic accent: `.lp-italic-gilt` — orange italic for the emphasized word in a headline ("covered.", "in lockstep.").

## Color

Tight, warm-leaning dark palette. Define as CSS variables; do not scatter hex.

| Token | Value | Use |
|-------|-------|-----|
| Ink / surface | `#000` / `#0a0a0a` | Page background, dark surfaces |
| Paper / text | `#E5E5E5` (off-white, ~92% white) | Body text on dark. Never pure `#fff` for long-form. |
| Accent | `#FB7A1C` (orange) | Single accent — CTAs, emphasized headline words, active state |
| Warm cream | `#E8DCC6` | Secondary warm tone |
| Grays | `#A3A3A3` and white-alpha steps | Muted text, hairline borders (`rgba(255,255,255,.06)`) |

Rules:
- One accent color (orange). No second accent. No purple/violet/indigo — ever.
- No flat single-color section backgrounds where a composition is expected; use the
  dark surface + hairline borders + product imagery instead.
- Light mode is a first-class surface, not an inversion — keep contrast and warmth.

## Layout & composition

- **Left-aligned.** Headings, body, and cards are left-aligned. Centered headings are banned (they read as AI-generated).
- **Hairline borders** (`rgba(255,255,255,.06)`), not thick borders or colored left-borders.
- **Cards earn their place.** Use cards when the card IS the unit (a capability in the matrix, a finding row). No decorative 3-up feature grids with icon-in-circle.
- **One job per section**: one purpose, one headline, one supporting line.
- Numbered section eyebrows in mono (`01. THE METHODOLOGY`).

## Motion

- `prefers-reduced-motion` is respected — keep it that way.
- Entrance fades (`lp-fade-up`) with staggered `--lp-d` delays. Keep motion purposeful (entrance, reveal), 50–700ms, `transform`/`opacity` only.

## App UI (app.pencheff.com)

- Calm surface hierarchy, strong type, few colors, minimal chrome — not a dashboard-card mosaic.
- Section headings state the area ("Posture Overview", "Registered Targets").
- Wide data tables scroll inside an `overflow-x-auto` container; page-header action
  groups use `flex flex-wrap` so they don't overflow on mobile.
- One accent (orange) for primary actions and active nav.

## Anti-patterns (never ship)

- Centered headings · purple gradients · icon-in-colored-circle feature grids ·
  emoji as design elements · colored left-border cards · uniform bubbly radius on
  everything · Inter/Roboto/system as the display face · placeholder/lorem text ·
  body text < 14px · contrast < 4.5:1 on body.
