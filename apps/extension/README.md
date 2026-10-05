# Pencheff Proxy — browser extension

A Manifest V3 WebExtension that captures every HTTP request the browser makes (including HTTPS bodies, via a fetch/XHR wrapper) and streams them to a Pencheff engagement. **No CA certificate install required.**

## Load unpacked

### Chrome / Edge
1. Open `chrome://extensions`.
2. Toggle **Developer mode** on (top-right).
3. Click **Load unpacked** and pick this directory (`apps/extension/`).

### Firefox
1. Open `about:debugging` → **This Firefox**.
2. Click **Load Temporary Add-on**, pick `apps/extension/manifest.json`.

## Pair with an engagement

1. Create an engagement in the Pencheff web UI; copy the pairing code.
2. Open the extension popup; enter the API base URL (e.g. `https://api.pencheff.local`) and the pairing code; click **Pair**.
3. Browse the target. Captured flows appear in `/engagements/<id>/traffic` within ~2s (the extension batches every 50 flows or 2 seconds, whichever is first).

## Caveats

- HTTPS request/response **bodies** are captured via the page-world `fetch` / `XMLHttpRequest` wrapper (`src/content.js`). Background-only flows (e.g. browser-internal XHRs that the page never sees) get marked `body_capture: "limited"`.
- The first version is intentionally minimal — no per-tab UX, no header rewriting. Open issues for what's missing.
