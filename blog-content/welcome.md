---
title: "Welcome to the Pencheff Blog"
date: "2026-05-13"
description: "A sample post demonstrating all supported content types: text, code, tables, images, video, audio, and more."
author: "Pencheff Team"
---

This blog serves content from `.md` files in the `blog-content/` folder at the repo root. Drop a new `.md` file in and it appears immediately — no rebuild required.

## Text and Formatting

Regular paragraph with **bold**, _italic_, ~~strikethrough~~, and `inline code`. Links work too: [Pencheff](https://pencheff.com).

> Security is a process, not a product.

## Code Block

```python
def verify_finding(endpoint: str, payload: str) -> bool:
    """Re-fire a crafted payload and confirm exploitation."""
    response = requests.post(endpoint, data={"q": payload}, timeout=5)
    return response.status_code == 200 and "error" in response.text
```

## Table

| Surface      | Scanner          | Output format    |
|--------------|------------------|------------------|
| Web DAST     | Pencheff engine  | OWASP Top 10     |
| SAST         | CodeQL + Semgrep | CWE references   |
| Dependencies | osv-scanner      | CVE + EPSS score |
| IaC          | Trivy            | CIS Benchmark    |

## Image

Place images in `blog-content/images/` and reference them with a relative path:

![Pencheff logo](images/logo.png)

The blog rewrites `images/logo.png` → `/api/asset/images/logo.png` automatically.

## Video

For video and audio embedded as raw HTML, use the full `/api/asset/` path:

<video controls width="640" style="max-width:100%;border-radius:6px;">
  <source src="/api/asset/videos/demo.mp4" type="video/mp4" />
  Your browser does not support the video tag.
</video>

## Audio

<audio controls style="width:100%;margin:1em 0;">
  <source src="/api/asset/audio/intro.mp3" type="audio/mpeg" />
  Your browser does not support the audio element.
</audio>

## Blockquote

> The goal is to use AI to run the adversarial testing cycle autonomously — so security teams get rigorous, reproducible findings without the manual overhead that makes thorough testing expensive and slow.
>
> — Bala Sri Harsha Cheeday, Founder

## Task List

- [x] DAST coverage
- [x] SAST and secrets scanning
- [x] SCA and SBOM
- [x] LLM red teaming
- [ ] Blog setup (this!)

## Embedded Link

For further reading, see the [Pencheff documentation](https://docs.pencheff.com).
