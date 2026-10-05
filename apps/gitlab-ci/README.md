# Pencheff GitLab CI Integration

Add Pencheff security scanning to any GitLab CI pipeline.

## Quick start

Add to your `.gitlab-ci.yml`:

```yaml
include:
  - remote: 'https://raw.githubusercontent.com/pencheff/pencheff/main/apps/gitlab-ci/.gitlab-ci.yml'

variables:
  PENCHEFF_TARGET: "https://your-app.example.com"
  PENCHEFF_FAIL_ON: "high"
  PENCHEFF_API_TOKEN: $PENCHEFF_API_TOKEN  # set in GitLab CI/CD Settings → Variables
```

## Variables

| Variable | Default | Description |
|---|---|---|
| `PENCHEFF_TARGET` | *(required)* | Target URL or HOST:PORT |
| `PENCHEFF_PROFILE` | `cicd` | Scan profile: `quick`, `standard`, `deep`, `api-only`, `compliance`, `cicd` |
| `PENCHEFF_FAIL_ON` | `high` | Minimum severity to fail the pipeline |
| `PENCHEFF_API_BASE` | *(empty)* | Hosted Pencheff API base URL |
| `PENCHEFF_API_TOKEN` | *(empty)* | Bearer token for the hosted backend |
| `PENCHEFF_ENGAGEMENT_ID` | *(empty)* | Scope scan to a specific engagement |

## Report artifact

The scan report (JSON + Markdown) is uploaded as a GitLab artifact and kept for 30 days.
