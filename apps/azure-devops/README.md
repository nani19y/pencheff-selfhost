# Pencheff Azure DevOps Integration

Add Pencheff security scanning to any Azure DevOps pipeline.

## Quick start

In your `azure-pipelines.yml`:

```yaml
extends:
  template: apps/azure-devops/azure-pipelines.yml@pencheff
  parameters:
    target: 'https://your-app.example.com'
    failOn: 'high'
```

Set `PENCHEFF_API_TOKEN` as a secret pipeline variable in Azure DevOps → Pipelines → Edit → Variables.

## Parameters

| Parameter | Default | Description |
|---|---|---|
| `target` | *(required)* | Target URL or HOST:PORT |
| `profile` | `cicd` | Scan profile: `quick`, `standard`, `deep`, `api-only`, `compliance`, `cicd` |
| `failOn` | `high` | Minimum severity to fail the build |
| `apiBase` | *(empty)* | Hosted Pencheff API base URL |
| `engagementId` | *(empty)* | Scope scan to a specific engagement |
| `artifactName` | `pencheff-report` | Name of the published artifact |

## Report artifact

The scan report (JSON + Markdown) is uploaded as a build artifact.
