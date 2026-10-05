# Pencheff Plugin SDK

Write your own scan modules in Python and drop them into pencheff.

## Quick start

1. Create a file at `~/.pencheff/custom_modules/my_module.py`
2. Subclass `BaseTestModule`
3. Export `PENCHEFF_ENABLE_CUSTOM_MODULES=1`
4. Your module will be auto-discovered on server start and is runnable from
   `run_policy` / `run_module` / directly via `ModuleClass().run(...)`.

## Example

```python
from __future__ import annotations

from pencheff.config import Severity
from pencheff.core.findings import Evidence, Finding
from pencheff.core.http_client import PencheffHTTPClient
from pencheff.core.session import PentestSession
from pencheff.modules.base import BaseTestModule


class MyCustomCheck(BaseTestModule):
    name = "custom_robots_check"
    category = "misconfiguration"
    owasp_categories = ["A05"]
    description = "Flag a robots.txt that contains sensitive disallowed paths."

    def get_techniques(self) -> list[str]:
        return ["robots-leak"]

    async def run(self, session, http, targets=None, config=None):
        base = session.target.base_url.rstrip("/")
        try:
            r = await http.request("GET", f"{base}/robots.txt")
        except Exception:
            return []
        if not r or r.status != 200:
            return []

        findings = []
        for line in r.text.splitlines():
            if line.lower().startswith("disallow:") and "admin" in line.lower():
                findings.append(Finding(
                    title="robots.txt leaks an admin path",
                    severity=Severity.LOW,
                    category="misconfiguration",
                    owasp_category="A05",
                    description=f"robots.txt exposes: {line}",
                    remediation="Remove the disallowed path from robots.txt; rely on auth instead.",
                    endpoint=f"{base}/robots.txt",
                    evidence=[Evidence(
                        request_method="GET",
                        request_url=f"{base}/robots.txt",
                        response_status=200,
                        description=line,
                    )],
                ))
        return findings
```

## Module contract

Every module must implement:

- `name` (str): machine identifier (lowercase, underscores)
- `category` (str): one of `injection | auth | authz | misconfiguration | components | ssrf | ...`
- `owasp_categories` (list[str]): e.g. `["A03"]`
- `description` (str): one-line summary
- `get_techniques()`: list of technique labels
- `run(session, http, targets, config)`: returns `list[Finding]`

## Integration

Custom modules appear in `list_scan_profiles` once loaded. You can include them
in a YAML policy file:

```yaml
apiVersion: pencheff/v1
kind: ScanPolicy
metadata:
  name: custom-first-pass
spec:
  targets:
    - url: https://example.com
  modules:
    - name: custom_robots_check
      params: {}
  thresholds:
    fail_on: low
```

## Security notice

Custom-module code runs inside the pencheff process with full host
privileges. Only load modules from trusted sources. Keep
`PENCHEFF_ENABLE_CUSTOM_MODULES=0` (or unset) on shared environments.
