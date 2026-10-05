# Example: Sigma rule synthesised by detection_engineer

`pencheff detect --findings findings.json --format sigma`:

```yaml
title: Possible Exploit of Public-Facing Application (T1190)
id: pencheff-t1190-744e809a4b05
status: experimental
description: Detect anomalous request patterns indicative of T1190 against acme.example.com.
references:
  - https://attack.mitre.org/techniques/T1190/
author: pencheff
date: 2026-04-27
tags:
  - attack.initial_access
  - attack.t1190
logsource:
  category: webserver
detection:
  selection:
    cs-method: ['POST', 'PUT', 'PATCH']
    cs-uri-stem|contains:
      - "/admin"
      - "/.env"
      - "/.git/"
  filter:
    sc-status:
      - 200
      - 302
  condition: selection and filter
falsepositives:
  - Legitimate API traffic
  - Authorized scanner traffic from declared scope
level: high
```

For Splunk SPL: `pencheff detect --format spl`.
For Microsoft Sentinel KQL: `pencheff detect --format kql`.
