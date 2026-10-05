# Pencheff Playbook Catalog

Pencheff ships **30 specialist playbooks** — 28 adapted from
[0xSteph/pentest-ai-agents](https://github.com/0xSteph/pentest-ai-agents)
plus two more (`crawl_first`, `api_authenticator`) that anchor the
HTTP-first reconnaissance + login-discovery flow. Each is a Python class
registered in `pencheff.playbooks.REGISTRY` and exposed both as a CLI
subcommand and an MCP tool (`playbook_<name>`).

| Playbook | Tier | Phase | Noise | CLI | MITRE |
|---|---|---|---|---|---|
| engagement_planner | 1 | scope   | quiet    | `pencheff plan` | — |
| threat_modeler     | 1 | scope   | quiet    | `pencheff threatmodel` | — |
| crawl_first        | 2 | crawl   | moderate | (run via `pencheff engage`) | T1595, T1596 |
| api_authenticator  | 2 | auth    | moderate | (run via `pencheff engage`) | T1078 |
| osint_collector    | 1 | recon   | quiet    | `pencheff osint` | T1589, T1590, T1591, T1596 |
| recon_advisor      | 2 | recon   | moderate | `pencheff recon` | T1595, T1590, T1592, T1046 |
| vuln_scanner       | 2 | vuln    | moderate | `pencheff vuln` | T1190, T1595 |
| web_hunter         | 2 | vuln    | loud     | `pencheff webhunt` | T1190, T1185, T1059.007 |
| api_security       | 2 | vuln    | moderate | `pencheff api` | T1190, T1078 |
| cloud_security     | 2 | vuln    | moderate | `pencheff cloud` | T1078.004, T1530, T1602 |
| bizlogic_hunter    | 2 | vuln    | moderate | `pencheff bizlogic` | T1190, T1078 |
| stig_analyst       | 1 | vuln    | quiet    | `pencheff stig` | — |
| cicd_redteam       | 1 | vuln    | quiet    | `pencheff cicd` | T1190, T1133, T1552, T1611 |
| mobile_pentester   | 2 | vuln    | quiet    | `pencheff mobile` | T1592, T1552.001 |
| ctf_solver         | 2 | vuln    | moderate | `pencheff ctf` | T1595, T1190 |
| exploit_guide      | 1 | exploit | quiet    | (advisory only — ran by swarm) | T1190, T1059 |
| attack_planner     | 1 | exploit | quiet    | (advisory only — ran by swarm) | — |
| exploit_chainer    | 2 | exploit | loud     | `pencheff exploit-chain` | T1190, T1078, T1003 |
| poc_validator      | 2 | exploit | moderate | `pencheff poc` | T1190 |
| credential_tester  | 2 | exploit | loud     | `pencheff credtest` | T1110, T1110.003, T1003 |
| ad_attacker        | 2 | exploit | loud     | `pencheff ad <op>` | T1558, T1558.003, T1558.004, T1003.006, T1649, T1187 |
| wireless_pentester | 2 | exploit | loud     | `pencheff wireless <op>` | T1110, T1187 |
| social_engineer    | 1 | exploit | quiet    | `pencheff socialeng` | T1566 |
| privesc_advisor    | 1 | postex  | quiet    | `pencheff privesc` | T1068, T1548, T1574 |
| forensics_analyst  | 1 | postex  | quiet    | `pencheff forensics <mode>` | — |
| malware_analyst    | 1 | postex  | quiet    | `pencheff malware <mode>` | — |
| detection_engineer | 1 | detect  | quiet    | `pencheff detect` | — |
| report_generator   | 1 | report  | quiet    | `pencheff report` | — |
| bug_bounty         | 2 | report  | moderate | `pencheff bugbounty` | — |
| swarm_orchestrator | 2 | scope   | moderate | `pencheff engage` (or `swarm`) | — |

**Tier 1 (advisory)** = deterministic Python; no targeted network egress
beyond DNS resolution and public OSINT databases. Safe to run without a
scope file.

**Tier 2 (execution)** = network scanning, exploitation, external-tool
invocation. Requires `--scope FILE` and validates every target.

**OPSEC noise** filters via `pencheff engage --noise {quiet,moderate,loud}`.
A ceiling of `quiet` keeps only OSINT/threat-modelling/STIG/report-style
playbooks. A ceiling of `moderate` excludes the loud (exploit / credential
brute / AD attack) playbooks.

## Phase DAG (9 phases)

```
scope   → engagement_planner, threat_modeler
crawl   → crawl_first                                  (HTTP-only crawl + sitemap + robots + spec discovery)
auth    → api_authenticator                            (login URL discovered from crawl, fed to ApiLoginModule)
recon   → osint_collector, recon_advisor               (parallel by default)
vuln    → vuln_scanner, web_hunter, api_security,
          cloud_security, bizlogic_hunter, stig_analyst
exploit → exploit_guide, attack_planner,
          exploit_chainer, poc_validator
postex  → privesc_advisor
detect  → detection_engineer
report  → report_generator, bug_bounty
```

`crawl` populates `session.discovered.endpoints` with the *real* surface
before auth runs, so auth picks a discovered login URL instead of guessing
from a static 14-path list. Vuln modules later read the same populated
endpoint set via `BaseTestModule._get_target_endpoints` — zero per-module
changes needed for the new flow.
