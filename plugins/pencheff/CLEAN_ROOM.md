# Clean-Room Provenance

This document records the methodology used while implementing pencheff's
Phase-1 through Phase-6 deterministic-orchestrator expansion. The expansion
was inspired by the public capability inventory of
[hexstrike-ai](https://github.com/0x4m4/hexstrike-ai) (MIT licensed). To
keep pencheff's IP posture clean, the work followed these rules:

## Rules followed

1. **No file from hexstrike-ai was opened in an editor by an
   implementer.** A capability inventory was extracted by a research agent
   (see the planning document committed alongside this branch), and that
   inventory — not hexstrike's source — drove the implementation.

2. **Every YAML decision table cites its source.** Comments at the top of
   each `pencheff/data/policies/*.yaml` reference the wrapped tool's own
   documentation, OWASP / PortSwigger / NIST references, or RFC numbers.
   The intent is that any auditor can re-derive the table from public
   primary sources.

3. **No string identifiers from hexstrike were reused.** Class and module
   names are intentionally generic (Orchestrator, Selector, ParamOptimizer,
   ChainPlanner, ThrottleAdapter). None of hexstrike's class names (e.g.
   `IntelligentDecisionEngine`, `BugBountyWorkflowManager`,
   `VulnerabilityCorrelator`) appear in pencheff's source.

4. **Wrapped binaries are invoked, not linked.** Every external tool is
   called via `asyncio.create_subprocess_exec` with `shell=False`. Their
   licences therefore do not propagate. See `THIRD_PARTY_NOTICES.md` for
   the inventory.

5. **Cryptography solvers were derived from textbook references**, not
   from any third-party orchestrator. Sources are cited inline:

   - Caesar / Vigenère / Kasiski / IC: Stinson, *Cryptography: Theory and
     Practice* §1.2, §2.3.
   - Wiener: Wiener 1990, *Cryptanalysis of Short RSA Secret Exponents*.
   - Fermat factoring: Stinson §3.4.4.
   - Common modulus: Boneh, *Twenty Years of Attacks on the RSA
     Cryptosystem* §3.
   - Length extension: RFC 1320 / Wikipedia "Length extension attack".

6. **Cloud privesc rule sets were derived from public security research
   blogs**, with citations:

   - AWS: Rhino Security Labs "AWS IAM Privilege Escalation Methods"
     (2018, updated periodically).
   - GCP: Rhino Security Labs / SpecterOps GCP IAM research; Google's IAM
     documentation.
   - Azure: Andy Robbins / SpecterOps Azure IAM research; Microsoft docs.

   None of these sources are themselves under a licence that would
   restrict redistribution of the rules they document.

7. **MITRE ATT&CK technique IDs** come from MITRE's own published JSON
   feed (already in the repo at `pencheff/data/mitre_attack.json`), which
   is permissively licensed for derivative use.

## Reproducibility

If anyone needs to re-implement these YAMLs from scratch:

1. Run `pencheff explain-policy <name>` to see the current contents.
2. Replace each entry by re-reading the cited source.
3. Run `pytest plugins/pencheff/tests/orchestrator/` — the suite asserts
   the *shape* of the policies (e.g. that `web/discovery` has > 0
   candidates, that `nmap.aggressive` contains `-T4`), not exact values,
   so a re-derived set will still pass as long as the documented behaviour
   is preserved.

## Contact

If a third party believes any portion of pencheff's source overlaps with
their own copyrighted work, please open an issue at
https://github.com/Magadha-IG/pencheff/issues with a citation to the
specific file and line, and we will revisit.
