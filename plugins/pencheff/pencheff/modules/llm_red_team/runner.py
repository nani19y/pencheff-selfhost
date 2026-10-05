"""Shared LLM red-team module runner: iterate a selected set of OWASP modules
against session.llm_config. Extracted from scan_llm_red_team so the agent path
(agent_probe) reuses the exact same loop. See spec 2026-06-27-agent-attack-suite."""
from __future__ import annotations

import logging
import traceback
from typing import Any

from pencheff.modules.llm_red_team import LLM_RED_TEAM_MODULES

log = logging.getLogger("pencheff.modules.llm_red_team")


async def run_red_team_categories(
    session: Any,
    selected_ids: list[str],
    max_payloads: int | None,
    techniques: list[str] | None = None,
    module_label: str = "scan_llm_red_team",
) -> list:
    """Run each module in ``selected_ids`` against ``session.llm_config``.
    Per-module budget = max(1, max_payloads // len(selected_ids)). Isolates
    per-module exceptions into INFO error-findings. Returns all findings."""
    if not selected_ids:
        return []
    if max_payloads is not None:
        per_module_cap: int | None = max(1, max_payloads // len(selected_ids))
    else:
        per_module_cap = max_payloads

    session.discovered.running_module = module_label
    all_findings: list = []
    try:
        for cat in selected_ids:
            mod = LLM_RED_TEAM_MODULES[cat]()
            try:
                findings = await mod.run(
                    session, http=None,
                    config={"techniques": techniques, "max_payloads": per_module_cap},
                )
                all_findings.extend(findings)
                if findings:
                    session.findings.add_many(findings)
            except Exception as exc:  # noqa: BLE001 — one bad category mustn't kill the rest
                log.warning(
                    "llm_redteam_progress: module_error %s — %s: %s\n%s",
                    cat, type(exc).__name__, str(exc)[:200], traceback.format_exc(limit=4),
                )
                from pencheff.config import Severity as _Sev
                from pencheff.core.findings import Evidence as _Evi, Finding as _Fnd
                err = _Fnd(
                    title=f"LLM red team module {cat} failed to execute",
                    severity=_Sev.INFO, category="llm_runtime_error", owasp_category=cat,
                    description=(f"The {cat} red-team module raised {type(exc).__name__}: {exc}. "
                                 "Common causes: unreachable endpoint, malformed request_template, "
                                 "response_path mismatch."),
                    remediation="Verify the endpoint is reachable and llm_config matches the provider's API shape.",
                    endpoint=session.target.base_url,
                    evidence=[_Evi(request_method="POST", request_url=session.target.base_url,
                                   description=f"{type(exc).__name__}: {exc}"[:500])],
                )
                all_findings.append(err)
                session.findings.add_many([err])
    finally:
        session.discovered.running_module = None
    session.discovered.completed_modules.append(module_label)
    return all_findings
