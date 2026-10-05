"""report-generator — Tier 1 advisory.

Stitches the engagement deliverable: executive summary, findings,
chains, MITRE coverage, OPSEC summary. Calls the existing
``reporting.exporter`` machinery for Word/CSV/JSON output.
"""

from __future__ import annotations

from typing import Any

from pencheff.core import mitre_attack
from pencheff.core.tier import tier_1
from pencheff.playbooks.base import Playbook, RunResult


class ReportGeneratorPlaybook(Playbook):
    name = "report_generator"
    tier = 1
    phase = "report"
    noise = "quiet"
    mitre = []
    handoff_to = []
    requires_scope = False
    description = "Final engagement deliverables (Word + CSV + JSON + Markdown)."

    @tier_1
    async def run(self, session: Any, eng_db: Any, engagement_id: str | None = None,
                  output: str | None = None, formats: list[str] | None = None,
                  **kwargs: Any) -> RunResult:
        formats = formats or ["json"]
        artifacts: dict[str, Any] = {"output_dir": output or "(stdout)"}

        # Coverage summary
        finding_dicts: list[dict] = []
        if session and getattr(session, "findings", None):
            finding_dicts = [f.to_dict() for f in session.findings.get_all()]
        all_mitre = []
        for f in finding_dicts:
            v = f.get("mitre")
            if isinstance(v, list):
                all_mitre.extend(v)
        coverage = mitre_attack.coverage_map(all_mitre)
        artifacts["mitre_coverage"] = {tac: [t["id"] for t in techs]
                                       for tac, techs in coverage.items()}
        artifacts["finding_count"] = len(finding_dicts)

        # Engagement DB rollup
        if eng_db and engagement_id:
            artifacts["engagement_markdown"] = eng_db.export_markdown(engagement_id)

        # Format outputs via existing exporter
        outs: dict[str, str] = {}
        if session is not None:
            try:
                from pencheff.reporting.exporter import export_docx, export_csv, export_json
                if "docx" in formats:
                    outs["docx"] = export_docx(session, output_dir=output)
                if "csv" in formats:
                    outs["csv"] = export_csv(session, output_dir=output)
                if "json" in formats:
                    outs["json"] = export_json(session, output_dir=output)
            except Exception as exc:  # pragma: no cover
                artifacts["export_error"] = str(exc)
        artifacts["files"] = outs

        self._log(eng_db, engagement_id, "report",
                  summary=f"{len(finding_dicts)} findings, formats={formats}")
        return RunResult(
            playbook=self.name,
            summary=f"Report generated — {len(finding_dicts)} findings.",
            artifacts=artifacts,
        )
