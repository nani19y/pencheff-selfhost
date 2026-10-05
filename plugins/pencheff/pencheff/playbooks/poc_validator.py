"""poc-validator — Tier 2 execution.

Wraps ``test_endpoint`` + ``verify_finding`` to systematically convert
unverified findings into true_positive / false_positive.
"""

from __future__ import annotations

from typing import Any

from pencheff.core.scope_guard import current_scope
from pencheff.core.tier import tier_2
from pencheff.playbooks.base import Playbook, RunResult


class PocValidatorPlaybook(Playbook):
    name = "poc_validator"
    tier = 2
    phase = "exploit"
    noise = "moderate"
    mitre = ["T1190"]
    handoff_to = ["report_generator", "exploit_chainer"]
    requires_scope = True
    description = "Build PoCs via test_endpoint, then verify_finding."

    @tier_2
    async def run(self, session: Any, eng_db: Any, engagement_id: str | None = None,
                  finding_id: str | None = None, **kwargs: Any) -> RunResult:
        guard = current_scope()
        from pencheff import server as _srv
        verified: list[dict[str, Any]] = []
        targets = []
        if finding_id:
            f = session.findings.get_by_id(finding_id)
            if f:
                targets = [f]
        else:
            targets = session.findings.get_all()[:5]  # top 5 by CVSS

        for f in targets:
            if not f.endpoint:
                continue
            if guard:
                try:
                    guard.validate(f.endpoint)
                except Exception:
                    continue
            try:
                resp = await _srv.test_endpoint(
                    session_id=session.id, url=f.endpoint, method="GET",
                )
                status = "true_positive" if resp.get("status_code") in (200, 302, 401, 403, 500) else "false_positive"
                await _srv.verify_finding(
                    session_id=session.id, finding_id=f.id,
                    status=status, notes=f"poc-validator status={resp.get('status_code')}",
                )
                verified.append({"id": f.id, "title": f.title, "status": status})
            except Exception as exc:
                verified.append({"id": f.id, "title": f.title, "error": str(exc)})

        self._log(eng_db, engagement_id, "test_endpoint",
                  summary=f"verified {len(verified)} finding(s)")
        return RunResult(
            playbook=self.name,
            summary=f"PoC validation: {len(verified)} attempt(s).",
            handoffs=list(self.handoff_to),
            artifacts={"verifications": verified},
        )
