"""api_authenticator — auth via the discovered login URL.

Runs after :class:`crawl_first` has populated ``session.discovered.endpoints``.
Picks the most-login-shaped URL out of that list (via
:func:`pencheff.core.login_finder.pick_login_url`) and hands it to
:class:`pencheff.modules.auth.api_login.ApiLoginModule`. Falls back to
the ApiLoginModule's built-in 14-path probe only if no candidate is
discovered.
"""

from __future__ import annotations

from typing import Any

from pencheff.core.login_finder import pick_login_url, all_login_candidates
from pencheff.core.scope_guard import current_scope
from pencheff.core.tier import tier_2
from pencheff.playbooks.base import Playbook, RunResult


class ApiAuthenticatorPlaybook(Playbook):
    name = "api_authenticator"
    tier = 2
    phase = "auth"
    noise = "moderate"
    mitre = ["T1078"]
    handoff_to = ["recon_advisor", "vuln_scanner"]
    requires_scope = True
    description = (
        "Pick a login URL from the crawled endpoint set, authenticate via "
        "ApiLoginModule, inject cookies + token into the session."
    )

    @tier_2
    async def run(self, session: Any, eng_db: Any, engagement_id: str | None = None,
                  **kwargs: Any) -> RunResult:
        guard = current_scope()
        if guard:
            guard.validate(session.target.base_url)

        # No credentials → nothing to do. Don't fire ApiLoginModule's
        # "no creds" finding here; the engage flow always runs auth even
        # when no creds were configured, and a noisy INFO finding for
        # every credential-less scan is just clutter.
        creds = session.credentials.get("default")
        if not creds or not creds.username or not creds.password:
            # A static bearer/api_key/cookie credential IS the session auth:
            # there's no login flow to run, but every request already carries it
            # (CredentialSet.inject_into_headers). Mark the session authenticated
            # so auth-gated breakers (AuthzAgent / IDOR) don't quiet-quit.
            if creds and (creds.token or creds.api_key or creds.cookie):
                session.authenticated = True
                self._log(eng_db, engagement_id, "auth",
                          summary="static token/api_key credential — session "
                                  "marked authenticated (no login flow needed)")
                return RunResult(
                    playbook=self.name,
                    summary="Static credential applied; session authenticated.",
                    findings_added=0,
                    handoffs=list(self.handoff_to),
                    artifacts={"auth": "static_token"},
                )
            self._log(eng_db, engagement_id, "auth",
                      summary="no credentials configured — skipping API login")
            return RunResult(
                playbook=self.name,
                summary="No credentials configured — skipped.",
                findings_added=0,
                handoffs=list(self.handoff_to),
                artifacts={"skipped": "no_credentials"},
            )

        # Pick a discovered login URL if we can.
        candidates = all_login_candidates(session.discovered.endpoints or [])
        chosen = candidates[0][0] if candidates else None

        from pencheff.core.http_client import PencheffHTTPClient
        from pencheff.modules.auth.api_login import ApiLoginModule

        before_count = session.findings.count
        http = PencheffHTTPClient(session)
        try:
            mod = ApiLoginModule()
            findings = await mod.run(session, http, config={
                # When chosen is None, ApiLoginModule falls back to its
                # built-in 14-path probe automatically — so the static
                # behavior is preserved on targets where the crawl
                # surfaced nothing login-shaped.
                "login_url": chosen,
            })
        finally:
            try:
                await http.close()
            except Exception:
                pass

        new = session.findings.add_many(findings)
        success = any(
            (f.title == "Authenticated Session Established via API Login")
            for f in findings
        )

        log_summary = (
            f"discovered={chosen} → {'AUTHENTICATED' if success else 'failed'}"
            if chosen else
            f"no login URL discovered; ApiLoginModule fallback → "
            f"{'AUTHENTICATED' if success else 'failed'}"
        )
        self._log(eng_db, engagement_id, "auth", summary=log_summary)

        return RunResult(
            playbook=self.name,
            summary=log_summary,
            findings_added=session.findings.count - before_count,
            handoffs=list(self.handoff_to),
            artifacts={
                "discovered_url": chosen,
                "candidates": candidates[:5],
                "authenticated": success,
            },
        )
