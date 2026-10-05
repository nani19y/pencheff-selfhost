"""Pencheff playbook registry — the 28 specialists from
https://github.com/0xSteph/pentest-ai-agents reified as Python.

Each playbook is a class subclassing :class:`Playbook`. The registry is
built from explicit imports below — no auto-discovery — so tooling
(grep, IDE jumps, registry tests) sees the full surface at a glance.
"""

from __future__ import annotations

from pencheff.playbooks.base import Playbook, RunResult, Phase, Noise

# fmt: off
from pencheff.playbooks.engagement_planner import EngagementPlannerPlaybook
from pencheff.playbooks.recon_advisor      import ReconAdvisorPlaybook
from pencheff.playbooks.osint_collector    import OsintCollectorPlaybook
from pencheff.playbooks.exploit_guide      import ExploitGuidePlaybook
from pencheff.playbooks.privesc_advisor    import PrivescAdvisorPlaybook
from pencheff.playbooks.cloud_security     import CloudSecurityPlaybook
from pencheff.playbooks.api_security       import ApiSecurityPlaybook
from pencheff.playbooks.mobile_pentester   import MobilePentesterPlaybook
from pencheff.playbooks.wireless_pentester import WirelessPentesterPlaybook
from pencheff.playbooks.social_engineer    import SocialEngineerPlaybook
from pencheff.playbooks.vuln_scanner       import VulnScannerPlaybook
from pencheff.playbooks.web_hunter         import WebHunterPlaybook
from pencheff.playbooks.credential_tester  import CredentialTesterPlaybook
from pencheff.playbooks.attack_planner     import AttackPlannerPlaybook
from pencheff.playbooks.bug_bounty         import BugBountyPlaybook
from pencheff.playbooks.ad_attacker        import AdAttackerPlaybook
from pencheff.playbooks.exploit_chainer    import ExploitChainerPlaybook
from pencheff.playbooks.poc_validator      import PocValidatorPlaybook
from pencheff.playbooks.swarm_orchestrator import SwarmOrchestratorPlaybook
from pencheff.playbooks.bizlogic_hunter    import BizlogicHunterPlaybook
from pencheff.playbooks.cicd_redteam       import CicdRedteamPlaybook
from pencheff.playbooks.detection_engineer import DetectionEngineerPlaybook
from pencheff.playbooks.threat_modeler     import ThreatModelerPlaybook
from pencheff.playbooks.forensics_analyst  import ForensicsAnalystPlaybook
from pencheff.playbooks.malware_analyst    import MalwareAnalystPlaybook
from pencheff.playbooks.stig_analyst       import StigAnalystPlaybook
from pencheff.playbooks.report_generator   import ReportGeneratorPlaybook
from pencheff.playbooks.ctf_solver         import CtfSolverPlaybook
from pencheff.playbooks.crawl_first        import CrawlFirstPlaybook
from pencheff.playbooks.api_authenticator  import ApiAuthenticatorPlaybook
# fmt: on


_classes: list[type[Playbook]] = [
    EngagementPlannerPlaybook,
    ReconAdvisorPlaybook,
    OsintCollectorPlaybook,
    ExploitGuidePlaybook,
    PrivescAdvisorPlaybook,
    CloudSecurityPlaybook,
    ApiSecurityPlaybook,
    MobilePentesterPlaybook,
    WirelessPentesterPlaybook,
    SocialEngineerPlaybook,
    VulnScannerPlaybook,
    WebHunterPlaybook,
    CredentialTesterPlaybook,
    AttackPlannerPlaybook,
    BugBountyPlaybook,
    AdAttackerPlaybook,
    ExploitChainerPlaybook,
    PocValidatorPlaybook,
    SwarmOrchestratorPlaybook,
    BizlogicHunterPlaybook,
    CicdRedteamPlaybook,
    DetectionEngineerPlaybook,
    ThreatModelerPlaybook,
    ForensicsAnalystPlaybook,
    MalwareAnalystPlaybook,
    StigAnalystPlaybook,
    ReportGeneratorPlaybook,
    CtfSolverPlaybook,
    CrawlFirstPlaybook,
    ApiAuthenticatorPlaybook,
]

REGISTRY: dict[str, type[Playbook]] = {cls.name: cls for cls in _classes}
assert len(REGISTRY) == 30, f"expected 30 playbooks, got {len(REGISTRY)}"

__all__ = [
    "Playbook", "RunResult", "Phase", "Noise", "REGISTRY",
]
