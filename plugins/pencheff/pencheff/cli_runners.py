"""Shared CLI dispatch for the pentest-ai-agents integration.

Each ``run_*`` async function is invoked from ``__main__.py`` and:

1. Loads the scope file (Tier 2 commands).
2. Initialises an in-memory pencheff session (or reuses an existing one).
3. Spins up / reuses an :class:`pencheff.core.engagement_db.EngagementDB` row.
4. Runs the chosen playbook from the registry.
5. Prints a JSON result to stdout.
"""

from __future__ import annotations

import argparse
import json
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pencheff.core.engagement_db import EngagementDB
from pencheff.core.scope_guard import ScopeGuard, ScopeViolation, set_scope


def _load_scope(args: argparse.Namespace) -> ScopeGuard | None:
    path = getattr(args, "scope", None)
    if not path:
        return None
    g = ScopeGuard.from_file(path)
    set_scope(g)
    return g


def _make_session(target: str | None, profile: str = "standard") -> Any:
    from pencheff.config import SCAN_PROFILES
    from pencheff.core.session import create_session
    if not target:
        target = "http://placeholder.invalid"
    p = SCAN_PROFILES.get(profile, SCAN_PROFILES["standard"])
    return create_session(target_url=target, depth=p["depth"])


def _eng_id(args: argparse.Namespace, eng_db: EngagementDB,
            client: str = "local", etype: str = "external",
            scope_obj: ScopeGuard | None = None) -> str:
    eid = getattr(args, "engagement_id", None)
    if eid:
        return eid
    return eng_db.init_engagement(
        client=client, engagement_type=etype,
        scope=(scope_obj.to_dict() if scope_obj else None),
    )


def _print(payload: Any) -> None:
    def default(obj: Any) -> Any:
        if isinstance(obj, datetime):
            return obj.isoformat()
        return str(obj)
    print(json.dumps(payload, indent=2, default=default))


def _result_to_json(result: Any) -> dict[str, Any]:
    return {
        "playbook": result.playbook,
        "summary": result.summary,
        "findings_added": result.findings_added,
        "actions": result.actions,
        "handoffs": result.handoffs,
        "artifacts": result.artifacts,
        "error": result.error,
    }


# ── engage / swarm ────────────────────────────────────────────────────
async def run_engage(args: argparse.Namespace) -> int:
    from pencheff.playbooks.swarm_orchestrator import SwarmOrchestratorPlaybook

    scope = _load_scope(args)
    eng_db = EngagementDB() if not getattr(args, "no_db", False) else None

    client = getattr(args, "client", "local")
    etype = getattr(args, "engagement_type", "external")
    eid = _eng_id(args, eng_db, client=client, etype=etype, scope_obj=scope) if eng_db else None

    session = _make_session(args.target)
    pb = SwarmOrchestratorPlaybook()
    phases = args.phases.split(",") if getattr(args, "phases", None) else None

    try:
        result = await pb.run(
            session, eng_db, eid,
            scope=(scope.to_dict() if scope else {}),
            noise_ceiling=getattr(args, "noise", None),
            tier=getattr(args, "tier", 2),
            phases=phases,
            parallel_recon=not getattr(args, "no_parallel_recon", False),
            include_subdomains=not getattr(args, "no_subdomains", False),
            max_subdomains=int(getattr(args, "max_subdomains", 10)),
            port_range=getattr(args, "port_range", "top-1000"),
        )
    except ScopeViolation as exc:
        print(f"[pencheff] scope violation: {exc}", file=sys.stderr)
        if eng_db and eid:
            eng_db.log(eid, agent="cli", action="scope_violation",
                       summary=str(exc))
        return 2
    payload = {"engagement_id": eid, **_result_to_json(result),
               "session_id": session.id,
               "findings": [f.to_dict() for f in session.findings.get_all()]}
    _print(payload)
    return 0


# ── single-playbook drivers ──────────────────────────────────────────
async def _run_playbook(name: str, args: argparse.Namespace, **extra: Any) -> int:
    from pencheff.playbooks import REGISTRY
    cls = REGISTRY.get(name)
    if not cls:
        print(f"[pencheff] unknown playbook: {name}", file=sys.stderr)
        return 2
    scope = _load_scope(args) if cls.tier == 2 else None
    eng_db = EngagementDB()
    eid = _eng_id(args, eng_db, scope_obj=scope)
    session = _make_session(getattr(args, "target", None) or "http://placeholder.invalid")
    pb = cls()
    try:
        result = await pb.run(session, eng_db, eid,
                              scope=(scope.to_dict() if scope else {}),
                              **extra)
    except ScopeViolation as exc:
        print(f"[pencheff] scope violation: {exc}", file=sys.stderr)
        eng_db.log(eid, agent="cli", action="scope_violation", summary=str(exc))
        return 2
    payload = {"engagement_id": eid, **_result_to_json(result)}
    _print(payload)
    return 0


async def run_plan(args: argparse.Namespace) -> int:
    scope = _load_scope(args) if getattr(args, "scope", None) else None
    eng_db = EngagementDB()
    eid = _eng_id(args, eng_db, etype=getattr(args, "engagement_type", "external"),
                  scope_obj=scope)
    from pencheff.playbooks.engagement_planner import EngagementPlannerPlaybook
    session = _make_session(args.target)
    res = await EngagementPlannerPlaybook().run(
        session, eng_db, eid,
        scope={"client": "local", "type": getattr(args, "engagement_type", "external")},
    )
    _print({"engagement_id": eid, **_result_to_json(res)})
    return 0


async def run_osint(args: argparse.Namespace) -> int:
    return await _run_playbook("osint_collector", args, target=args.target)


async def run_recon(args: argparse.Namespace) -> int:
    return await _run_playbook("recon_advisor", args)


async def run_vuln(args: argparse.Namespace) -> int:
    return await _run_playbook("vuln_scanner", args,
                               use_external=not getattr(args, "no_external", False))


async def run_webhunt(args: argparse.Namespace) -> int:
    return await _run_playbook("web_hunter", args, wordlist=args.wordlist)


async def run_api(args: argparse.Namespace) -> int:
    return await _run_playbook("api_security", args, spec=args.spec)


async def run_exploit_chain(args: argparse.Namespace) -> int:
    return await _run_playbook("exploit_chainer", args)


async def run_poc(args: argparse.Namespace) -> int:
    return await _run_playbook("poc_validator", args, finding_id=args.finding_id)


async def run_privesc(args: argparse.Namespace) -> int:
    eng_db = EngagementDB()
    eid = _eng_id(args, eng_db)
    from pencheff.playbooks.privesc_advisor import PrivescAdvisorPlaybook
    text = ""
    if getattr(args, "peas_output", None):
        try:
            text = Path(args.peas_output).read_text()
        except Exception:
            pass
    res = await PrivescAdvisorPlaybook().run(
        _make_session(None), eng_db, eid, peas_output=text,
    )
    _print({"engagement_id": eid, **_result_to_json(res)})
    return 0


async def run_cloud(args: argparse.Namespace) -> int:
    return await _run_playbook("cloud_security", args, provider=args.provider)


async def run_ad(args: argparse.Namespace) -> int:
    return await _run_playbook(
        "ad_attacker", args, op=args.op, domain=args.domain,
        user=args.user, password=args.password, dc=args.dc,
        target=args.target, users=args.users,
    )


async def run_wireless(args: argparse.Namespace) -> int:
    return await _run_playbook(
        "wireless_pentester", args, op=args.op, interface=args.interface,
        bssid=args.bssid, channel=args.channel,
        cap=args.cap, wordlist=args.wordlist, ssid=args.ssid,
    )


async def run_mobile(args: argparse.Namespace) -> int:
    return await _run_playbook(
        "mobile_pentester", args, mode=args.mode, apk=args.apk, ipa=args.ipa,
    )


async def run_forensics(args: argparse.Namespace) -> int:
    eng_db = EngagementDB()
    eid = _eng_id(args, eng_db)
    from pencheff.playbooks.forensics_analyst import ForensicsAnalystPlaybook
    res = await ForensicsAnalystPlaybook().run(
        _make_session(None), eng_db, eid,
        mode=args.mode, image=args.image, evidence_dir=args.evidence_dir,
    )
    _print({"engagement_id": eid, **_result_to_json(res)})
    return 0


async def run_malware(args: argparse.Namespace) -> int:
    eng_db = EngagementDB()
    eid = _eng_id(args, eng_db)
    from pencheff.playbooks.malware_analyst import MalwareAnalystPlaybook
    res = await MalwareAnalystPlaybook().run(
        _make_session(None), eng_db, eid,
        mode=args.mode, sample=args.sample,
    )
    _print({"engagement_id": eid, **_result_to_json(res)})
    return 0


async def run_cicd(args: argparse.Namespace) -> int:
    eng_db = EngagementDB()
    eid = _eng_id(args, eng_db)
    from pencheff.playbooks.cicd_redteam import CicdRedteamPlaybook
    res = await CicdRedteamPlaybook().run(
        _make_session(None), eng_db, eid,
        workflow=args.workflow, provider=args.provider,
    )
    _print({"engagement_id": eid, **_result_to_json(res)})
    return 0


async def run_bizlogic(args: argparse.Namespace) -> int:
    return await _run_playbook("bizlogic_hunter", args)


async def run_bugbounty(args: argparse.Namespace) -> int:
    return await _run_playbook("bug_bounty", args, platform=args.platform)


async def run_socialeng(args: argparse.Namespace) -> int:
    eng_db = EngagementDB()
    eid = _eng_id(args, eng_db)
    from pencheff.playbooks.social_engineer import SocialEngineerPlaybook
    variables = dict(item.split("=", 1) for item in args.var if "=" in item)
    res = await SocialEngineerPlaybook().run(
        _make_session(None), eng_db, eid,
        pretext=args.pretext, variables=variables,
    )
    _print({"engagement_id": eid, **_result_to_json(res)})
    return 0


async def run_ctf(args: argparse.Namespace) -> int:
    return await _run_playbook("ctf_solver", args, target=args.target)


async def run_threatmodel(args: argparse.Namespace) -> int:
    eng_db = EngagementDB()
    scope = _load_scope(args)
    eid = _eng_id(args, eng_db, scope_obj=scope)
    from pencheff.playbooks.threat_modeler import ThreatModelerPlaybook
    res = await ThreatModelerPlaybook().run(
        _make_session(None), eng_db, eid,
        scope=(scope.to_dict() if scope else {}),
        method=args.method,
    )
    _print({"engagement_id": eid, **_result_to_json(res)})
    return 0


async def run_detect(args: argparse.Namespace) -> int:
    findings: list[dict[str, Any]] = []
    if args.findings:
        findings = json.loads(Path(args.findings).read_text())
        if isinstance(findings, dict):
            findings = findings.get("findings", [])
    from pencheff.reporting.detection_rules import render_findings
    out = render_findings(findings, fmt=args.format, target=args.target)
    sys.stdout.write(out)
    if not out.strip():
        sys.stderr.write(
            "[pencheff] no detection rules emitted — "
            "ensure findings carry `mitre`/`mitre_id` field with a known technique.\n"
        )
    return 0


async def run_stig(args: argparse.Namespace) -> int:
    eng_db = EngagementDB()
    eid = _eng_id(args, eng_db)
    from pencheff.playbooks.stig_analyst import StigAnalystPlaybook
    res = await StigAnalystPlaybook().run(
        _make_session(None), eng_db, eid,
        asset=args.asset, stig_id=args.stig_id,
    )
    _print({"engagement_id": eid, **_result_to_json(res)})
    return 0


async def run_report(args: argparse.Namespace) -> int:
    eng_db = EngagementDB()
    eid = args.engagement_id
    formats = [f.strip() for f in args.format.split(",") if f.strip()]
    from pencheff.playbooks.report_generator import ReportGeneratorPlaybook
    session = _make_session(None)
    res = await ReportGeneratorPlaybook().run(
        session, eng_db, eid,
        output=args.output, formats=formats,
    )
    _print({"engagement_id": eid, **_result_to_json(res)})
    return 0


async def run_credtest(args: argparse.Namespace) -> int:
    return await _run_playbook(
        "credential_tester", args, hashes=args.hashes, hash_mode=args.hash_mode,
        wordlist=args.wordlist, hydra_target=args.hydra_target,
        hydra_service=args.hydra_service, users=args.users,
    )


# ── Engagement DB ────────────────────────────────────────────────────
async def run_engagement(args: argparse.Namespace) -> int:
    eng_db = EngagementDB()
    cmd = getattr(args, "edb_command", None)
    if cmd == "init":
        scope = ScopeGuard.from_file(args.scope) if args.scope else None
        eid = eng_db.init_engagement(
            client=args.client, engagement_type=args.engagement_type,
            scope=(scope.to_dict() if scope else None),
            notes=args.notes,
        )
        print(eid)
        return 0
    if cmd == "list":
        _print(eng_db.list_engagements())
        return 0
    if cmd == "show":
        data = eng_db.show(args.engagement_id)
        if not data:
            print(f"[pencheff] engagement {args.engagement_id} not found", file=sys.stderr)
            return 2
        _print(data)
        return 0
    if cmd == "log":
        eng_db.log(args.engagement_id, agent=args.agent, action=args.action,
                   summary=args.summary, detail=args.detail)
        print("logged")
        return 0
    if cmd == "handoff":
        eng_db.handoff(args.engagement_id, from_agent=args.from_agent,
                       to_agent=args.to_agent, payload=args.payload)
        print("handoff recorded")
        return 0
    if cmd == "export":
        if args.format == "json":
            _print(eng_db.show(args.engagement_id))
        else:
            sys.stdout.write(eng_db.export_markdown(args.engagement_id))
        return 0
    if cmd == "chains":
        _print(eng_db.list_chains(args.engagement_id))
        return 0
    if cmd == "migrate":
        EngagementDB()  # constructor migrates
        print("migrated")
        return 0
    print("usage: pencheff engagement {init|list|show|log|handoff|export|chains|migrate}",
          file=sys.stderr)
    return 2


# ── Memory ───────────────────────────────────────────────────────────
_MEMORY_PATH = Path(__file__).resolve().parents[1] / "docs" / "PROJECT_MEMORY.md"


async def run_memory(args: argparse.Namespace) -> int:
    cmd = getattr(args, "mem_command", None)
    _MEMORY_PATH.parent.mkdir(parents=True, exist_ok=True)
    if cmd == "show":
        if _MEMORY_PATH.exists():
            sys.stdout.write(_MEMORY_PATH.read_text())
        return 0
    msg = getattr(args, "message", "(no message)")
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    line = f"\n## {ts}\n{msg}\n"
    with _MEMORY_PATH.open("a") as f:
        f.write(line)
    print(f"appended to {_MEMORY_PATH}")
    return 0
