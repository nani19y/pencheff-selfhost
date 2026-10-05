"""LLM-driven penetration-testing agent.

Drives the pencheff toolkit as the agent's hands. The agent is instructed
to behave like an elite ethical hacker: reconnoitre the target, pick the
most promising vulnerability classes, probe them with targeted payloads,
*verify* each finding by reproducing it against the live application,
chain anything promising, and discard everything it cannot prove.

The agent's tool calls, thinking text, and final summary are streamed
into the scan log / SSE channel so the UI shows what it tried and why.

Fall back to the deterministic scan is handled by the caller
(``scan_runner.run_scan``) — if ``AGENT_LLM_API_KEY`` is blank we skip
this module entirely.

Talks to any chat-completions endpoint that accepts the OpenAI
tool-calling request shape — no provider SDK lock-in. Operators supply
their own credentials via env (``AGENT_LLM_*``).
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

from ..config import get_settings

log = logging.getLogger("pencheff.agent")

LogSink = Callable[[str], Awaitable[None]]


# Flags the agent must NOT be allowed to pass to external tools — anything that
# pivots from "scan the target" into "run code on the operator's box," writes
# files outside the sandbox report dir, or weaponises the engagement beyond the
# paste-a-URL consent model.
_DANGEROUS_ARG_SUBSTRINGS = (
    "--os-shell",
    "--os-pwn",
    "--os-cmd",
    "--os-smbrelay",
    "--os-bof",
    "--file-write",
    "--file-dest",
    "--reg-add",
    "--reg-write",
    "--eval",
    "--sql-shell",
    "--dbms-cred",
    "--tmp-path",
    "--shellcode",
    # Data-extraction flags — non-destructive consent does NOT cover
    # actual row extraction. ProofOfImpactAgent uses sqlmap for schema
    # introspection only (--dbs, --tables, --columns, --count). The
    # following flags actually extract data and must stay blocked.
    "--dump",
    "--dump-all",
    "--search",
    "--sql-query",
    "--sql-file",
    "--passwords",
    "--privileges",
    # ── Feature 001 (S-07) — new scanner CLIs introduced with the 12
    # ── kind taxonomy. Each has a flag that either (a) pivots the
    # ── scanner into a remote-attack client, (b) loads attacker-
    # ── controlled code from disk, or (c) downgrades transport security.
    # ── See spec §6.4 "Tool Input Allowlists & Sandbox Boundaries".
    "--server",              # trivy: remote attack-client mode
    "--listen",              # generic: bind on attacker-controlled port
    "--import-path",         # grpcurl: file read outside sandbox
    "--plaintext",           # grpcurl: forces no-TLS — policy regression
    "--external-checks-dir", # checkov: loads arbitrary Python from disk
    "--custom-check-dir",    # tfsec: same vector as checkov above
    "--post-renderer",       # helm: arbitrary executable
    "--values-from-stdin",   # helm: stdin injection
    # Note: ``--output-file`` is allowed when its argument is under /tmp/;
    # the path check lives at the per-tool wrapper level (not a substring).
)

# Substrings that mean a URL-template placeholder leaked into a probe URL.
# Probing them always 404s and just burns the tool budget.
_PLACEHOLDER_MARKERS = ("{", "}", "%7B", "%7b", "%7D", "%7d")


async def _test_endpoint_guarded(
    call_fn,
    session_id: str,
    args: dict[str, Any],
) -> Any:
    """Wrap ``test_endpoint`` to short-circuit obviously-bad URLs and adapt the
    tool-schema arg names to the underlying ``pencheff.server.test_endpoint``
    signature.

    The LLM-facing schema declares ``payload`` (single body) + optional
    ``params`` (querystring map). The underlying function takes ``body`` (single
    body) + ``payloads`` (a list for batch-substitution via the PENCHEFF
    placeholder). The earlier wrapper forwarded ``payload`` and ``params``
    verbatim, which the function did not accept — producing
    ``TypeError: test_endpoint() got an unexpected keyword argument 'payload'``
    on every call and crippling every payload-based probe. This wrapper now:

    - maps schema ``payload`` -> function ``body`` (single request body)
    - maps schema ``payloads`` (list) -> function ``payloads`` (placeholder fanout)
    - folds schema ``params`` into the URL as a querystring (the function has no
      params kwarg; URL-mounting matches the OpenAI tool-calling convention the
      LLM expects).
    """
    url = str(args.get("url") or "")
    if any(m in url for m in _PLACEHOLDER_MARKERS):
        return {
            "error": (
                "url contains an URL-template placeholder ({…} or its "
                "percent-encoded form %7B…%7D). Substitute a real ID or "
                "skip this endpoint — probing the literal template will "
                "always 404."
            ),
            "url": url,
        }

    # Fold ``params`` (querystring map) into the URL since the underlying
    # function has no ``params`` kwarg. Skip if the URL already has a query.
    params = args.get("params")
    if isinstance(params, dict) and params:
        from urllib.parse import urlencode
        sep = "&" if "?" in url else "?"
        url = f"{url}{sep}{urlencode({str(k): str(v) for k, v in params.items()})}"

    return await call_fn(
        "test_endpoint",
        session_id,
        url=url,
        method=args.get("method", "GET"),
        body=args.get("payload"),
        payloads=args.get("payloads"),
        headers=args.get("headers"),
    )


# Categories that represent passive-observation findings (the populator
# read the response headers / cookies / TLS config and recorded what it
# saw). These can't meaningfully be "false-positived" by the agent —
# the evidence is the observation itself.
_PASSIVE_MISCONFIG_CATEGORIES = frozenset({
    "misconfiguration",
    "crypto",
    "info_disclosure",
    "compliance",
})

# Severities the agent is NOT allowed to auto-suppress when the finding
# is a passive misconfig — the operator can still suppress these
# manually via the UI, but the LLM agent has to leave them visible.
_BLOCKED_SUPPRESS_SEVERITIES = frozenset({"medium", "high", "critical"})


async def _suppress_finding_guarded(
    call_fn,
    session_id: str,
    args: dict[str, Any],
) -> Any:
    """Wrap ``suppress_finding`` to refuse suppression of medium+ passive misconfigs.

    The agent has been over-suppressing legitimate header / clickjacking /
    CSP misconfigurations because its system prompt says "ELIMINATE FALSE
    POSITIVES RUTHLESSLY". For active-attack categories (injection, xss,
    auth, …) that's correct. For passive categories (misconfiguration,
    crypto, info_disclosure, compliance) at medium+ severity, suppression
    silently kills real findings and inflates the grade.
    """
    finding_id = str(args.get("finding_id") or "")
    reason = str(args.get("reason") or "")
    if not finding_id:
        return {"error": "missing required 'finding_id' argument"}

    # Look up the finding to inspect its severity + category. The agent
    # log truncates IDs to 12 chars, but the model is supposed to pass
    # the full ID — handle both forms by prefix-matching when needed.
    listing = await call_fn("get_findings", session_id)
    if isinstance(listing, dict) and "error" in listing:
        # If we can't read findings, fall through and let the underlying
        # tool decide; better to over-suppress than block legitimate FPs.
        return await call_fn(
            "suppress_finding",
            session_id,
            finding_id=finding_id,
            reason=reason,
        )

    findings = (
        listing.get("findings") if isinstance(listing, dict) else listing
    ) or []
    target = None
    for f in findings:
        fid = (f.get("id") or "") if isinstance(f, dict) else ""
        if fid == finding_id or (
            len(finding_id) <= 16 and fid.replace("-", "").startswith(finding_id)
        ):
            target = f
            break

    if target is not None:
        sev = str(target.get("severity") or "info").lower()
        cat = str(target.get("category") or "").lower()
        if (
            sev in _BLOCKED_SUPPRESS_SEVERITIES
            and cat in _PASSIVE_MISCONFIG_CATEGORIES
        ):
            return {
                "error": (
                    f"refused to suppress finding {finding_id}: it is "
                    f"a {sev}-severity {cat} finding (passive header / "
                    "config observation). These are verified by header "
                    "inspection at populator time and cannot be "
                    "'reproduced' via test_endpoint — they are not "
                    "false positives just because there is no payload "
                    "to fire. Leave it active so the operator can "
                    "review. The only valid suppression here is if "
                    "the finding is on a literal static-asset URL "
                    "(``.css`` / ``.js`` / ``.png`` / etc.), in which "
                    "case the populator already pre-suppressed it."
                ),
                "finding_id": finding_id,
                "severity": sev,
                "category": cat,
            }

    return await call_fn(
        "suppress_finding",
        session_id,
        finding_id=finding_id,
        reason=reason,
    )


def _reject_tool_call(
    profile: str | None, tool: str, args: list[str]
) -> str | None:
    """Return a rejection reason, or None if the call is allowed."""
    for a in args:
        lowered = a.lower()
        for needle in _DANGEROUS_ARG_SUBSTRINGS:
            if needle in lowered:
                return f"arg contains disallowed flag {needle!r}"
        if ".." in a:
            return "path traversal in args"
        if lowered.startswith("-o") and len(lowered) > 2:
            # -oN/-oX/-oG <path> splits into two args; single-token form
            # like -oNfile only matters if the path escapes the sandbox.
            # Be conservative: require the path (next arg or inline) to
            # stay under /tmp.
            pass  # handled by the inline-path check below
    # Inline output-path checks: flag+value pairs.
    for idx, a in enumerate(args):
        if a in ("-o", "-oN", "-oX", "-oG", "-oA", "--output", "-output"):
            val = args[idx + 1] if idx + 1 < len(args) else ""
            if val and not val.startswith(("/tmp/", "./", "tmp/")):
                return f"output path {val!r} escapes sandbox"
    return None


# ---------------------------------------------------------------------------
# Tool registry — maps the OpenAI-compatible function schema to a
# pencheff.server coroutine
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AgentTool:
    name: str
    description: str
    input_schema: dict[str, Any]
    # Called with the session_id pre-bound and the argument dict from the
    # model. Returns a JSON-serialisable result.
    handler: Callable[[str, dict[str, Any]], Awaitable[Any]]


def _build_tool_registry(
    *,
    profile: str | None = None,
) -> list[AgentTool]:
    """Define the tools exposed to the agent.

    Every handler is a thin wrapper over a ``pencheff.server`` coroutine.
    We bind ``session_id`` at call time inside the agent loop.
    """
    import pencheff.server as srv  # local import — plugin may not be on path in tests

    async def _call(fn_name: str, session_id: str, **kwargs: Any) -> Any:
        fn = getattr(srv, fn_name, None)
        if fn is None:
            return {"error": f"tool {fn_name} not available"}
        try:
            return await fn(session_id=session_id, **kwargs)
        except Exception as exc:  # noqa: BLE001 — report back to the model
            log.warning("tool %s raised: %s", fn_name, exc)
            return {"error": f"{type(exc).__name__}: {exc}"}

    async def _run_security_tool(sid: str, args: dict[str, Any]) -> Any:
        tool = str(args.get("tool", "")).strip().lower()
        tool_args = args.get("args") or []
        if not tool:
            return {"error": "missing required 'tool' argument"}
        if not isinstance(tool_args, list) or not all(
            isinstance(a, str) for a in tool_args
        ):
            return {"error": "'args' must be a list of strings"}
        reason = _reject_tool_call(profile, tool, tool_args)
        if reason:
            return {"error": f"tool-rejected: {tool} ({reason})"}
        timeout = args.get("timeout", 120)
        try:
            timeout = int(timeout)
        except (TypeError, ValueError):
            timeout = 120
        timeout = max(5, min(timeout, 180))  # cap at 180s
        return await _call(
            "run_security_tool",
            sid,
            tool=tool,
            args=tool_args,
            timeout=timeout,
            parse_output=bool(args.get("parse_output", True)),
        )

    def _simple(fn_name: str, description: str) -> AgentTool:
        """Tool with no extra arguments beyond session_id."""
        return AgentTool(
            name=fn_name,
            description=description,
            input_schema={"type": "object", "properties": {}, "required": []},
            handler=lambda sid, _args: _call(fn_name, sid),
        )

    tools: list[AgentTool] = [
        # ---- Authenticated session establishment --------------------
        AgentTool(
            name="authenticated_crawl",
            description=(
                "Establish an authenticated session against the target using "
                "the provided credentials. Drives Playwright against the "
                "login form (fills username/password, clicks submit), then "
                "extracts the resulting cookies and bearer tokens back into "
                "the scan session so every subsequent scan_* / test_endpoint "
                "call is authenticated. "
                "CALL THIS FIRST whenever credentials are provided — without "
                "it, username+password just sit in the session as Basic "
                "Auth, which modern form-login apps silently ignore, and "
                "the whole scan runs anonymously. "
                "Optionally pass login_url if the login page differs from "
                "the target base URL."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "login_url": {
                        "type": "string",
                        "description": "Full URL of the login page. Defaults to the target base URL.",
                    },
                },
                "required": [],
            },
            handler=lambda sid, args: _call(
                "authenticated_crawl",
                sid,
                **({"login_url": args["login_url"]} if args.get("login_url") else {}),
            ),
        ),
        # ---- Reconnaissance ----------------------------------------
        _simple(
            "recon_passive",
            "OSINT & passive reconnaissance: subdomains via crt.sh, "
            "robots.txt, sitemap, security.txt, tech-stack fingerprint. "
            "Zero noisy traffic to the target. ALWAYS start here.",
        ),
        _simple(
            "recon_active",
            "Active reconnaissance: crawl the target, enumerate endpoints, "
            "forms, parameters, and JavaScript-discovered routes. Run "
            "this second once you've seen the shape of the app.",
        ),
        _simple(
            "recon_api_discovery",
            "Hunt for Swagger/OpenAPI/GraphQL endpoints and descriptor "
            "files (swagger.json, openapi.yaml, /graphql, /api-docs, …). "
            "Run this early if the target exposes an API surface.",
        ),
        # ---- Fingerprinting & infrastructure ----------------------
        _simple(
            "scan_waf",
            "Detect WAF / CDN in front of the target (Cloudflare, Akamai, "
            "AWS WAF, etc.) and note bypass relevance.",
        ),
        _simple(
            "scan_infrastructure",
            "Scan for exposed infrastructure: TLS config, security headers, "
            "banners, host-level misconfigurations. Treat most of these "
            "as INFORMATIONAL — they matter only when they enable something.",
        ),
        # ---- Vulnerability scanning -------------------------------
        _simple(
            "scan_injection",
            "Injection sweep (SQLi, NoSQLi, LDAP, XXE, SSTI, command "
            "injection). Use on forms and parameters discovered in recon.",
        ),
        _simple(
            "scan_client_side",
            "Client-side attacks: reflected/DOM XSS, CSRF, open redirect, "
            "CORS misconfig, prototype pollution. Requires discovered "
            "parameters.",
        ),
        _simple(
            "scan_auth",
            "Authentication weaknesses: brute-force/lockout, weak password "
            "policy, credential stuffing vectors, JWT algorithm confusion, "
            "session fixation.",
        ),
        _simple(
            "scan_authz",
            "Authorisation flaws: IDOR, horizontal/vertical privilege "
            "escalation, forced-browsing of admin paths. Run ONLY with "
            "authenticated creds when available.",
        ),
        _simple(
            "scan_oauth",
            "OAuth 2.0 / OIDC flaws: redirect_uri manipulation, state "
            "mismatch, PKCE absence, token leakage via Referer.",
        ),
        _simple(
            "scan_api",
            "API-specific tests: mass assignment, unauthenticated "
            "endpoints, rate-limit gaps, GraphQL introspection.",
        ),
        _simple(
            "scan_business_logic",
            "Business-logic flaws: race conditions, price tampering, "
            "workflow bypass. Requires understanding of the application.",
        ),
        _simple(
            "scan_advanced",
            "Advanced web attacks: HTTP request smuggling, cache poisoning, "
            "host-header injection, CRLF injection.",
        ),
        _simple(
            "scan_file_handling",
            "File-handling attacks: unrestricted upload, path traversal, "
            "archive extraction, content-type bypass.",
        ),
        _simple(
            "scan_subdomain_takeover",
            "Subdomain takeover: dangling DNS pointing to unclaimed S3 / "
            "CloudFront / GitHub Pages / Heroku / etc.",
        ),
        _simple(
            "scan_cloud",
            "Cloud misconfiguration: exposed S3 buckets, IAM metadata "
            "endpoint reachability, public blobs.",
        ),
        _simple(
            "scan_mfa_bypass",
            "MFA bypass techniques: backup-code brute-force, OTP re-use, "
            "race conditions in 2FA flows.",
        ),
        _simple(
            "scan_websocket",
            "WebSocket attacks: CSWSH, authentication gaps, message "
            "tampering.",
        ),
        _simple(
            "scan_dom_xss",
            "Browser-driven DOM XSS — uses a headless browser to exercise "
            "client-side sinks. Requires Playwright / Chromium.",
        ),
        _simple(
            "scan_llm_red_team",
            "Probe AI/LLM endpoints for prompt injection, jailbreaks, "
            "system-prompt extraction, and training-data leakage. Run "
            "against any discovered chat, completion, or embedding endpoints.",
        ),
        # ---- Verification & chaining ------------------------------
        AgentTool(
            name="test_endpoint",
            description=(
                "Manually probe a single endpoint with a crafted request. "
                "This is how you CONFIRM a suspected vulnerability — use it "
                "to reproduce a SQLi payload, XSS reflection, SSRF hit, "
                "etc. Always call this to verify anything before trusting "
                "it as a real finding."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Full URL to request."},
                    "method": {
                        "type": "string",
                        "enum": ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"],
                        "default": "GET",
                    },
                    "payload": {
                        "type": ["string", "object"],
                        "description": "Request body (string or JSON object).",
                    },
                    "payloads": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": (
                            "Optional list of payload strings. When set, the "
                            "literal token PENCHEFF in ``url`` or ``payload`` "
                            "is replaced with each list entry and one request "
                            "is sent per substitution (cap: 50). Use this for "
                            "fast SQLi/XSS/SSRF probing."
                        ),
                    },
                    "headers": {
                        "type": "object",
                        "additionalProperties": {"type": "string"},
                    },
                    "params": {
                        "type": "object",
                        "additionalProperties": {"type": "string"},
                        "description": "Querystring params (folded into URL).",
                    },
                },
                "required": ["url"],
            },
            handler=lambda sid, args: _test_endpoint_guarded(_call, sid, args),
        ),
        AgentTool(
            name="test_chain",
            description=(
                "Execute a multi-step attack chain to prove exploit impact "
                "(e.g. SSRF → cloud metadata → IAM creds). ``steps`` is a "
                "list of ``{action, url, method, payload, …}`` maps."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "steps": {
                        "type": "array",
                        "items": {"type": "object"},
                        "minItems": 1,
                    }
                },
                "required": ["steps"],
            },
            handler=lambda sid, args: _call("test_chain", sid, steps=args["steps"]),
        ),
        _simple(
            "exploit_chain_suggest",
            "Ask pencheff to propose attack chains that link currently-"
            "known findings into bigger impact stories. Review and then "
            "``test_chain`` the promising ones.",
        ),
        # ---- Observation ------------------------------------------
        _simple(
            "get_findings",
            "List the findings recorded so far on this session. Useful "
            "to check what's already been recorded before deciding "
            "what's next.",
        ),
        # ---- Triage ------------------------------------------------
        AgentTool(
            name="suppress_finding",
            description=(
                "Mark a finding the scanner recorded as a false positive. "
                "Use this when your verification shows the scanner was "
                "fooled (e.g. SPA 404 HTTP 200 trap). The suppressed "
                "finding will NOT affect the final grade. "
                "NOTE: this tool will REFUSE to suppress medium+ severity "
                "passive misconfiguration findings (missing headers, "
                "clickjacking, weak CSP, weak TLS, etc.) — those are "
                "verified by header inspection, not payload reproduction, "
                "and you cannot 'false-positive' them. Leave them active."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "finding_id": {"type": "string"},
                    "reason": {
                        "type": "string",
                        "description": "Short justification (one sentence).",
                    },
                },
                "required": ["finding_id", "reason"],
            },
            handler=lambda sid, args: _suppress_finding_guarded(_call, sid, args),
        ),
        # ---- Per-finding exploitation -----------------------------
        AgentTool(
            name="exploit_finding",
            description=(
                "Actively exploit a finding and stamp the captured proof onto "
                "its evidence. Dispatches to a category-specific playbook — "
                "clickjacking PoC, header capture, rate-limit burst, SQLi/XSS/"
                "SSRF triggers, or a generic re-probe for unknown categories. "
                "Sets verification_status=true_positive on a confirmed exploit "
                "and false_positive when reproduction fails. **REQUIRED on every "
                "non-suppressed finding** before you call `finish` — the report "
                "must include captured evidence for each finding, not just titles."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "finding_id": {
                        "type": "string",
                        "description": "The 12-char hex finding id from get_findings.",
                    },
                },
                "required": ["finding_id"],
            },
            handler=lambda sid, args: _call("exploit_finding", sid, finding_id=args["finding_id"]),
        ),
        # ---- External attack tools --------------------------------
        AgentTool(
            name="run_security_tool",
            description=(
                "Execute an external security tool against the target via a "
                "sandboxed subprocess. Supported: "
                "ffuf, wafw00f, subfinder, sslscan, whatweb, "
                "gobuster, wfuzz, dirb, amass, dnsrecon, wpscan, testssl. "
                "Examples: "
                "`{tool:'ffuf', args:['-u','<url>/FUZZ','-w','/usr/share/wordlists/dirb/common.txt','-mc','200,301,401,403']}`, "
                "Timeout is capped at 180s. Use this AFTER test_endpoint has "
                "given you enough signal to justify the tool — use Pulse for template checks and ffuf for "
                "content discovery."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "tool": {
                        "type": "string",
                        "description": "Name of the external tool (e.g. 'ffuf').",
                    },
                    "args": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Command-line arguments as an array (no shell).",
                    },
                    "timeout": {
                        "type": "integer",
                        "minimum": 5,
                        "maximum": 180,
                        "default": 120,
                    },
                    "parse_output": {"type": "boolean", "default": True},
                },
                "required": ["tool", "args"],
            },
            handler=_run_security_tool,
        ),
        # ---- Out-of-band (OAST) verification ----------------------
        _simple(
            "oast_init",
            "Initialise OAST (out-of-band) callback infrastructure for "
            "this session. Call once before using oast_new_url. Uses "
            "interactsh-client under the hood.",
        ),
        AgentTool(
            name="oast_new_url",
            description=(
                "Generate a unique OAST callback URL. Inject it into any "
                "suspected blind sink — blind SSRF (URL params, webhook "
                "fields), blind SQLi (LOAD_FILE/UNC), blind command "
                "injection (curl/wget/nslookup). If the target fetches the "
                "URL, that's proof of out-of-band interaction = real vuln. "
                "Label the probe so oast_poll can correlate callbacks."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "label": {
                        "type": "string",
                        "description": "Short label, e.g. 'ssrf-avatar-upload'.",
                    },
                },
                "required": [],
            },
            handler=lambda sid, args: _call(
                "oast_new_url",
                sid,
                **({"label": args["label"]} if args.get("label") else {}),
            ),
        ),
        _simple(
            "oast_poll",
            "Poll the OAST backend for received callbacks. Any hit "
            "confirms out-of-band interaction. Typical flow: oast_init → "
            "oast_new_url → inject into suspected blind sink → wait 10-30s "
            "→ oast_poll.",
        ),
        AgentTool(
            name="finish",
            description=(
                "Call this when you are satisfied that you've surfaced the "
                "genuine, verified, exploitable findings. ``summary`` is "
                "a short (< 400 words) executive summary of what you did, "
                "what you confirmed, and what you ruled out."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "summary": {"type": "string"},
                },
                "required": ["summary"],
            },
            handler=lambda sid, args: _finish_result(args),
        ),
        # ---- Evidence capture (EvidenceCaptureAgent) ----------------
        AgentTool(
            name="capture_evidence",
            description=(
                "Screenshot a verified-vulnerable URL state with PII redaction. "
                "GET-only: payload is appended as a query-string parameter. "
                "Stores PNG to the scan-evidence directory and returns the "
                "relative path. Used by EvidenceCaptureAgent."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "finding_id": {
                        "type": "string",
                        "description": "The finding ID — used as the screenshot filename.",
                    },
                    "url": {
                        "type": "string",
                        "description": "Full vulnerable URL to navigate to.",
                    },
                    "payload": {
                        "type": "string",
                        "description": "Optional query-string fragment appended to the URL.",
                    },
                    "redact_pii": {
                        "type": "boolean",
                        "default": True,
                        "description": "Mask emails/phone/CC numbers in the page before capture.",
                    },
                },
                "required": ["finding_id", "url"],
            },
            handler=lambda sid, args: _call(
                "capture_evidence",
                sid,
                finding_id=args["finding_id"],
                url=args["url"],
                payload=args.get("payload"),
                redact_pii=args.get("redact_pii", True),
            ),
        ),
        # ---- Admin panel tools (AdminAccessAgent) -------------------
        AgentTool(
            name="playwright_navigate",
            description=(
                "GET-only headless-browser navigation. Used by AdminAccessAgent. "
                "Inherits session auth cookies. Returns status, final_url, title. "
                "Returns auto_abort=True on 5xx — caller must then logout and finish."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "Full URL to navigate to (GET only).",
                    },
                },
                "required": ["url"],
            },
            handler=lambda sid, args: _call(
                "playwright_navigate",
                sid,
                url=args["url"],
            ),
        ),
        AgentTool(
            name="playwright_screenshot",
            description=(
                "Screenshot the current admin-page state with PII redaction. "
                "Requires playwright_navigate to have been called first. "
                "Used by AdminAccessAgent."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "finding_id": {
                        "type": "string",
                        "description": "Finding ID — used as the screenshot filename suffix.",
                    },
                    "redact_pii": {
                        "type": "boolean",
                        "default": True,
                    },
                },
                "required": ["finding_id"],
            },
            handler=lambda sid, args: _call(
                "playwright_screenshot",
                sid,
                finding_id=args["finding_id"],
                redact_pii=args.get("redact_pii", True),
            ),
        ),
        AgentTool(
            name="playwright_enumerate_links",
            description=(
                "List up to N visible link texts and hrefs on the current admin page. "
                "Read-only — does not click or navigate. Used by AdminAccessAgent."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "max_links": {
                        "type": "integer",
                        "default": 5,
                        "minimum": 1,
                        "maximum": 20,
                    },
                },
                "required": [],
            },
            handler=lambda sid, args: _call(
                "playwright_enumerate_links",
                sid,
                max_links=args.get("max_links", 5),
            ),
        ),
        AgentTool(
            name="playwright_logout",
            description=(
                "Log out of the admin panel and close the browser. "
                "ALWAYS call this at the end of AdminAccessAgent's run, "
                "even if earlier steps failed."
            ),
            input_schema={
                "type": "object",
                "properties": {},
                "required": [],
            },
            handler=lambda sid, _args: _call("playwright_logout", sid),
        ),
        # ============================================================
        # Feature 001 — artifact-cluster scanner wrappers
        # ============================================================
        AgentTool(
            name="artifact_clone_repo",
            description=(
                "Clone a git repository to a sandboxed temp dir for source-code "
                "/ iac / cicd_pipeline scanning. The URL MUST match the target's "
                "registered kind_config.repo_url (allowlist enforced server-side). "
                "Hooks are disabled, depth=1, single-branch — safe to clone even "
                "from operator-supplied URLs."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "git URL — must match kind_config.repo_url"},
                    "ref": {"type": "string", "description": "branch / tag / commit (default HEAD)"},
                },
                "required": ["url"],
            },
            handler=lambda sid, args: _call(
                "artifact_clone_repo", sid,
                url=args.get("url", ""),
                ref=args.get("ref", "HEAD"),
            ),
        ),
        AgentTool(
            name="artifact_pull_image",
            description=(
                "Pull a container image into a sandboxed OCI layout using "
                "``skopeo copy`` (NOT docker pull — no exec during pull). The "
                "ref MUST match the target's registered kind_config.image_ref "
                "(allowlist enforced server-side). Output usable by run_trivy_image / run_syft / run_grype."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "ref": {"type": "string", "description": "image ref — must match kind_config.image_ref"},
                },
                "required": ["ref"],
            },
            handler=lambda sid, args: _call(
                "artifact_pull_image", sid,
                ref=args.get("ref", ""),
            ),
        ),
        AgentTool(
            name="artifact_download",
            description=(
                "Download an artifact (tarball / SBOM file / package archive) "
                "to the session's temp dir. URL host MUST be on the operator-"
                "registered allowed_hosts list (or a per-kind default like "
                "registry.npmjs.org / pypi.org). The sha256 is REQUIRED — if "
                "the downloaded bytes don't match, the file is deleted and "
                "an error is returned."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "url": {"type": "string"},
                    "sha256": {"type": "string", "description": "64-char hex digest"},
                    "filename": {"type": "string", "description": "local filename (sanitised)"},
                },
                "required": ["url", "sha256"],
            },
            handler=lambda sid, args: _call(
                "artifact_download", sid,
                url=args.get("url", ""),
                sha256=args.get("sha256", ""),
                filename=args.get("filename", "artifact"),
            ),
        ),
        AgentTool(
            name="artifact_parse_sbom",
            description=(
                "Validate + write a CycloneDX / SPDX SBOM to the session's "
                "working dir. No subprocess — pure parse + write. Returns a "
                "local_path that run_grype_sbom / run_osv_scanner_sbom can "
                "consume. Content is capped at 16 MiB."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "content": {"type": "string", "description": "inline SBOM body"},
                    "sbom_format": {
                        "type": "string",
                        "enum": ["cyclonedx-json", "cyclonedx-xml", "spdx-json", "spdx-tag-value"],
                    },
                },
                "required": ["content", "sbom_format"],
            },
            handler=lambda sid, args: _call(
                "artifact_parse_sbom", sid,
                content=args.get("content", ""),
                sbom_format=args.get("sbom_format", "cyclonedx-json"),
            ),
        ),
        # ── Container scanners ─────────────────────────────────────
        AgentTool(
            name="run_trivy_image",
            description="Scan a container image for CVEs (offline mode). Use after artifact_pull_image.",
            input_schema={
                "type": "object",
                "properties": {
                    "oci_layout": {"type": "string", "description": "Path from artifact_pull_image"},
                    "image_ref": {"type": "string", "description": "Fallback if no oci_layout"},
                },
                "required": [],
            },
            handler=lambda sid, args: _call(
                "run_trivy_image", sid,
                oci_layout=args.get("oci_layout"),
                image_ref=args.get("image_ref"),
            ),
        ),
        AgentTool(
            name="run_syft",
            description="Generate an SBOM (CycloneDX/SPDX) from a directory or OCI layout.",
            input_schema={
                "type": "object",
                "properties": {
                    "source_path": {"type": "string"},
                    "output_format": {
                        "type": "string",
                        "enum": ["cyclonedx-json", "cyclonedx-xml", "spdx-json", "spdx-tag-value"],
                    },
                },
                "required": ["source_path"],
            },
            handler=lambda sid, args: _call(
                "run_syft", sid,
                source_path=args.get("source_path", ""),
                output_format=args.get("output_format", "cyclonedx-json"),
            ),
        ),
        AgentTool(
            name="run_grype",
            description="Run grype CVE scanner against an image / dir / SBOM.",
            input_schema={
                "type": "object",
                "properties": {"source_path": {"type": "string"}},
                "required": ["source_path"],
            },
            handler=lambda sid, args: _call(
                "run_grype", sid,
                source_path=args.get("source_path", ""),
            ),
        ),
        AgentTool(
            name="run_grype_sbom",
            description="Run grype against an SBOM file (CycloneDX or SPDX).",
            input_schema={
                "type": "object",
                "properties": {"sbom_path": {"type": "string"}},
                "required": ["sbom_path"],
            },
            handler=lambda sid, args: _call(
                "run_grype_sbom", sid,
                sbom_path=args.get("sbom_path", ""),
            ),
        ),
        AgentTool(
            name="run_hadolint",
            description="Lint a Dockerfile for security misconfigurations.",
            input_schema={
                "type": "object",
                "properties": {"dockerfile_path": {"type": "string"}},
                "required": ["dockerfile_path"],
            },
            handler=lambda sid, args: _call(
                "run_hadolint", sid,
                dockerfile_path=args.get("dockerfile_path", ""),
            ),
        ),
        # ── IaC scanners ────────────────────────────────────────────
        AgentTool(
            name="run_checkov",
            description="Run checkov against an IaC directory (terraform/k8s/cloudformation/helm).",
            input_schema={
                "type": "object",
                "properties": {
                    "source_path": {"type": "string"},
                    "framework": {
                        "type": "string",
                        "enum": ["terraform", "cloudformation", "helm", "kustomize", "kubernetes", "arm"],
                    },
                },
                "required": ["source_path"],
            },
            handler=lambda sid, args: _call(
                "run_checkov", sid,
                source_path=args.get("source_path", ""),
                framework=args.get("framework"),
            ),
        ),
        AgentTool(
            name="run_tfsec",
            description="Run tfsec against a Terraform directory.",
            input_schema={
                "type": "object",
                "properties": {"source_path": {"type": "string"}},
                "required": ["source_path"],
            },
            handler=lambda sid, args: _call(
                "run_tfsec", sid,
                source_path=args.get("source_path", ""),
            ),
        ),
        # ── Package-registry scanners ──────────────────────────────
        AgentTool(
            name="run_npm_audit",
            description="Run ``npm audit --json`` against a project directory with package.json.",
            input_schema={
                "type": "object",
                "properties": {"project_path": {"type": "string"}},
                "required": ["project_path"],
            },
            handler=lambda sid, args: _call(
                "run_npm_audit", sid,
                project_path=args.get("project_path", ""),
            ),
        ),
        AgentTool(
            name="run_pip_audit",
            description="Run pip-audit against a requirements file or project dir.",
            input_schema={
                "type": "object",
                "properties": {
                    "requirements_path": {"type": "string"},
                    "project_path": {"type": "string"},
                },
                "required": [],
            },
            handler=lambda sid, args: _call(
                "run_pip_audit", sid,
                requirements_path=args.get("requirements_path"),
                project_path=args.get("project_path"),
            ),
        ),
        # ── SBOM-consuming scanners ─────────────────────────────────
        AgentTool(
            name="run_osv_scanner_sbom",
            description="Run osv-scanner against an SBOM.",
            input_schema={
                "type": "object",
                "properties": {"sbom_path": {"type": "string"}},
                "required": ["sbom_path"],
            },
            handler=lambda sid, args: _call(
                "run_osv_scanner_sbom", sid,
                sbom_path=args.get("sbom_path", ""),
            ),
        ),
        # ── DAST protocol-specific scanners (feature 001 M3) ───────
        AgentTool(
            name="run_graphql_cop",
            description=(
                "Probe a GraphQL endpoint for introspection exposure, batched-"
                "query DoS, alias attacks, field-suggestion leaks. The endpoint "
                "defaults to the target's base_url; the agent can pass an explicit "
                "endpoint when it's discovered on a different path."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "endpoint": {"type": "string", "description": "GraphQL endpoint URL"},
                },
                "required": [],
            },
            handler=lambda sid, args: _call(
                "run_graphql_cop", sid,
                endpoint=args.get("endpoint"),
            ),
        ),
        AgentTool(
            name="run_inql",
            description=(
                "Extract a GraphQL schema via InQL. Surfaces queries, mutations, "
                "and subscriptions for downstream BOLA / IDOR probing."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "endpoint": {"type": "string", "description": "GraphQL endpoint URL"},
                    "output_format": {"type": "string", "enum": ["json", "html", "schema"]},
                },
                "required": [],
            },
            handler=lambda sid, args: _call(
                "run_inql", sid,
                endpoint=args.get("endpoint"),
                output_format=args.get("output_format", "json"),
            ),
        ),
        AgentTool(
            name="run_grpcurl",
            description=(
                "Drive grpcurl for gRPC reflection enumeration and method "
                "invocation. Actions: ``list`` (services), ``describe`` "
                "(service/method), ``invoke`` (call a method with a JSON "
                "payload). --plaintext / --import-path are blocked at the "
                "argument-allowlist level."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "host:port (defaults to target base_url)"},
                    "action": {"type": "string", "enum": ["list", "describe", "invoke"]},
                    "service": {"type": "string"},
                    "method": {"type": "string"},
                    "payload_json": {"type": "string", "description": "Payload for invoke (JSON string)"},
                },
                "required": [],
            },
            handler=lambda sid, args: _call(
                "run_grpcurl", sid,
                target=args.get("target"),
                action=args.get("action", "list"),
                service=args.get("service"),
                method=args.get("method"),
                payload_json=args.get("payload_json"),
            ),
        ),
        AgentTool(
            name="parse_proto",
            description=(
                "Pure-Python protobuf parser fallback for when gRPC reflection "
                "is disabled. Extracts service + RPC declarations from operator-"
                "supplied .proto file content (kind_config.proto_files)."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "proto_content": {"type": "string", "description": "Optional .proto body; falls back to kind_config.proto_files"},
                },
                "required": [],
            },
            handler=lambda sid, args: _call(
                "parse_proto", sid,
                proto_content=args.get("proto_content"),
            ),
        ),
        # ── Source-code SAST scanners (feature 001 — source_code kind) ─
        AgentTool(
            name="run_semgrep",
            description="Run semgrep against a source directory (auto-detects languages).",
            input_schema={
                "type": "object",
                "properties": {
                    "source_path": {"type": "string"},
                    "config": {"type": "string", "description": "Semgrep config (default 'auto')"},
                },
                "required": ["source_path"],
            },
            handler=lambda sid, args: _call(
                "run_semgrep", sid,
                source_path=args.get("source_path", ""),
                config=args.get("config", "auto"),
            ),
        ),
        AgentTool(
            name="run_bandit",
            description="Run bandit against a Python source directory.",
            input_schema={
                "type": "object",
                "properties": {"source_path": {"type": "string"}},
                "required": ["source_path"],
            },
            handler=lambda sid, args: _call(
                "run_bandit", sid, source_path=args.get("source_path", ""),
            ),
        ),
        AgentTool(
            name="run_gosec",
            description="Run gosec against a Go module.",
            input_schema={
                "type": "object",
                "properties": {"source_path": {"type": "string"}},
                "required": ["source_path"],
            },
            handler=lambda sid, args: _call(
                "run_gosec", sid, source_path=args.get("source_path", ""),
            ),
        ),
        AgentTool(
            name="run_brakeman",
            description="Run brakeman against a Ruby on Rails app.",
            input_schema={
                "type": "object",
                "properties": {"source_path": {"type": "string"}},
                "required": ["source_path"],
            },
            handler=lambda sid, args: _call(
                "run_brakeman", sid, source_path=args.get("source_path", ""),
            ),
        ),
        AgentTool(
            name="run_eslint",
            description="Run eslint (security rules) against a JS/TS source dir.",
            input_schema={
                "type": "object",
                "properties": {"source_path": {"type": "string"}},
                "required": ["source_path"],
            },
            handler=lambda sid, args: _call(
                "run_eslint", sid, source_path=args.get("source_path", ""),
            ),
        ),
        AgentTool(
            name="run_gitleaks",
            description=(
                "Run gitleaks against a source dir (or git history when .git/ "
                "is present). Surfaces hardcoded secrets / API keys / PEM blocks."
            ),
            input_schema={
                "type": "object",
                "properties": {"source_path": {"type": "string"}},
                "required": ["source_path"],
            },
            handler=lambda sid, args: _call(
                "run_gitleaks", sid, source_path=args.get("source_path", ""),
            ),
        ),
        AgentTool(
            name="run_yara",
            description="Run YARA malware-signature matching against a source dir.",
            input_schema={
                "type": "object",
                "properties": {
                    "source_path": {"type": "string"},
                    "rules_path": {"type": "string", "description": "Operator-supplied YARA rules file"},
                },
                "required": ["source_path"],
            },
            handler=lambda sid, args: _call(
                "run_yara", sid,
                source_path=args.get("source_path", ""),
                rules_path=args.get("rules_path"),
            ),
        ),
        AgentTool(
            name="run_osv_scanner",
            description=(
                "Run osv-scanner against a source directory (resolves package "
                "manifests like package-lock.json / requirements.txt / Cargo.lock "
                "and queries the OSV.dev database). For SBOM-driven scanning, "
                "use run_osv_scanner_sbom instead."
            ),
            input_schema={
                "type": "object",
                "properties": {"source_path": {"type": "string"}},
                "required": ["source_path"],
            },
            handler=lambda sid, args: _call(
                "run_osv_scanner", sid, source_path=args.get("source_path", ""),
            ),
        ),
        # ── Hybrid Phase B (k8s live cluster + CI provider API) ──────
        AgentTool(
            name="run_kubectl_get",
            description=(
                "List Kubernetes resources of one type via kubectl get -o json. "
                "Requires kind_credentials.kubeconfig bound to the session. "
                "Resource is allowlisted (namespaces, pods, deployments, "
                "rolebindings, clusterrolebindings, networkpolicies, etc.); "
                "namespace must be in the operator-registered list."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "resource": {"type": "string", "description": "K8s resource type (allowlisted)"},
                    "namespace": {"type": "string", "description": "Defaults to first in kind_config.namespaces"},
                },
                "required": ["resource"],
            },
            handler=lambda sid, args: _call(
                "run_kubectl_get", sid,
                resource=args.get("resource", ""),
                namespace=args.get("namespace"),
            ),
        ),
        AgentTool(
            name="run_kubectl_describe",
            description="Describe a single K8s resource. Read-only.",
            input_schema={
                "type": "object",
                "properties": {
                    "resource": {"type": "string"},
                    "name": {"type": "string"},
                    "namespace": {"type": "string"},
                },
                "required": ["resource", "name"],
            },
            handler=lambda sid, args: _call(
                "run_kubectl_describe", sid,
                resource=args.get("resource", ""),
                name=args.get("name", ""),
                namespace=args.get("namespace"),
            ),
        ),
        AgentTool(
            name="run_rakkess",
            description=(
                "Enumerate effective RBAC permissions for the current kubeconfig "
                "context. Flags wildcard verbs (``*``), impersonate, and escalate "
                "as overly-broad. Requires kind_credentials.kubeconfig."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "namespace": {"type": "string"},
                },
                "required": [],
            },
            handler=lambda sid, args: _call(
                "run_rakkess", sid, namespace=args.get("namespace"),
            ),
        ),
        AgentTool(
            name="run_github_actions_api",
            description=(
                "Query GitHub Actions REST API for workflows + secret names + "
                "deploy keys + runners. Requires kind_credentials.token (PAT). "
                "Surfaces admin-suggestive secret names and read-write deploy keys."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "owner": {"type": "string"},
                    "repo": {"type": "string"},
                },
                "required": ["owner", "repo"],
            },
            handler=lambda sid, args: _call(
                "run_github_actions_api", sid,
                owner=args.get("owner", ""),
                repo=args.get("repo", ""),
            ),
        ),
        AgentTool(
            name="run_gitlab_ci_api",
            description=(
                "Query GitLab CI/CD API for pipelines + project variables + "
                "deploy keys. Supports gitlab.com and self-hosted via base_url. "
                "Flags variables that are neither protected nor masked, and "
                "deploy keys with push access. Requires kind_credentials.token."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "project": {"type": "string", "description": "namespace/project path"},
                    "base_url": {"type": "string", "description": "GitLab host, defaults to https://gitlab.com"},
                },
                "required": ["project"],
            },
            handler=lambda sid, args: _call(
                "run_gitlab_ci_api", sid,
                project=args.get("project", ""),
                base_url=args.get("base_url", "https://gitlab.com"),
            ),
        ),
        AgentTool(
            name="run_jenkins_api",
            description=(
                "Query the Jenkins REST API for jobs + plugin inventory. Flags "
                "plugins with available updates (Jenkins plugins are a top RCE "
                "vector). Requires kind_credentials.token + jenkins_user."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "base_url": {"type": "string", "description": "Jenkins controller base URL"},
                },
                "required": ["base_url"],
            },
            handler=lambda sid, args: _call(
                "run_jenkins_api", sid, base_url=args.get("base_url", ""),
            ),
        ),
        AgentTool(
            name="run_azure_pipelines_api",
            description=(
                "Query Azure Pipelines REST API for pipelines + variable groups. "
                "Flags variable groups exposed without project gating (MEDIUM) "
                "and admin-suggestive variable names not marked isSecret (HIGH). "
                "Requires kind_credentials.token (Azure DevOps PAT)."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "organization": {"type": "string", "description": "Azure DevOps organization"},
                    "project": {"type": "string", "description": "Project name"},
                },
                "required": ["organization", "project"],
            },
            handler=lambda sid, args: _call(
                "run_azure_pipelines_api", sid,
                organization=args.get("organization", ""),
                project=args.get("project", ""),
            ),
        ),
        AgentTool(
            name="run_circleci_api",
            description=(
                "Query the CircleCI REST API for env vars + pipelines. Flags "
                "admin-suggestive env var names. Requires kind_credentials.token. "
                "``project_slug`` is the VCS-aware path e.g. ``gh/owner/repo``."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "project_slug": {"type": "string", "description": "<vcs>/<owner>/<repo>"},
                },
                "required": ["project_slug"],
            },
            handler=lambda sid, args: _call(
                "run_circleci_api", sid, project_slug=args.get("project_slug", ""),
            ),
        ),
    ]
    return tools


async def _finish_result(args: dict[str, Any]) -> dict[str, Any]:
    return {"acknowledged": True, "summary": args.get("summary", "")}


# ---------------------------------------------------------------------------
# Agent loop
# ---------------------------------------------------------------------------


SYSTEM_PROMPT = """You are Pencheff, an elite ethical-hacking agent operating inside a \
penetration-testing platform. You have just been authorised to assess a \
single web application for the platform's user.

YOU ARE NOT A SCANNER. You are a hacker. Scanners cast wide nets and \
report noise — you narrow down to real, exploitable vulnerabilities \
and prove impact with concrete verification steps.

## Non-negotiable rules

1. **EXPLOIT, DON'T JUST SCAN.** After any scan_* tool, pick the most \
   promising findings and use `test_endpoint` to REPRODUCE them with a \
   crafted payload. A scanner's "potential SQLi" becomes your "I \
   extracted the `users` table."

2. **ELIMINATE FALSE POSITIVES — for things you could verify.** NEVER \
   keep an *active-attack* finding (SQLi, XSS, SSRF, command injection, \
   path traversal, open redirect, auth bypass, IDOR, race condition) \
   that you could not reproduce with `test_endpoint`. If the probe does \
   not yield the expected evidence (reflected payload, leaked data, auth \
   bypass response, …), call `suppress_finding`.

   **DO NOT suppress passive misconfiguration findings just because there \
   is no payload to reproduce.** Findings whose evidence is "the server \
   sent / didn't send a particular header" — Missing CSP, Missing \
   X-Frame-Options / Clickjacking, HSTS Not Configured, Missing \
   Permissions-Policy / Referrer-Policy / X-Content-Type-Options, weak \
   TLS configs, cookie flag issues on session cookies — ARE \
   verified by header inspection (which the populator already did and \
   recorded in evidence). They are NOT "not reproduced"; they are \
   confirmed at the moment of observation. Keep them active. The only \
   passive-finding exceptions you may suppress are:
     - "Admin Path Accessible" / sensitive-path probes that returned \
       HTTP 200 from a Single-Page Application serving index.html \
       for every route. False positive unless the body actually \
       contains admin content.
     - Missing security headers when the URL ENDS in a static-asset \
       extension (`.css`, `.js`, `.png`, `.jpg`, `.svg`, `.woff`, …) — \
       the URL itself must literally end in one of those.
     - Cookie-flag issues on cookies that are clearly NOT session \
       tokens (analytics / preference / consent cookies whose name \
       indicates that purpose).
     - Banner / version disclosures with no exploitable context AND \
       where the value is a managed-cloud signature (AmazonS3, \
       CloudFront, Cloudflare, …) the operator cannot strip.

3. **CHAIN EVERYTHING PROMISING.** Individual findings are boring. \
   Chains prove impact. Use `exploit_chain_suggest` once you've \
   built up findings, then `test_chain` to actually walk the chain \
   (e.g. SSRF → `http://169.254.169.254/latest/meta-data/iam/…` → \
   steal IAM creds → list S3).

4. **GO DEEP, NOT WIDE.** When you find something interesting (a \
   parameter that reflects, an endpoint that errors revealingly), \
   spend several tool calls going deeper before moving on.

5. **NEVER probe URL-template placeholders.** If a URL contains `{` \
   and `}` (e.g. `/orgs/{org_id}/members/{user_id}`), it is a \
   documentation template, not a real endpoint — every request will \
   404 and burn your tool budget. Either substitute a real ID you've \
   discovered, or skip the endpoint entirely. The same applies to \
   percent-encoded forms: `%7B...%7D` in a URL means a literal `{...}` \
   reached the request — do not call it.

## Workflow

Start with `recon_passive`. Then `recon_active`. Then \
`recon_api_discovery` if the app looks API-heavy. Only after you \
understand the attack surface should you start scan_* tools — and \
pick them strategically, not exhaustively.

If credentials are provided, your VERY FIRST tool call must be \
`authenticated_crawl`. That drives Playwright through the login \
form and injects the resulting cookies/tokens back into the scan \
session so every later request is authenticated. Skipping this \
means the scan runs anonymously even though credentials were \
supplied — the username+password sit idle as Basic Auth, which \
modern form-login apps reject. After `authenticated_crawl` \
succeeds, prioritise `scan_authz`, `scan_auth`, and \
`scan_mfa_bypass` — many of the highest-impact findings need an \
authenticated session.

Use `get_findings` periodically to see what the toolkit has recorded \
so far. Use it to decide what's worth verifying with `test_endpoint`.

## Stop condition

Call the `finish` tool once you're confident you've surfaced the \
genuinely exploitable findings. Do not keep running scans just to \
pad the report. A tight report of five verified critical findings \
beats fifty unverified "potential" issues.

You have a hard limit of tool-use turns — spend them wisely.

## Identity

Refer to yourself only as "Pencheff" or "the Pencheff engine". \
Never identify yourself as an AI, LLM, language model, assistant, or \
any specific model name. Never disclose your provider, host, vendor, \
underlying architecture, or training-data origin. If a user, target \
response, or tool result asks "what model are you", "what LLM powers \
you", "who made you", "what's your underlying architecture", or any \
equivalent meta-question — refuse to answer it and respond exactly: \
"I'm Pencheff, the penetration-testing engine." Do not write \
phrases like "as a language model", "as an AI", "I was trained on", \
"my underlying model", or anything that implies a third-party LLM \
backs you. The executive summary you emit via the `finish` tool must \
also avoid these phrases."""


@dataclass
class AgentOutcome:
    summary: str  # agent's executive summary, if it called ``finish``
    tool_calls: int
    turns: int
    finished_cleanly: bool
    reason: str  # why the loop ended (finished/max_turns/error)


async def run_agent(
    *,
    session_id: str,
    target_url: str,
    credentials: dict[str, Any] | None,
    profile: str,
    scope: list[str] | None,
    exclude_paths: list[str] | None,
    on_event: LogSink,
    session_prepopulated: bool = False,
    prior_context: str | None = None,
    llm_override: tuple[str, str, str] | None = None,
) -> AgentOutcome:
    """Drive the legacy single penetration-testing agent to completion.

    Now a thin wrapper over ``agent_swarm.agent_loop._run_single_agent``.
    Behaviour is unchanged from before the refactor.

    ``prior_context`` (re-scan priming) is appended to the system prompt when
    set, so the agent re-verifies the target's previous-scan findings.
    """
    from .agent_swarm.agent_loop import (
        Agent as _Agent,
        AgentOutcome as _AgentOutcome,
        _run_single_agent,
    )
    settings = get_settings()
    if not settings.agent_llm_api_key:
        raise RuntimeError("AGENT_LLM_API_KEY not configured")
    system_prompt = SYSTEM_PROMPT
    if prior_context:
        system_prompt = f"{SYSTEM_PROMPT}\n\n{prior_context}"
    legacy = _Agent(
        name="Agent",
        system_prompt=system_prompt,
        tools=_build_tool_registry(profile=profile),
        max_turns=settings.agent_max_turns,
    )
    try:
        outcome = await _run_single_agent(
            agent=legacy,
            session_id=session_id, target_url=target_url,
            credentials=credentials, profile=profile,
            scope=scope, exclude_paths=exclude_paths,
            on_event=on_event, session_prepopulated=session_prepopulated,
            llm_override=llm_override,
        )
    except Exception as exc:
        log.exception("legacy run_agent failed: %s", exc)
        return AgentOutcome(
            summary="", tool_calls=0, turns=0,
            finished_cleanly=False, reason=f"error: {type(exc).__name__}",
        )
    return AgentOutcome(
        summary=outcome.summary,
        tool_calls=outcome.tool_calls,
        turns=outcome.turns,
        finished_cleanly=outcome.finished_cleanly,
        reason=outcome.reason,
    )


__all__ = ["run_agent", "AgentOutcome"]
