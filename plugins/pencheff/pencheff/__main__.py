"""Entry point for the ``pencheff`` CLI.

After ``pip install pencheff`` the package installer puts a ``pencheff``
console script on the user's ``PATH`` (declared in ``[project.scripts]``
in ``pyproject.toml``), so the canonical invocation is the bare command
— exactly like ``aws`` or ``kubectl``::

    pencheff                       # Start MCP server (stdio)
    pencheff --version             # Print the installed version
    pencheff scan --target URL     # Headless CI/CD scan
    pencheff map --target HOST     # Lightweight TCP port map
    pencheff webscan --target URL  # Web server exposure scan
    pencheff pulse --target URL    # Template-based detection scan
    pencheff scan --target URL --profile cicd --fail-on high
    pencheff history --target URL
    pencheff compare SESSION_A SESSION_B

The ``python -m pencheff`` form still works (this file remains a valid
``__main__`` module), but ``pencheff`` is the documented entry point.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from typing import Any


def _resolve_version() -> str:
    """Best-effort lookup of the installed package version.

    Falls back to ``"unknown"`` when the package metadata is not present
    (e.g. running from a source checkout that has never been installed).
    """
    try:
        from importlib.metadata import PackageNotFoundError, version as _v
    except ImportError:  # Python < 3.8 — not supported, but defensive.
        return "unknown"
    try:
        return _v("pencheff")
    except PackageNotFoundError:
        return "unknown"


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pencheff",
        description="Pencheff — AI-native penetration testing agent (MCP + CLI)",
    )
    parser.add_argument(
        "-V",
        "--version",
        action="version",
        version=f"pencheff {_resolve_version()}",
        help="Print the installed pencheff version and exit.",
    )
    sub = parser.add_subparsers(dest="command")

    # ── MCP server (default) ─────────────────────────────────────────
    sub.add_parser("serve", help="Start MCP server (default when no command given)")

    # ── LSP server (for VSCode / JetBrains / Neovim / Emacs) ─────────
    sub.add_parser(
        "lsp",
        help="Start the Pencheff Language Server (LSP over stdio). "
             "Editors connect to this server to surface scan findings as "
             "inline diagnostics.",
    )

    # ── Headless scan ────────────────────────────────────────────────
    scan_p = sub.add_parser("scan", help="Run a headless pentest scan")
    scan_p.add_argument("--target", required=True, help="Target URL")
    scan_p.add_argument(
        "--profile",
        default="standard",
        choices=["quick", "standard", "deep", "api-only", "compliance", "cicd"],
        help="Scan profile (default: standard)",
    )
    scan_p.add_argument(
        "--fail-on",
        default=None,
        choices=["info", "low", "medium", "high", "critical"],
        dest="fail_on",
        help="Exit non-zero if any finding meets or exceeds this severity",
    )
    scan_p.add_argument("--username", default=None, help="Target username")
    scan_p.add_argument("--password", default=None, help="Target password")
    scan_p.add_argument("--token", default=None, help="Bearer token for auth")
    scan_p.add_argument("--output", default=None, help="Output dir for reports")
    scan_p.add_argument(
        "--format",
        default="json",
        help="Report format(s) — comma-separated list of json|markdown|docx|csv",
    )
    scan_p.add_argument("--save-history", action="store_true", help="Save scan to history")
    # Engagement & Pulse template filters
    scan_p.add_argument(
        "--engagement-id", default=None,
        help="Tie this scan to a Pencheff engagement (cross-references, persistent state).",
    )
    scan_p.add_argument(
        "--pulse-templates", default=None,
        help="Comma-separated list of Pulse template paths to load alongside the default set.",
    )
    scan_p.add_argument(
        "--pulse-tags", default=None,
        help="Comma-separated list of Pulse tags to filter templates (e.g. exposure,api,cve).",
    )

    # ── Lightweight TCP mapper ───────────────────────────────────────
    map_p = sub.add_parser(
        "map",
        help="Run a lightweight TCP connect port map for authorized targets",
        description=(
            "Lightweight TCP connect scanner for authorized internal asset "
            "discovery. Supports hostnames, URLs, IP addresses, and small CIDRs."
        ),
    )
    map_p.add_argument(
        "--target",
        required=True,
        action="append",
        help="Target hostname/IP/URL/CIDR. Repeat or comma-separate for multiple targets.",
    )
    map_p.add_argument(
        "--ports",
        default="top-100",
        help="Ports to scan: top-100, top-1000, all, 22,80,443, or 1-1024.",
    )
    map_p.add_argument(
        "--all-ports",
        action="store_true",
        help="Scan all TCP ports from 1 through 65535. Overrides --ports.",
    )
    map_p.add_argument(
        "--format",
        default="table",
        choices=["table", "json", "csv", "xml"],
        help="Output format (default: table).",
    )
    map_p.add_argument(
        "--timeout",
        type=float,
        default=1.5,
        help="Per-port connection timeout in seconds (default: 1.5).",
    )
    map_p.add_argument(
        "--concurrency",
        type=int,
        default=100,
        help="Maximum simultaneous connection attempts (default: 100).",
    )
    map_p.add_argument(
        "--no-banners",
        action="store_true",
        help="Only report open ports; skip best-effort banner grabbing.",
    )
    map_p.add_argument(
        "-sS",
        "--stealth-scan",
        action="store_true",
        help=(
            "Use Pencheff's low-noise TCP connect mode. This is not raw SYN "
            "scanning; raw stealth/evasion scans are intentionally not built in."
        ),
    )
    map_p.add_argument(
        "-sU",
        "--udp-scan",
        action="store_true",
        help="Also run a small safe UDP probe set. Use --udp-ports to override the default top UDP list.",
    )
    map_p.add_argument(
        "--udp-ports",
        default="top",
        help="UDP ports to probe when -sU is enabled: top, 53,123,161, or ranges like 1-1024.",
    )
    map_p.add_argument(
        "-sV",
        "--version-detect",
        action="store_true",
        help="Run best-effort service/version detection from safe banners and protocol probes.",
    )
    map_p.add_argument(
        "-O",
        "--os-detect",
        action="store_true",
        help="Add passive OS guesses from service banners.",
    )
    map_p.add_argument(
        "--script-scan",
        action="store_true",
        help="Run safe built-in script-style checks against discovered open ports.",
    )
    map_p.add_argument(
        "--vuln-scan",
        action="store_true",
        help="Run safe exposure checks for risky open services.",
    )
    map_p.add_argument(
        "--traceroute",
        action="store_true",
        help="Run system traceroute/tracepath after port discovery when available.",
    )
    map_p.add_argument(
        "-A",
        "--aggressive",
        action="store_true",
        help="Bundle version detection, passive OS detection, script checks, and traceroute.",
    )
    map_p.add_argument(
        "-T",
        "--timing",
        type=int,
        default=3,
        choices=[0, 1, 2, 3, 4, 5],
        help="Timing profile from 0 (slowest) through 5 (fastest). Default: 3.",
    )
    for timing_level in range(6):
        map_p.add_argument(
            f"-T{timing_level}",
            action="store_const",
            const=timing_level,
            dest="timing",
            help=argparse.SUPPRESS,
        )

    # ── SQL injection assessor ───────────────────────────────────────
    sqli_p = sub.add_parser(
        "sqli",
        help="Run a non-destructive SQL injection assessment",
        description=(
            "First-party SQL injection assessor for authorized targets. "
            "Detects likely SQLi; does not dump data or attempt shell access."
        ),
    )
    sqli_p.add_argument("--url", default=None, help="Target URL with query parameters.")
    sqli_p.add_argument(
        "-r",
        "--request-file",
        default=None,
        help="Load a raw HTTP request from a file.",
    )
    sqli_p.add_argument(
        "--base-url",
        default=None,
        help="Base URL to resolve relative raw requests that do not include a Host header.",
    )
    sqli_p.add_argument(
        "-m",
        "--bulk-file",
        default=None,
        help="Scan targets from a text file: URL, or METHOD URL [body] per line.",
    )
    sqli_p.add_argument(
        "--burp-xml",
        default=None,
        help="Import targets from a Burp XML export.",
    )
    sqli_p.add_argument(
        "--crawl",
        default=None,
        help="Crawl a same-origin seed URL and assess discovered parameterized links/forms.",
    )
    sqli_p.add_argument(
        "--crawl-limit",
        type=int,
        default=25,
        help="Maximum pages to fetch when --crawl is used (default: 25).",
    )
    sqli_p.add_argument(
        "--method",
        default="GET",
        choices=["GET", "POST", "PUT", "PATCH"],
        help="HTTP method (default: GET).",
    )
    sqli_p.add_argument(
        "--data",
        default=None,
        help="URL-encoded request body for POST/PUT/PATCH, e.g. 'id=1&name=test'.",
    )
    sqli_p.add_argument(
        "--param",
        action="append",
        help="Parameter to test. Repeat for multiple. Defaults to all query/body params.",
    )
    sqli_p.add_argument(
        "--technique",
        action="append",
        choices=["all", "error", "boolean", "time", "union", "stacked"],
        help="Technique to use. Repeatable. Default: all safe techniques.",
    )
    sqli_p.add_argument(
        "--profile",
        default="standard",
        choices=["quick", "standard", "deep"],
        help="Assessment profile (default: standard).",
    )
    sqli_p.add_argument(
        "--level",
        type=int,
        choices=[1, 2, 3, 4, 5],
        default=None,
        help="Payload breadth from 1 through 5. Defaults to the selected profile.",
    )
    sqli_p.add_argument(
        "--risk",
        type=int,
        choices=[1, 2],
        default=None,
        help="Risk level: 1 avoids stacked probes; 2 enables safe stacked-query detection.",
    )
    sqli_p.add_argument(
        "--tamper",
        action="append",
        choices=["space2comment", "randomcase", "equaltolike"],
        help="Apply a first-party payload transform. Repeatable.",
    )
    sqli_p.add_argument(
        "--header",
        action="append",
        help="Extra HTTP header as 'Name: value'. Repeat for multiple.",
    )
    sqli_p.add_argument("--cookie", default=None, help="Cookie header value to send.")
    sqli_p.add_argument("--proxy", default=None, help="HTTP proxy URL, e.g. http://127.0.0.1:8080.")
    sqli_p.add_argument("--csrf-token", default=None, help="Hidden form token name to refresh before probes.")
    sqli_p.add_argument("--anti-cache", action="store_true", help="Add no-cache headers and a nonce query parameter.")
    sqli_p.add_argument("--traffic-log", default=None, help="Write JSONL request/response evidence to this path.")
    sqli_p.add_argument("--cache-dir", default=".pencheff/sqli_sessions", help="Directory for cached SQLi assessments.")
    sqli_p.add_argument("--resume", action="store_true", help="Reuse cached assessment results when available.")
    sqli_p.add_argument("--wizard", action="store_true", help="Prompt interactively for a single target.")
    sqli_p.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=1,
        help="Increase evidence verbosity. Use -vv for headers, -vvv for response samples.",
    )
    sqli_p.add_argument(
        "--timeout",
        type=float,
        default=8.0,
        help="Per-request timeout in seconds (default: 8).",
    )
    sqli_p.add_argument(
        "--delay",
        type=int,
        default=2,
        help="Time-check delay in seconds, capped to 1-5 (default: 2).",
    )
    sqli_p.add_argument(
        "--verify-ssl",
        action="store_true",
        help="Verify TLS certificates.",
    )
    sqli_p.add_argument(
        "--format",
        default="table",
        choices=["table", "json", "csv"],
        help="Output format (default: table).",
    )

    # ── Web server exposure scanner ─────────────────────────────────
    web_p = sub.add_parser(
        "webscan",
        help="Run a non-destructive web server exposure assessment",
        description=(
            "First-party web server assessor for authorized targets. Checks "
            "headers, cookies, methods, common exposed files, default pages, "
            "directory listings, and disclosure patterns."
        ),
    )
    web_p.add_argument("--target", action="append", help="Target URL or hostname. Repeatable.")
    web_p.add_argument("--targets-file", default=None, help="Targets file: URL, host, or 'host port' per line.")
    web_p.add_argument(
        "--profile",
        default="standard",
        choices=["quick", "standard", "deep"],
        help="Path/check breadth (default: standard).",
    )
    web_p.add_argument(
        "--path",
        action="append",
        help="Additional path to check, e.g. /admin/. Repeatable.",
    )
    web_p.add_argument("--paths-file", default=None, help="File containing extra paths, one per line.")
    web_p.add_argument("--check-db", action="append", help="Additional JSON check database to load. Repeatable.")
    web_p.add_argument("--tag", action="append", help="Only run checks with this tag. Repeatable.")
    web_p.add_argument(
        "--tuning",
        action="append",
        choices=["headers", "cookies", "methods", "files", "cgi", "apps", "versions", "disclosure", "admin", "backup"],
        help="Run checks in selected tuning categories. Repeatable.",
    )
    web_p.add_argument("--auth-profile", default=None, help="JSON file with workflow-safe auth headers/cookie.")
    web_p.add_argument("--suppressions", action="append", help="JSON suppression/allowlist file. Repeatable.")
    web_p.add_argument("--header", action="append", help="Extra HTTP header as 'Name: value'. Repeatable.")
    web_p.add_argument("--cookie", default=None, help="Cookie header value to send.")
    web_p.add_argument("--proxy", default=None, help="HTTP proxy URL, e.g. http://127.0.0.1:8080.")
    web_p.add_argument("--traffic-log", default=None, help="Write JSONL request/response evidence to this path.")
    web_p.add_argument("--timeout", type=float, default=8.0, help="Per-request timeout in seconds (default: 8).")
    web_p.add_argument("--concurrency", type=int, default=10, help="Maximum concurrent safe path checks (default: 10).")
    web_p.add_argument("--delay", type=float, default=0.0, help="Delay between requests in seconds (default: 0).")
    web_p.add_argument(
        "--request-encoding",
        default="none",
        choices=["none", "url", "double-url"],
        help="Compatibility path encoding mode. This is not a stealth mode.",
    )
    web_p.add_argument("--update-checks", action="store_true", help="Install/update the user webscan check database.")
    web_p.add_argument("--update-source", default=None, help="Optional local path or URL for check database update.")
    web_p.add_argument("--update-destination", default=None, help="Destination for updated check database.")
    web_p.add_argument("--verify-ssl", action="store_true", help="Verify TLS certificates.")
    web_p.add_argument(
        "--format",
        default="table",
        choices=["table", "json", "csv", "xml", "html"],
        help="Output format (default: table).",
    )

    # ── Template-based detection scanner ────────────────────────────
    pulse_p = sub.add_parser(
        "pulse",
        help="Run first-party template-based detection checks",
        description="Safe Pulse template scanner for authorized targets.",
    )
    pulse_p.add_argument("--target", action="append", help="Target URL or hostname. Repeatable.")
    pulse_p.add_argument("--targets-file", default=None, help="Targets file, one URL/host per line.")
    pulse_p.add_argument("-t", "--templates", action="append", help="Template file or directory. Repeatable.")
    pulse_p.add_argument("--workflow", default=None, help="Workflow JSON selecting tags/template_ids.")
    pulse_p.add_argument("--template-id", action="append", help="Only run this template id. Repeatable.")
    pulse_p.add_argument("--exclude-id", action="append", help="Exclude this template id. Repeatable.")
    pulse_p.add_argument("--tag", action="append", help="Only run templates with this tag. Repeatable.")
    pulse_p.add_argument("--severity", action="append", choices=["critical", "high", "medium", "low", "info"], help="Severity to include. Repeatable.")
    pulse_p.add_argument("--profile", default="standard", choices=["quick", "standard", "deep", "cicd"], help="Severity profile (default: standard).")
    pulse_p.add_argument("--auth-profile", default=None, help="JSON file with safe auth headers/cookie.")
    pulse_p.add_argument("--header", action="append", help="Extra HTTP header as 'Name: value'. Repeatable.")
    pulse_p.add_argument("--cookie", default=None, help="Cookie header value to send.")
    pulse_p.add_argument("--proxy", default=None, help="HTTP proxy URL.")
    pulse_p.add_argument("--timeout", type=float, default=8.0, help="Per-request timeout in seconds.")
    pulse_p.add_argument("--concurrency", type=int, default=20, help="Maximum concurrent requests.")
    pulse_p.add_argument("--rate-limit", type=float, default=0.0, help="Delay before each request in seconds.")
    pulse_p.add_argument("--verify-ssl", action="store_true", help="Verify TLS certificates.")
    pulse_p.add_argument("--ignore-file", default=None, help="Additional .pulse-ignore file with template id globs.")
    pulse_p.add_argument("--require-signed", action="store_true", help="Only run templates carrying signature metadata.")
    pulse_p.add_argument("--trusted-author", action="append", help="Only run templates from this author. Repeatable.")
    pulse_p.add_argument("--cache-dir", default=None, help="Directory for Pulse cache/resume files.")
    pulse_p.add_argument("--resume", action="store_true", help="Reuse cached target results when available.")
    pulse_p.add_argument("--retries", type=int, default=0, help="HTTP retry count per request (default: 0).")
    pulse_p.add_argument("--max-host-errors", type=int, default=20, help="Stop a template after this many errors.")
    pulse_p.add_argument("--stats-file", default=None, help="Write aggregate scan stats as JSON.")
    pulse_p.add_argument("--interactsh-url", default=None, help="Safe OAST placeholder value for templates; callbacks are not polled.")
    pulse_p.add_argument("--headless", action="store_true", help="Enable optional safe Playwright DOM templates when installed.")
    pulse_p.add_argument("--update-templates", action="store_true", help="Install/update user Pulse templates.")
    pulse_p.add_argument("--update-source", default=None, help="Optional local path or URL for template update.")
    pulse_p.add_argument("--update-destination", default=None, help="Destination directory for updated templates.")
    pulse_p.add_argument(
        "--format",
        default="table",
        choices=["table", "json", "jsonl", "csv", "xml", "html"],
        help="Output format (default: table).",
    )

    # ── Pentest-AI agents integration: per-specialist + orchestrator ────
    # See plugins/pencheff/docs/PLAYBOOKS.md for the full catalog.

    eng_p = sub.add_parser(
        "engage", help="Run the full 7-phase swarm orchestration",
        description="Drive engagement_planner → recon → vuln → exploit → postex → detect → report.",
    )
    eng_p.add_argument("--target", required=True)
    eng_p.add_argument("--scope", default=None, help="Path to scope YAML/JSON.")
    eng_p.add_argument("--engagement-id", default=None,
                       help="Reuse an existing engagement DB row.")
    eng_p.add_argument("--client", default="local", help="Client name for new engagement.")
    eng_p.add_argument("--type", default="external", dest="engagement_type",
                       choices=["external", "internal", "webapp", "cloud", "wireless", "mobile"])
    eng_p.add_argument("--tier", type=int, default=2, choices=[1, 2])
    eng_p.add_argument("--noise", default=None, choices=["quiet", "moderate", "loud"],
                       help="Filter playbooks by OPSEC noise ceiling.")
    eng_p.add_argument("--phases", default=None,
                       help="Comma-separated subset of: scope,recon,vuln,exploit,postex,detect,report")
    eng_p.add_argument("--no-parallel-recon", action="store_true",
                       help="Run recon strands sequentially.")
    eng_p.add_argument("--no-subdomains", action="store_true",
                       help="Skip the subdomain fan-out after recon.")
    eng_p.add_argument("--max-subdomains", type=int, default=10,
                       help="Maximum discovered subdomains to fan out into (default: 10).")
    eng_p.add_argument("--port-range", default="top-1000",
                       help="Port range for recon_active: top-100, top-1000, all, "
                            "1-65535, or 22,80,443 (default: top-1000).")
    eng_p.add_argument("--output", default=None, help="Output dir for report exports.")
    eng_p.add_argument("--format", default="json,docx,csv",
                       help="Report formats: json,docx,csv (comma-separated).")
    eng_p.add_argument("--no-db", action="store_true", help="Skip engagement DB persistence.")

    # `swarm` is registered later as an alias of `engage` via main() dispatch.

    # Per-specialist commands
    plan_p = sub.add_parser("plan", help="engagement_planner (Tier 1)")
    plan_p.add_argument("--target", required=True)
    plan_p.add_argument("--type", default="external", dest="engagement_type")
    plan_p.add_argument("--scope", default=None)

    osint_p = sub.add_parser("osint", help="osint_collector (Tier 1)")
    osint_p.add_argument("--target", required=True)

    recon_p = sub.add_parser("recon", help="recon_advisor (Tier 2)")
    recon_p.add_argument("--target", required=True)
    recon_p.add_argument("--scope", required=True)
    recon_p.add_argument("--engagement-id", default=None)

    vuln_p = sub.add_parser("vuln", help="vuln_scanner (Tier 2)")
    vuln_p.add_argument("--target", required=True)
    vuln_p.add_argument("--scope", required=True)
    vuln_p.add_argument("--engagement-id", default=None)
    vuln_p.add_argument("--no-external", action="store_true")

    web_h = sub.add_parser("webhunt", help="web_hunter (Tier 2)")
    web_h.add_argument("--target", required=True)
    web_h.add_argument("--scope", required=True)
    web_h.add_argument("--wordlist", default=None)
    web_h.add_argument("--engagement-id", default=None)

    api_p = sub.add_parser("api", help="api_security (Tier 2)")
    api_p.add_argument("--target", required=True)
    api_p.add_argument("--scope", required=True)
    api_p.add_argument("--spec", default=None, help="OpenAPI/Swagger/Postman path")
    api_p.add_argument("--engagement-id", default=None)

    chain_p = sub.add_parser("exploit-chain", help="exploit_chainer (Tier 2)")
    chain_p.add_argument("--target", required=True)
    chain_p.add_argument("--scope", required=True)
    chain_p.add_argument("--engagement-id", default=None)

    poc_p = sub.add_parser("poc", help="poc_validator (Tier 2)")
    poc_p.add_argument("--target", required=True)
    poc_p.add_argument("--scope", required=True)
    poc_p.add_argument("--finding", default=None, dest="finding_id")
    poc_p.add_argument("--engagement-id", default=None)

    privesc_p = sub.add_parser("privesc", help="privesc_advisor (Tier 1)")
    privesc_p.add_argument("--peas-output", default=None,
                           help="Path to linpeas/winpeas output to triage.")

    cloud_p = sub.add_parser("cloud", help="cloud_security (Tier 2)")
    cloud_p.add_argument("--target", required=True)
    cloud_p.add_argument("--scope", required=True)
    cloud_p.add_argument("--provider", default="aws", choices=["aws", "azure", "gcp"])
    cloud_p.add_argument("--engagement-id", default=None)

    ad_p = sub.add_parser("ad", help="ad_attacker (Tier 2)")
    ad_p.add_argument("op", choices=["bloodhound", "secretsdump", "kerberoast",
                                      "asreproast", "adcs", "smb"])
    ad_p.add_argument("--scope", required=True)
    ad_p.add_argument("--domain", default=None)
    ad_p.add_argument("--user", default=None)
    ad_p.add_argument("--password", default=None)
    ad_p.add_argument("--dc", default=None)
    ad_p.add_argument("--target", default=None, help="For 'smb' op")
    ad_p.add_argument("--users", default=None, help="Userlist for asreproast")
    ad_p.add_argument("--engagement-id", default=None)

    wifi_p = sub.add_parser("wireless", help="wireless_pentester (Tier 2)")
    wifi_p.add_argument("op", choices=["capture", "crack", "pmkid", "evil-twin"])
    wifi_p.add_argument("--scope", required=True)
    wifi_p.add_argument("--interface", default="wlan0")
    wifi_p.add_argument("--bssid", default=None)
    wifi_p.add_argument("--channel", type=int, default=None)
    wifi_p.add_argument("--cap", default=None)
    wifi_p.add_argument("--wordlist", default="/usr/share/wordlists/rockyou.txt")
    wifi_p.add_argument("--ssid", default="free-wifi")

    mob_p = sub.add_parser("mobile", help="mobile_pentester (Tier 2)")
    mob_p.add_argument("mode", choices=["static", "mobsf", "ios"])
    mob_p.add_argument("--scope", required=True)
    mob_p.add_argument("--apk", default=None)
    mob_p.add_argument("--ipa", default=None)

    fr_p = sub.add_parser("forensics", help="forensics_analyst")
    fr_p.add_argument("mode", choices=["memory", "timeline", "disk", "advisor"])
    fr_p.add_argument("--image", default=None)
    fr_p.add_argument("--evidence-dir", default=None)

    mw_p = sub.add_parser("malware", help="malware_analyst")
    mw_p.add_argument("mode", choices=["static", "yara", "clam", "floss", "advisor"])
    mw_p.add_argument("--sample", default=None)

    ci_p = sub.add_parser("cicd", help="cicd_redteam (Tier 1)")
    ci_p.add_argument("--workflow", default=None,
                      help="Path to workflow YAML (file or directory).")
    ci_p.add_argument("--provider", default="github", choices=["github", "gitlab", "jenkins"])

    biz_p = sub.add_parser("bizlogic", help="bizlogic_hunter (Tier 2)")
    biz_p.add_argument("--target", required=True)
    biz_p.add_argument("--scope", required=True)
    biz_p.add_argument("--engagement-id", default=None)

    bb_p = sub.add_parser("bugbounty", help="bug_bounty (Tier 2)")
    bb_p.add_argument("--target", required=True)
    bb_p.add_argument("--scope", required=True)
    bb_p.add_argument("--platform", default="h1", choices=["h1", "bc"])
    bb_p.add_argument("--engagement-id", default=None)

    se_p = sub.add_parser("socialeng", help="social_engineer (Tier 1)")
    se_p.add_argument("--pretext", default="spear-phish")
    se_p.add_argument("--var", action="append", default=[],
                      help="key=value template variables; repeatable")

    ctf_p = sub.add_parser("ctf", help="ctf_solver (Tier 2)")
    ctf_p.add_argument("--target", required=True)
    ctf_p.add_argument("--scope", required=True)

    tm_p = sub.add_parser("threatmodel", help="threat_modeler (Tier 1)")
    tm_p.add_argument("--scope", required=True)
    tm_p.add_argument("--method", default="stride", choices=["stride", "dread"])

    det_p = sub.add_parser("detect", help="detection_engineer (Tier 1)")
    det_p.add_argument("--findings", default=None,
                       help="JSON file containing findings list.")
    det_p.add_argument("--format", default="sigma", choices=["sigma", "spl", "kql"])
    det_p.add_argument("--target", default="TARGET")

    stig_p = sub.add_parser("stig", help="stig_analyst (Tier 1)")
    stig_p.add_argument("--asset", default="webapp")
    stig_p.add_argument("--id", default=None, dest="stig_id")

    rep_p = sub.add_parser("report", help="report_generator (Tier 1)")
    rep_p.add_argument("--engagement-id", required=True)
    rep_p.add_argument("--format", default="json,docx,csv,md")
    rep_p.add_argument("--output", default=None)

    cred_p = sub.add_parser("credtest", help="credential_tester (Tier 2)")
    cred_p.add_argument("--target", required=True)
    cred_p.add_argument("--scope", required=True)
    cred_p.add_argument("--hashes", default=None, help="Path to hashes file")
    cred_p.add_argument("--hash-mode", default="0")
    cred_p.add_argument("--users", default=None)
    cred_p.add_argument("--wordlist", default="/usr/share/wordlists/rockyou.txt")
    cred_p.add_argument("--hydra-target", default=None)
    cred_p.add_argument("--hydra-service", default=None)

    # Engagement DB
    edb_p = sub.add_parser("engagement", help="Manage the engagement DB.")
    edb_sub = edb_p.add_subparsers(dest="edb_command")
    edb_init = edb_sub.add_parser("init")
    edb_init.add_argument("--client", required=True)
    edb_init.add_argument("--type", default="external", dest="engagement_type")
    edb_init.add_argument("--scope", default=None, help="Path to scope file (stored).")
    edb_init.add_argument("--notes", default="")
    edb_sub.add_parser("list")
    edb_show = edb_sub.add_parser("show")
    edb_show.add_argument("engagement_id")
    edb_log = edb_sub.add_parser("log")
    edb_log.add_argument("engagement_id")
    edb_log.add_argument("--agent", required=True)
    edb_log.add_argument("--action", required=True)
    edb_log.add_argument("--summary", default="")
    edb_log.add_argument("--detail", default="")
    edb_ho = edb_sub.add_parser("handoff")
    edb_ho.add_argument("engagement_id")
    edb_ho.add_argument("--from", required=True, dest="from_agent")
    edb_ho.add_argument("--to", required=True, dest="to_agent")
    edb_ho.add_argument("--payload", default="")
    edb_ex = edb_sub.add_parser("export")
    edb_ex.add_argument("engagement_id")
    edb_ex.add_argument("--format", default="md", choices=["md", "json"])
    edb_ch = edb_sub.add_parser("chains")
    edb_ch.add_argument("engagement_id")
    edb_sub.add_parser("migrate")

    # Memory subcommand (mirrors source's /memory slash command)
    mem_p = sub.add_parser("memory", help="Project memory file (PROJECT_MEMORY.md).")
    mem_sub = mem_p.add_subparsers(dest="mem_command")
    mem_up = mem_sub.add_parser("update")
    mem_up.add_argument("--message", default="(no message)")
    mem_sub.add_parser("show")

    # ── Deterministic workflows (Phase 4 — no LLM) ───────────────────
    auto_p = sub.add_parser(
        "auto-pentest",
        help="Run the full deterministic engagement (bug-bounty + CVE intel + red-team narrative). No LLM required.",
    )
    auto_p.add_argument("--target", required=True)
    auto_p.add_argument("--intensity", default="default", choices=["stealth", "default", "aggressive"])
    auto_p.add_argument("--output", default=None, help="Write JSON result to this path (default: stdout)")

    bb_det_p = sub.add_parser(
        "bb-recon",
        help="Deterministic bug-bounty workflow (subdomain → live filter → crawl → param → scan → triage).",
    )
    bb_det_p.add_argument("--target", required=True)
    bb_det_p.add_argument("--intensity", default="default", choices=["stealth", "default", "aggressive"])
    bb_det_p.add_argument("--output", default=None)

    ctf_det_p = sub.add_parser(
        "ctf-solve",
        help="Deterministic CTF auto-solver (file path or text blob). No model in the loop.",
    )
    ctf_det_p.add_argument("--challenge", required=True, help="File path or quoted text blob")
    ctf_det_p.add_argument("--output", default=None)

    cve_p = sub.add_parser(
        "cve-correlate",
        help="Enrich findings with linked CVEs from the offline overlay + live NVD/CIRCL feed.",
    )
    cve_p.add_argument("--findings", required=True, help="Path to JSON file with findings list")
    cve_p.add_argument("--output", default=None)

    rt_det_p = sub.add_parser(
        "redteam-narrative",
        help="Build a MITRE-aligned red-team narrative from existing findings.",
    )
    rt_det_p.add_argument("--findings", required=True, help="Path to JSON file with findings list")
    rt_det_p.add_argument("--output", default=None)

    pol_p = sub.add_parser(
        "explain-policy",
        help="Print the active decision-table policy YAML for transparency / audit.",
    )
    pol_p.add_argument("policy", choices=[
        "tool_selection", "parameters", "chains", "fallbacks",
        "throttle", "cve_correlation", "confidence",
    ])

    wf_p = sub.add_parser(
        "run-workflow",
        help="Generic deterministic-workflow dispatcher.",
    )
    wf_p.add_argument("name", choices=["auto_pentest", "bug_bounty", "ctf_solve", "cve_intel", "red_team"])
    wf_p.add_argument("--target", default=None)
    wf_p.add_argument("--challenge", default=None)
    wf_p.add_argument("--findings", default=None)
    wf_p.add_argument("--intensity", default="default")
    wf_p.add_argument("--output", default=None)

    # ── History ──────────────────────────────────────────────────────
    hist_p = sub.add_parser("history", help="List saved scan history")
    hist_p.add_argument("--target", default=None, help="Filter by target URL")

    # ── Compare ──────────────────────────────────────────────────────
    cmp_p = sub.add_parser("compare", help="Compare two saved scans")
    cmp_p.add_argument("session_a", help="Baseline session ID")
    cmp_p.add_argument("session_b", help="Current session ID")

    # ── LLM red-team ────────────────────────────────────────────────
    rt_p = sub.add_parser(
        "llm-redteam",
        help="Run an LLM red-team scan against a chat endpoint (CI-friendly)",
    )
    rt_p.add_argument("--target", required=True, help="Chat completions endpoint URL")
    rt_p.add_argument(
        "--provider",
        default="openai-chat",
        choices=[
            "openai-chat", "custom", "executable",
            "websocket", "bedrock", "vertex", "azure-openai", "browser",
        ],
    )
    rt_p.add_argument("--model", default=None)
    rt_p.add_argument("--system-prompt", default=None, dest="system_prompt")
    rt_p.add_argument(
        "--header", action="append", default=[],
        metavar="KEY=VALUE",
        help="Auth header (repeatable). Example: --header 'Authorization=Bearer sk-...'",
    )
    rt_p.add_argument(
        "--profile", default="standard",
        choices=["quick", "standard", "deep"],
        help="Red-team profile (default: standard)",
    )
    rt_p.add_argument("--strategies", default=None,
                      help="Comma-separated strategy ids (e.g. base64,jailbreak,crescendo)")
    rt_p.add_argument("--datasets", default=None,
                      help="Comma-separated dataset ids (e.g. harmbench,donotanswer,aegis,unsafebench,xstest)")
    rt_p.add_argument("--guardrails", default=None,
                      help="Comma-separated guardrail ids (e.g. pii,secrets,unsafe-code)")
    rt_p.add_argument(
        "--iterative", default=None, dest="iterative",
        choices=["static", "pair", "tap", "goat", "hydra"],
        help="Iterative search mode. static = deterministic expansion (no attacker LLM). "
             "pair / tap / goat / hydra all require --attacker-endpoint.",
    )
    rt_p.add_argument(
        "--plugins", default=None, dest="plugins",
        help="Comma-separated add-on plugin packs to enable. Default = all "
             "(bias,rag,mcp,coding-agent). Pass an explicit list to opt out.",
    )
    rt_p.add_argument("--attacker-provider", default=None, dest="attacker_provider",
                      choices=["openai-chat", "executable"])
    rt_p.add_argument("--attacker-endpoint", default=None, dest="attacker_endpoint")
    rt_p.add_argument("--attacker-model", default=None, dest="attacker_model")
    rt_p.add_argument(
        "--attacker-header", action="append", default=[], dest="attacker_header",
        metavar="KEY=VALUE",
        help="Auth header for the attacker LLM (repeatable).",
    )
    rt_p.add_argument("--judge-endpoint", default=None, dest="judge_endpoint")
    rt_p.add_argument("--judge-model", default=None, dest="judge_model")
    rt_p.add_argument(
        "--judge-provider", default="openai-chat", dest="judge_provider",
        choices=["openai-chat", "executable", "llama-guard", "granite-guardian", "openai-moderation"],
    )
    rt_p.add_argument("--max-cost-usd", default=None, type=float, dest="max_cost_usd")
    rt_p.add_argument("--max-rps", default=None, type=float, dest="max_rps")
    rt_p.add_argument("--retries", default=1, type=int)
    rt_p.add_argument("--timeout-s", default=30, type=int, dest="timeout_s")
    rt_p.add_argument("--concurrency", default=5, type=int)
    rt_p.add_argument("--max-payloads", default=None, type=int, dest="max_payloads")
    rt_p.add_argument(
        "--fail-on", default=None, dest="fail_on",
        choices=["info", "low", "medium", "high", "critical"],
        help="Exit non-zero if any finding meets or exceeds this severity",
    )
    rt_p.add_argument(
        "--output-format", default="markdown", dest="output_format",
        choices=["markdown", "json", "junit", "csv", "html", "prometheus"],
    )
    rt_p.add_argument("--output-file", default=None, dest="output_file",
                      help="Write the rendered output here (default: stdout)")
    rt_p.add_argument("--compare-to", default=None, dest="compare_to",
                      help="Path to a JSON file from a previous --output-format json run; "
                           "compute regressions/fixes against it before exiting")

    return parser


async def _run_scan(args: argparse.Namespace) -> int:
    """Execute a headless scan and return exit code."""
    from pencheff.config import SCAN_PROFILES, Severity
    from pencheff.core.session import create_session
    from pencheff.core.http_client import PencheffHTTPClient

    profile = SCAN_PROFILES.get(args.profile, SCAN_PROFILES["standard"])
    fail_on = args.fail_on or profile.get("fail_on")

    creds: dict[str, Any] = {}
    if args.username:
        creds["username"] = args.username
    if args.password:
        creds["password"] = args.password
    if args.token:
        creds["token"] = args.token

    session = create_session(
        target_url=args.target,
        credentials=creds or None,
        depth=profile["depth"],
    )

    print(f"[pencheff] scan started  target={args.target}  profile={args.profile}  session={session.id}")

    # SPA-fallback fingerprint. Probe two random non-existent paths so
    # brute-force / admin-path / OAuth modules can tell "real 200 OK" from
    # "SPA index.html catch-all". Without this, scanning a single-page app
    # fires HIGH false positives for every admin path it tries.
    try:
        from pencheff.core.spa_detector import establish_spa_fingerprint
        _fp_http = PencheffHTTPClient(session)
        try:
            await establish_spa_fingerprint(session, _fp_http)
        finally:
            try:
                await _fp_http.close()
            except Exception:
                pass
    except Exception as exc:  # noqa: BLE001 — never block the scan
        print(f"[pencheff] SPA fingerprint probe failed: {exc}", file=sys.stderr)

    # Import all scan functions from server lazily to avoid circular imports
    from pencheff import server as _srv  # noqa: F401 — registers tools on mcp
    from pencheff import server_enterprise as _srv_ent  # noqa: F401 — enterprise tools

    _MODULE_FN_MAP = {
        "recon_passive": _srv.recon_passive,
        "recon_active": _srv.recon_active,
        "recon_api_discovery": _srv.recon_api_discovery,
        "scan_waf": _srv.scan_waf,
        "scan_injection": _srv.scan_injection,
        "scan_client_side": _srv.scan_client_side,
        "scan_auth": _srv.scan_auth,
        "scan_mfa_bypass": _srv.scan_mfa_bypass,
        "scan_oauth": _srv.scan_oauth,
        "scan_authz": _srv.scan_authz,
        "scan_infrastructure": _srv.scan_infrastructure,
        "scan_api": _srv.scan_api,
        "scan_business_logic": _srv.scan_business_logic,
        "scan_cloud": _srv.scan_cloud,
        "scan_file_handling": _srv.scan_file_handling,
        "scan_advanced": _srv.scan_advanced,
        "scan_pulse": _srv.scan_pulse,
        "scan_websocket": _srv.scan_websocket,
        "scan_subdomain_takeover": _srv.scan_subdomain_takeover,
        "exploit_chain_suggest": _srv.exploit_chain_suggest,
        "generate_report": _srv.generate_report,
    }

    for module_name in profile["modules"]:
        fn = _MODULE_FN_MAP.get(module_name)
        if not fn:
            continue
        print(f"[pencheff] running {module_name}...")
        try:
            if module_name == "scan_pulse":
                result = await fn(
                    session_id=session.id,
                    extra_template_paths=(args.pulse_templates.split(",") if args.pulse_templates else None),
                    tags=(args.pulse_tags.split(",") if args.pulse_tags else None),
                )
            else:
                result = await fn(session_id=session.id)
            new = result.get("new_findings", 0)
            total = result.get("total_findings", 0)
            if new:
                print(f"[pencheff]   {module_name}: +{new} new findings (total: {total})")
        except Exception as e:
            print(f"[pencheff]   {module_name}: ERROR — {e}", file=sys.stderr)

    # Save history if requested
    if getattr(args, "save_history", False):
        from pencheff.core.scan_history import save_scan
        path = save_scan(session)
        print(f"[pencheff] scan saved to {path}")

    # Export report
    summary = session.findings.summary()
    findings_list = [f.to_dict() for f in session.findings.get_all()]

    if args.output or args.format in ("docx", "csv"):
        try:
            from pencheff.reporting.exporter import export_docx, export_csv, export_json
            if args.format == "docx":
                export_docx(session, output_dir=args.output)
            elif args.format == "csv":
                export_csv(session, output_dir=args.output)
            else:
                export_json(session, output_dir=args.output)
        except Exception as e:
            print(f"[pencheff] export error: {e}", file=sys.stderr)
    else:
        # Print JSON summary to stdout
        output = {
            "session_id": session.id,
            "target": args.target,
            "profile": args.profile,
            "summary": summary,
            "total_findings": session.findings.count,
            "findings": findings_list,
        }
        print(json.dumps(output, indent=2))

    print(f"\n[pencheff] scan complete — {session.findings.count} findings")
    for sev, count in sorted(summary.items(), key=lambda x: x[0]):
        if count:
            print(f"  {sev}: {count}")

    # Fail-on logic
    if fail_on:
        _SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        threshold = _SEVERITY_ORDER.get(fail_on, 0)
        for f in session.findings.get_all():
            if _SEVERITY_ORDER.get(f.severity.value, 0) >= threshold:
                print(
                    f"\n[pencheff] FAIL — found {f.severity.value} severity finding: {f.title}",
                    file=sys.stderr,
                )
                return 1

    return 0


async def _run_deterministic_workflow(args: argparse.Namespace) -> int:
    """Dispatch one of the deterministic workflows added in Phase 4."""
    from pencheff.workflows import get_workflow

    cmd_to_workflow = {
        "auto-pentest": "auto_pentest",
        "bb-recon": "bug_bounty",
        "ctf-solve": "ctf_solve",
        "cve-correlate": "cve_intel",
        "redteam-narrative": "red_team",
        "run-workflow": getattr(args, "name", None),
    }
    workflow_name = cmd_to_workflow.get(args.command)
    if not workflow_name:
        print(f"[pencheff] unknown workflow command: {args.command}", file=sys.stderr)
        return 2

    fn = get_workflow(workflow_name)

    kwargs: dict[str, Any] = {}
    if getattr(args, "target", None):
        kwargs["target"] = args.target
    if getattr(args, "intensity", None):
        kwargs["intensity"] = args.intensity
    if getattr(args, "challenge", None):
        kwargs["challenge"] = args.challenge
    if getattr(args, "findings", None):
        # Load JSON findings file.
        from pathlib import Path as _Path
        kwargs["findings"] = json.loads(_Path(args.findings).read_text())

    # Workflows that take "target" as the first positional arg.
    if workflow_name in ("auto_pentest", "bug_bounty"):
        positional = kwargs.pop("target", None)
        if not positional:
            print("[pencheff] --target is required for this workflow", file=sys.stderr)
            return 2
        result = await fn(positional, **kwargs)
    elif workflow_name == "ctf_solve":
        positional = kwargs.pop("challenge", None)
        if not positional:
            print("[pencheff] --challenge is required for ctf-solve", file=sys.stderr)
            return 2
        result = await fn(positional, **kwargs)
    else:  # cve_intel, red_team — keyword-only
        result = await fn(**kwargs)

    payload = json.dumps(result, indent=2, default=str)
    out_path = getattr(args, "output", None)
    if out_path:
        from pathlib import Path as _Path
        _Path(out_path).write_text(payload)
        print(f"[pencheff] wrote {out_path}")
    else:
        print(payload)
    return 0


def main() -> None:
    # Initialise the plugin OTel pipeline regardless of subcommand. Most
    # CLI paths (map, sqli, webscan, pulse, deterministic workflows,
    # agent specialists via cli_runners) don't import server.py, so the
    # init at the top of server.py only fires for ``pencheff`` /
    # ``pencheff serve``. Calling it here covers everything else; the
    # bootstrap is idempotent so the double-call from ``serve`` is safe.
    try:
        from pencheff.observability import init_plugin_observability
        init_plugin_observability("pencheff-cli")
    except Exception:
        pass

    parser = _build_parser()
    args = parser.parse_args()

    if args.command in (None, "serve"):
        from pencheff.server import mcp, select_mcp_transport
        from pencheff import server_enterprise  # noqa: F401 — registers enterprise tools
        from pencheff import server_playbooks  # noqa: F401 — registers playbook & engagement tools
        from pencheff import server_webapp  # noqa: F401 — registers parity tools
        mcp.run(transport=select_mcp_transport())
        return

    if args.command == "lsp":
        from pencheff.lsp.server import run as lsp_run
        sys.exit(lsp_run())

    if args.command == "scan":
        exit_code = asyncio.run(_run_scan(args))
        sys.exit(exit_code)

    if args.command == "map":
        from pencheff.core.netmap import run_cli
        exit_code = asyncio.run(run_cli(args))
        sys.exit(exit_code)

    if args.command == "sqli":
        from pencheff.core.sqlprobe import run_cli
        exit_code = asyncio.run(run_cli(args))
        sys.exit(exit_code)

    if args.command == "webscan":
        from pencheff.core.webscan import run_cli
        exit_code = asyncio.run(run_cli(args))
        sys.exit(exit_code)

    if args.command == "pulse":
        from pencheff.core.pulse import run_cli
        exit_code = asyncio.run(run_cli(args))
        sys.exit(exit_code)

    if args.command == "history":
        from pencheff.core.scan_history import list_scans
        scans = list_scans(args.target)
        print(json.dumps(scans, indent=2))
        return

    # ── Deterministic workflow dispatch ──────────────────────────────
    if args.command in ("auto-pentest", "bb-recon", "ctf-solve", "cve-correlate",
                        "redteam-narrative", "run-workflow"):
        sys.exit(asyncio.run(_run_deterministic_workflow(args)))

    if args.command == "explain-policy":
        from pencheff.core.orchestrator.policies import load_policies
        pol = load_policies(reload=True)
        print(json.dumps(getattr(pol, args.policy), indent=2))
        return

    if args.command == "compare":
        from pencheff.core.scan_history import compare_scans
        result = compare_scans(args.session_a, args.session_b)
        print(json.dumps(result, indent=2))
        return

    if args.command == "llm-redteam":
        from pencheff.cli.llm_redteam import cmd_llm_redteam
        sys.exit(cmd_llm_redteam(args))

    # ── Pentest-AI agents subcommands ────────────────────────────────
    from pencheff import cli_runners as _cr
    _DISPATCH = {
        "engage": _cr.run_engage,
        "swarm": _cr.run_engage,             # alias
        "plan": _cr.run_plan,
        "osint": _cr.run_osint,
        "recon": _cr.run_recon,
        "vuln": _cr.run_vuln,
        "webhunt": _cr.run_webhunt,
        "api": _cr.run_api,
        "exploit-chain": _cr.run_exploit_chain,
        "poc": _cr.run_poc,
        "privesc": _cr.run_privesc,
        "cloud": _cr.run_cloud,
        "ad": _cr.run_ad,
        "wireless": _cr.run_wireless,
        "mobile": _cr.run_mobile,
        "forensics": _cr.run_forensics,
        "malware": _cr.run_malware,
        "cicd": _cr.run_cicd,
        "bizlogic": _cr.run_bizlogic,
        "bugbounty": _cr.run_bugbounty,
        "socialeng": _cr.run_socialeng,
        "ctf": _cr.run_ctf,
        "threatmodel": _cr.run_threatmodel,
        "detect": _cr.run_detect,
        "stig": _cr.run_stig,
        "report": _cr.run_report,
        "credtest": _cr.run_credtest,
        "engagement": _cr.run_engagement,
        "memory": _cr.run_memory,
    }
    fn = _DISPATCH.get(args.command)
    if fn:
        sys.exit(asyncio.run(fn(args)))

    parser.print_help()


if __name__ == "__main__":
    main()
