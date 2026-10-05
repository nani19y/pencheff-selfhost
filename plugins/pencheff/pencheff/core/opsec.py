"""OPSEC noise tagging.

The source repo's ``_scope-guard.md`` mandates labeling every command:

    QUIET     passive only — DNS, WHOIS, certificate transparency, OSINT
    MODERATE  active scanning — TCP connects, HTTP requests, light enum
    LOUD      detection-triggering — vuln scans, brute force, exploitation

Pencheff carries the tag on every Finding so reports can show OPSEC
summaries, and the orchestrator can filter playbooks via ``--noise``.
"""

from __future__ import annotations

from typing import Literal

NoiseLevel = Literal["quiet", "moderate", "loud"]
LEVELS: tuple[NoiseLevel, ...] = ("quiet", "moderate", "loud")
ORDER = {n: i for i, n in enumerate(LEVELS)}


# Action → noise mapping. Used when an explicit tag is not provided.
_DEFAULT_TAGS: dict[str, NoiseLevel] = {
    # passive
    "recon_passive": "quiet",
    "osint": "quiet",
    "whois": "quiet",
    "dns": "quiet",
    "cert_transparency": "quiet",
    "wayback": "quiet",
    "threat_model": "quiet",
    "engagement_plan": "quiet",
    "stig_lookup": "quiet",
    "report": "quiet",
    "memory": "quiet",
    # active
    "recon_active": "moderate",
    "scan_pulse": "moderate",
    "scan_infrastructure": "moderate",
    "scan_api": "moderate",
    "scan_client_side": "moderate",
    "scan_authz": "moderate",
    "scan_oauth": "moderate",
    "scan_business_logic": "moderate",
    "scan_cloud": "moderate",
    "scan_websocket": "moderate",
    "scan_subdomain_takeover": "moderate",
    "scan_file_handling": "moderate",
    "test_endpoint": "moderate",
    "browser_crawl": "moderate",
    # loud
    "scan_injection": "loud",
    "scan_advanced": "loud",
    "scan_auth": "loud",
    "scan_mfa_bypass": "loud",
    "credential_test": "loud",
    "exploit_chain": "loud",
    "ad_kerberoast": "loud",
    "ad_secretsdump": "loud",
    "wireless_capture": "loud",
    "wireless_evil_twin": "loud",
}


def noise_level(action: str, default: NoiseLevel = "moderate") -> NoiseLevel:
    return _DEFAULT_TAGS.get(action, default)


def at_or_below(level: NoiseLevel, ceiling: NoiseLevel) -> bool:
    """True if ``level`` is no louder than ``ceiling``."""
    return ORDER[level] <= ORDER[ceiling]


def filter_for(ceiling: NoiseLevel | None, action: str, default: NoiseLevel = "moderate") -> bool:
    """Should this action run under the given noise ceiling?"""
    if ceiling is None:
        return True
    return at_or_below(noise_level(action, default), ceiling)
