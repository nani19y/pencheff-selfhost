"""Finding data model, CVSS scoring, and deduplication."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pencheff.config import (
    CVSS_SEVERITY,
    EU_AI_ACT_MAP,
    GDPR_LLM_MAP,
    HIPAA_MAP,
    ISO27001_MAP,
    ISO_42001_LLM_MAP,
    MITRE_ATLAS_MAP,
    NIST_MAP,
    NIST_AI_RMF_MAP,
    OWASP_LLM_TOP_10,
    OWASP_MOBILE_TOP_10,
    OWASP_TOP_10,
    PCI_DSS_MAP,
    SOC2_MAP,
    Severity,
    VerificationStatus,
)


@dataclass
class Evidence:
    """Proof of a vulnerability — request/response pair."""

    request_method: str
    request_url: str
    request_headers: dict[str, str] = field(default_factory=dict)
    request_body: str | None = None
    response_status: int | None = None
    response_headers: dict[str, str] = field(default_factory=dict)
    response_body_snippet: str | None = None
    description: str = ""
    # Optional structured payload that lets the fix-proposer build a
    # deterministic patch without involving an LLM. Shape varies by source:
    #   SCA / pip-audit / npm-audit:
    #     {"tool": "osv"|"pip-audit"|"npm-audit", "ecosystem": "PyPI",
    #      "package": "requests", "current_version": "2.30.0",
    #      "fix_version": "2.32.4", "manifest_path": "requirements.txt"}
    #   Semgrep autofix:
    #     {"kind": "text_replace", "fix": "...", "start_line": ..., ...}
    autofix: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        d = {
            "request": f"{self.request_method} {self.request_url}",
            "response_status": self.response_status,
            "description": self.description,
        }
        if self.request_body:
            d["request_body"] = self.request_body[:500]
        if self.response_body_snippet:
            d["response_snippet"] = self.response_body_snippet[:500]
        return d


class SuppressReason(str, Enum):
    ACCEPTED_RISK = "accepted_risk"
    WONT_FIX = "wont_fix"
    FALSE_POSITIVE = "false_positive"
    DUPLICATE = "duplicate"
    OUT_OF_SCOPE = "out_of_scope"


@dataclass
class Finding:
    """A single vulnerability finding."""

    title: str
    severity: Severity
    category: str
    owasp_category: str  # e.g. "A03"
    description: str
    remediation: str
    endpoint: str
    parameter: str | None = None
    cvss_vector: str = ""
    cvss_score: float = 0.0
    evidence: list[Evidence] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    cwe_id: str | None = None
    mitre_id: list[str] = field(default_factory=list)
    noise: str = "moderate"  # quiet | moderate | loud — OPSEC tag
    verification_status: VerificationStatus = VerificationStatus.UNVERIFIED
    verification_notes: str = ""
    suppressed: bool = False
    suppress_reason: SuppressReason | None = None
    suppress_notes: str = ""
    suppressed_at: datetime | None = None
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    discovered_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    # Arbitrary metadata dict for orchestrator tags (e.g. {"discovered_by_agent": "InjectionAgent"}).
    # Not part of the core pentest model; used by the agent_swarm merge step.
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def owasp_name(self) -> str:
        if self.owasp_category.startswith("LLM"):
            return OWASP_LLM_TOP_10.get(self.owasp_category, "Unknown")
        if self.owasp_category.startswith("M"):
            return OWASP_MOBILE_TOP_10.get(self.owasp_category, "Unknown")
        return OWASP_TOP_10.get(self.owasp_category, "Unknown")

    @property
    def compliance_mapping(self) -> dict[str, list[str]]:
        result: dict[str, list[str]] = {}
        pci = PCI_DSS_MAP.get(self.category)
        if pci:
            result["PCI-DSS"] = pci
        nist = NIST_MAP.get(self.category)
        if nist:
            result["NIST-800-53"] = nist
        soc2 = SOC2_MAP.get(self.category)
        if soc2:
            result["SOC2"] = soc2
        iso = ISO27001_MAP.get(self.category)
        if iso:
            result["ISO27001"] = iso
        hipaa = HIPAA_MAP.get(self.category)
        if hipaa:
            result["HIPAA"] = hipaa
        if self.owasp_category.startswith("LLM"):
            atlas = MITRE_ATLAS_MAP.get(self.owasp_category)
            if atlas:
                result["MITRE ATLAS"] = atlas
            ai_rmf = NIST_AI_RMF_MAP.get(self.owasp_category)
            if ai_rmf:
                result["NIST AI RMF"] = ai_rmf
            eu_ai = EU_AI_ACT_MAP.get(self.owasp_category)
            if eu_ai:
                result["EU AI Act"] = eu_ai
            gdpr = GDPR_LLM_MAP.get(self.owasp_category)
            if gdpr:
                result["GDPR"] = gdpr
            iso42001 = ISO_42001_LLM_MAP.get(self.owasp_category)
            if iso42001:
                result["ISO/IEC 42001"] = iso42001
        result["OWASP"] = [f"{self.owasp_category}: {self.owasp_name}"]
        return result

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "id": self.id,
            "title": self.title,
            "severity": self.severity.value,
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "category": self.category,
            "owasp": f"{self.owasp_category}: {self.owasp_name}",
            "endpoint": self.endpoint,
            "parameter": self.parameter,
            "description": self.description,
            "evidence": [e.to_dict() for e in self.evidence],
            "remediation": self.remediation,
            "references": self.references,
            "cwe": self.cwe_id,
            "mitre": self.mitre_id,
            "noise": self.noise,
            "compliance": self.compliance_mapping,
            "verification_status": self.verification_status.value,
            "verification_notes": self.verification_notes,
            "suppressed": self.suppressed,
            "discovered_at": self.discovered_at.isoformat(),
            "metadata": dict(self.metadata),
        }
        if self.suppressed:
            d["suppress_reason"] = self.suppress_reason.value if self.suppress_reason else None
            d["suppress_notes"] = self.suppress_notes
            d["suppressed_at"] = self.suppressed_at.isoformat() if self.suppressed_at else None
        return d


def severity_from_cvss(score: float) -> Severity:
    if score >= 9.0:
        return Severity.CRITICAL
    elif score >= 7.0:
        return Severity.HIGH
    elif score >= 4.0:
        return Severity.MEDIUM
    elif score >= 0.1:
        return Severity.LOW
    return Severity.INFO


class FindingsDB:
    """Collection of findings with deduplication.

    Two dedup modes apply, depending on the finding's category:

      * **Site-wide categories** (``misconfiguration``, ``crypto``,
        ``info_disclosure``, ``compliance``) — same title across
        multiple endpoints represents the *same* underlying issue (a
        deployment-wide config). Subsequent additions are merged into
        the first finding's evidence list so the spread is preserved
        but the dashboard shows one row instead of N.
      * **Endpoint-specific categories** (``injection``, ``xss``,
        ``auth``, ``authz``, ``ssrf``, ``csrf``, ``idor``,
        ``business_logic``, ``api``, ``file_handling``, …) — each
        endpoint+parameter combo is its own attack surface, so we
        keep the existing strict per-endpoint dedup.
    """

    # Categories where the same title across multiple endpoints is the
    # SAME underlying issue (it's a config that affects the whole site).
    _SITE_WIDE_CATEGORIES: frozenset[str] = frozenset({
        "misconfiguration", "crypto", "info_disclosure", "compliance",
    })

    def __init__(self):
        self._findings: list[Finding] = []
        self._dedup_keys: set[str] = set()

    def _dedup_key(self, f: Finding) -> str:
        if (f.category or "") in self._SITE_WIDE_CATEGORIES:
            # Site-wide — collapse across endpoints/parameters.
            return f"site|{f.category}|{f.title}"
        return f"{f.endpoint}|{f.parameter}|{f.category}|{f.title}"

    def _find_by_key(self, key: str) -> "Finding | None":
        for f in self._findings:
            if self._dedup_key(f) == key:
                return f
        return None

    def _merge_evidence(self, existing: "Finding", incoming: "Finding") -> None:
        """Fold an incoming duplicate into ``existing``.

        Strategy:
          * Append every Evidence row from ``incoming`` whose
            ``request_url`` isn't already represented on ``existing``.
          * If ``incoming`` has a different ``endpoint`` than
            ``existing`` and that URL isn't already in evidence, add a
            synthetic Evidence row noting the additional endpoint so
            the UI's "Affects N endpoints" badge stays accurate.
        """
        existing_urls = {
            (ev.request_url or "")
            for ev in (existing.evidence or [])
            if isinstance(ev, Evidence)
        }
        merged: list[Evidence] = list(existing.evidence or [])
        for ev in incoming.evidence or []:
            if not isinstance(ev, Evidence):
                continue
            url = ev.request_url or ""
            if url and url in existing_urls:
                continue
            existing_urls.add(url)
            merged.append(ev)
        if incoming.endpoint and incoming.endpoint not in existing_urls:
            merged.append(Evidence(
                request_method="OBSERVED",
                request_url=incoming.endpoint,
                description=(
                    f"Same site-wide issue also observed at "
                    f"{incoming.endpoint}"
                ),
            ))
        existing.evidence = merged

    def add(self, finding: Finding) -> bool:
        """Add a finding.

        Returns True if a new finding was inserted, False if the
        finding was a duplicate. For site-wide categories, duplicates
        are merged into the existing finding's evidence list (so the
        spread is preserved) but the function still returns False.
        """
        key = self._dedup_key(finding)
        if key in self._dedup_keys:
            existing = self._find_by_key(key)
            if existing is not None and existing is not finding:
                self._merge_evidence(existing, finding)
            return False
        self._dedup_keys.add(key)
        self._findings.append(finding)
        return True

    def add_force(self, finding: "Finding") -> None:
        """Append a finding bypassing dedup. Used by the agent_swarm
        orchestrator's merge step to copy findings between sessions.
        Internal-ish: the dedup bypass is intentional because
        cross-session merges should keep duplicates if they were
        legitimately discovered by different agents."""
        self._findings.append(finding)
        self._dedup_keys.add(self._dedup_key(finding))

    def add_many(self, findings: list[Finding]) -> int:
        """Add multiple findings. Returns count of new (non-duplicate) findings."""
        return sum(1 for f in findings if self.add(f))

    def get_all(
        self,
        severity: Severity | None = None,
        category: str | None = None,
        owasp_category: str | None = None,
        include_suppressed: bool = False,
    ) -> list[Finding]:
        results = self._findings
        if not include_suppressed:
            results = [f for f in results if not f.suppressed]
        if severity:
            results = [f for f in results if f.severity == severity]
        if category:
            results = [f for f in results if f.category == category]
        if owasp_category:
            results = [f for f in results if f.owasp_category == owasp_category]
        return sorted(results, key=lambda f: f.cvss_score, reverse=True)

    def get_by_id(self, finding_id: str) -> "Finding | None":
        for f in self._findings:
            if f.id == finding_id:
                return f
        return None

    def suppress(
        self,
        finding_id: str,
        reason: str,
        notes: str = "",
    ) -> bool:
        """Suppress a finding. Returns False if not found."""
        f = self.get_by_id(finding_id)
        if not f:
            return False
        f.suppressed = True
        f.suppress_reason = SuppressReason(reason)
        f.suppress_notes = notes
        f.suppressed_at = datetime.now(timezone.utc)
        return True

    def unsuppress(self, finding_id: str) -> bool:
        """Remove suppression from a finding."""
        f = self.get_by_id(finding_id)
        if not f:
            return False
        f.suppressed = False
        f.suppress_reason = None
        f.suppress_notes = ""
        f.suppressed_at = None
        return True

    @property
    def count(self) -> int:
        return sum(1 for f in self._findings if not f.suppressed)

    @property
    def total_count(self) -> int:
        return len(self._findings)

    def summary(self) -> dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for f in self._findings:
            if not f.suppressed:
                counts[f.severity.value] += 1
        counts["suppressed"] = sum(1 for f in self._findings if f.suppressed)
        return counts
