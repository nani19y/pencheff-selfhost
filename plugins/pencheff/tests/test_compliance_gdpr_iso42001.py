"""GDPR + ISO/IEC 42001 LLM compliance mapping tests."""
from __future__ import annotations

import pytest

from pencheff.config import (
    EU_AI_ACT_MAP,
    GDPR_LLM_MAP,
    ISO_42001_LLM_MAP,
    MITRE_ATLAS_MAP,
    NIST_AI_RMF_MAP,
    OWASP_LLM_TOP_10,
    Severity,
)
from pencheff.core.findings import Finding


@pytest.mark.parametrize("category", list(OWASP_LLM_TOP_10.keys()))
def test_gdpr_map_covers_every_owasp_llm_category(category: str) -> None:
    refs = GDPR_LLM_MAP.get(category)
    assert refs and all(r.startswith("Art.") for r in refs), (
        f"GDPR_LLM_MAP missing or malformed for {category}: {refs!r}"
    )


@pytest.mark.parametrize("category", list(OWASP_LLM_TOP_10.keys()))
def test_iso_42001_map_covers_every_owasp_llm_category(category: str) -> None:
    refs = ISO_42001_LLM_MAP.get(category)
    assert refs and all(r.startswith("A.") for r in refs), (
        f"ISO_42001_LLM_MAP missing or malformed for {category}: {refs!r}"
    )


def _make_finding(*, category: str, owasp_category: str) -> Finding:
    return Finding(
        title=f"Test {owasp_category}",
        severity=Severity.HIGH,
        category=category,
        owasp_category=owasp_category,
        description="x",
        remediation="x",
        endpoint="https://example.test/llm",
    )


def test_finding_compliance_mapping_includes_gdpr_and_iso42001() -> None:
    f = _make_finding(category="prompt_injection", owasp_category="LLM01")
    mapping = f.compliance_mapping
    # Every existing AI / data-protection mapping should still be present.
    assert "MITRE ATLAS" in mapping
    assert "NIST AI RMF" in mapping
    assert "EU AI Act" in mapping
    # The two new mappings:
    assert "GDPR" in mapping
    assert "ISO/IEC 42001" in mapping
    # And concrete article / control references — not just empty lists.
    assert any("Art. 32" in ref for ref in mapping["GDPR"])
    assert any("A.6.2.4" in ref for ref in mapping["ISO/IEC 42001"])


def test_finding_compliance_mapping_skips_llm_frameworks_for_non_llm_findings() -> None:
    f = _make_finding(category="injection", owasp_category="A03")
    mapping = f.compliance_mapping
    # Non-LLM finding — LLM-only frameworks must NOT appear.
    for fw in ("MITRE ATLAS", "NIST AI RMF", "EU AI Act", "GDPR", "ISO/IEC 42001"):
        assert fw not in mapping, f"{fw} should not appear on non-LLM findings"


def test_api_service_compliance_map_mirrors_plugin_definitions() -> None:
    """The API service file mirrors the canonical maps verbatim.

    We compare on disk text rather than import the API package because
    the plugin and API ship as separate deployables; the test runs in
    the plugin's interpreter only.
    """
    from pathlib import Path
    api_file = (
        Path(__file__).resolve().parent.parent.parent.parent
        / "apps" / "api" / "pencheff_api" / "services" / "compliance.py"
    )
    text = api_file.read_text(encoding="utf-8")
    # Spot-check a marker article + control from each new map.
    assert "Art. 22 Automated Decision-Making" in text
    assert "A.6.2.4 Verification and Validation" in text
    # The LLM_FRAMEWORKS list must include the new keys so the API
    # rollup actually surfaces them.
    assert '"gdpr-llm"' in text
    assert '"iso-42001"' in text
