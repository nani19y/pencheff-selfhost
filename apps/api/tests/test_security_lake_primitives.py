from __future__ import annotations

from pencheff_api.services.security_lake.primitives import (
    LakeContext,
    severity_id,
    status_id,
    build_metadata,
    build_enrichments,
    build_unmapped,
    fingerprint,
    base_event,
    CATEGORY_FINDINGS,
)
from pencheff_api.services.security_lake.validation import validate_ocsf


def test_severity_id_maps_pencheff_scale():
    assert severity_id("info") == 1
    assert severity_id("low") == 2
    assert severity_id("medium") == 3
    assert severity_id("high") == 4
    assert severity_id("critical") == 5
    assert severity_id("CRITICAL") == 5     # case-insensitive
    assert severity_id("bogus") == 0        # unknown
    assert severity_id(None) == 0
    assert severity_id("") == 0


def test_status_id_from_state():
    assert status_id(verification_status="unverified", suppressed=False) == 1   # New
    assert status_id(verification_status="true_positive", suppressed=False) == 2  # In Progress
    assert status_id(verification_status="unverified", suppressed=True) == 3      # Suppressed
    assert status_id(verification_status="fixed", suppressed=False) == 4          # Resolved
    assert status_id(verification_status="fixed", suppressed=True) == 3   # suppression wins


def test_build_metadata_pins_version_and_product():
    md = build_metadata()
    assert md["version"] == "1.3.0"
    assert md["product"]["name"] == "Pencheff"


def test_build_enrichments_emits_epss_and_kev():
    enr = build_enrichments(epss=0.42, kev=True)
    by = {e["name"]: e for e in enr}
    assert by["epss"]["value"] == "0.42"
    assert by["epss"]["data"] == {"epss": 0.42}
    assert by["kev"]["value"] == "True"
    assert build_enrichments(epss=None, kev=None) == []


def test_build_unmapped_drops_none_values():
    um = build_unmapped(reachability="reachable", risk_score=88.0,
                         ssvc_decision=None, ai_triage=None)
    assert um == {"reachability": "reachable", "risk_score": 88.0}


def test_fingerprint_is_stable_and_distinguishing():
    a = fingerprint(org_id="o1", asset_id="r1", source="sast",
                    rule_or_cve="py.sqli", location="app.py:10-12")
    b = fingerprint(org_id="o1", asset_id="r1", source="sast",
                    rule_or_cve="py.sqli", location="app.py:10-12")
    c = fingerprint(org_id="o1", asset_id="r1", source="sast",
                    rule_or_cve="py.sqli", location="app.py:99-99")
    assert a == b           # deterministic
    assert a != c           # location-sensitive
    assert len(a) == 64     # sha256 hex


def test_lake_context_holds_scope_and_time():
    ctx = LakeContext(org_id="o1", asset_id="r1", source="sast",
                      time_ms=1_700_000_000_000, is_new=True)
    assert ctx.org_id == "o1"
    assert CATEGORY_FINDINGS == 2


def test_base_event_skeleton_and_validates_as_detection_finding():
    ev = base_event(
        class_uid=2004,           # Detection Finding validates with just base + finding_info
        activity_id=1,
        ctx=LakeContext(org_id="o1", asset_id="r1", source="runtime",
                        time_ms=1_700_000_000_000, is_new=True),
        finding_info={"title": "X", "uid": "fp1"},
        sev_id=4,
        stat_id=1,
    )
    assert ev["category_uid"] == 2
    assert ev["class_uid"] == 2004
    assert ev["type_uid"] == 2004 * 100 + 1
    assert ev["metadata"]["version"] == "1.3.0"
    assert ev["finding_info"]["uid"] == "fp1"
    validate_ocsf(ev)  # must not raise


def test_base_event_for_vuln_class_has_skeleton_but_no_vulns_yet():
    # base_event builds only the shared skeleton; class-specific required fields
    # (e.g. vulnerabilities for 2002) are added by the per-source mappers.
    ev = base_event(
        class_uid=2002, activity_id=2,
        ctx=LakeContext(org_id="o1", asset_id="r1", source="sast",
                        time_ms=1_700_000_000_000, is_new=False),
        finding_info={"title": "Y", "uid": "fp2"}, sev_id=3, stat_id=2,
    )
    assert ev["type_uid"] == 2002 * 100 + 2
    assert "vulnerabilities" not in ev   # mapper's job, not base_event's
