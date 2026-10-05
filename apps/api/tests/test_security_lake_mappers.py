from __future__ import annotations

from types import SimpleNamespace

import pytest

from pencheff_api.services.security_lake import map_finding, validate_ocsf
from pencheff_api.services.security_lake.primitives import LakeContext
from pencheff_api.services.security_lake.mappers.sast import map_sast
from pencheff_api.services.security_lake.mappers.sca import map_sca
from pencheff_api.services.security_lake.mappers.secrets import map_secret
from pencheff_api.services.security_lake.mappers.iac import map_iac
from pencheff_api.services.security_lake.mappers.dast import map_dast
from pencheff_api.services.security_lake.mappers.runtime import map_runtime


def _ctx(source):
    return LakeContext(org_id="o1", asset_id="r1", source=source,
                       time_ms=1_700_000_000_000, is_new=True)


SAST_ROW = {"scanner": "semgrep", "rule_id": "py.sqli", "severity": "high",
            "title": "SQL injection", "description": "tainted", "file_path": "app/db.py",
            "line_start": 10, "line_end": 12, "code_snippet": "execute(f'..')",
            "cve": None, "package": None, "installed_version": None,
            "fixed_version": None, "raw": {"cwe": "CWE-89"}}
SCA_ROW = {"scanner": "osv", "rule_id": None, "severity": "critical", "title": "lodash",
           "description": "CVE-2020-8203", "file_path": "package-lock.json",
           "line_start": None, "line_end": None, "code_snippet": None,
           "cve": "CVE-2020-8203", "package": "lodash", "installed_version": "4.17.15",
           "fixed_version": "4.17.19", "raw": {}}
SECRET_ROW = {"scanner": "gitleaks", "rule_id": "aws-key", "severity": "high",
              "title": "AWS key", "description": "hardcoded", "file_path": "prod.env",
              "line_start": 4, "line_end": 4, "code_snippet": "AWS=..", "cve": None,
              "package": None, "installed_version": None, "fixed_version": None, "raw": {}}
IAC_ROW = {"scanner": "checkov", "rule_id": "CKV_AWS_20", "severity": "medium",
           "title": "S3 public", "description": "public acl", "file_path": "s3.tf",
           "line_start": 1, "line_end": 8, "code_snippet": None, "cve": None,
           "package": None, "installed_version": None, "fixed_version": None, "raw": {}}
RUNTIME_SPAN = {"detection_type": "prompt_injection", "severity": "critical",
                "title": "Injection blocked", "description": "injected instr",
                "span_id": "s1", "trace_id": "t1"}


def _dast_row():
    return SimpleNamespace(severity="high", cvss_score=7.5, cvss_vector="AV:N",
                           title="Reflected XSS", category="xss", cwe_id="CWE-79",
                           owasp_category="A03", endpoint="/search", parameter="q",
                           description="reflected", verification_status="true_positive",
                           suppressed=False, risk_score=72.0, epss=0.1, kev=False,
                           ssvc_decision="attend", reachability="exploited")


def test_map_sast_valid_vuln_finding_with_affected_code():
    ev = map_sast(SAST_ROW, _ctx("sast"))
    assert ev["class_uid"] == 2002
    assert ev["severity_id"] == 4
    code = ev["vulnerabilities"][0]["affected_code"][0]
    assert code["file"]["path"] == "app/db.py"
    assert code["start_line"] == 10 and code["end_line"] == 12
    assert ev["vulnerabilities"][0]["cwe"]["uid"] == "CWE-89"
    assert len(ev["finding_info"]["uid"]) == 64
    validate_ocsf(ev)


def test_map_sast_without_cwe_falls_back():
    row = {**SAST_ROW, "raw": {}}
    ev = map_sast(row, _ctx("sast"))
    assert ev["vulnerabilities"][0]["cwe"]["uid"] == "NVD-CWE-noinfo"
    validate_ocsf(ev)


def test_map_sca_valid_with_cve_and_package():
    ev = map_sca(SCA_ROW, _ctx("sca"))
    vuln = ev["vulnerabilities"][0]
    assert vuln["cve"]["uid"] == "CVE-2020-8203"
    pkg = vuln["affected_packages"][0]
    assert pkg["name"] == "lodash" and pkg["version"] == "4.17.15"
    assert pkg["fixed_in_version"] == "4.17.19"
    validate_ocsf(ev)


def test_map_sca_without_cve_uses_cwe_fallback():
    ev = map_sca({**SCA_ROW, "cve": None}, _ctx("sca"))
    assert ev["vulnerabilities"][0]["cwe"]["uid"] == "NVD-CWE-noinfo"
    validate_ocsf(ev)


def test_map_secret_valid_detection_finding():
    ev = map_secret(SECRET_ROW, _ctx("secret"))
    assert ev["class_uid"] == 2004
    assert ev["unmapped"]["file_path"] == "prod.env"
    validate_ocsf(ev)


def test_map_iac_valid_compliance_finding():
    ev = map_iac(IAC_ROW, _ctx("iac"))
    assert ev["class_uid"] == 2003
    assert ev["compliance"]["control"] == "CKV_AWS_20"
    assert ev["compliance"]["standards"] == ["checkov"]
    validate_ocsf(ev)


def test_map_dast_valid_with_enrichments_and_unmapped():
    ev = map_dast(_dast_row(), _ctx("dast"))
    assert ev["class_uid"] == 2002
    assert ev["status_id"] == 2  # true_positive -> In Progress
    assert ev["vulnerabilities"][0]["cwe"]["uid"] == "CWE-79"
    assert ev["unmapped"]["reachability"] == "exploited"
    assert ev["unmapped"]["cvss_score"] == 7.5
    enr = {e["name"]: e for e in ev["enrichments"]}
    assert enr["epss"]["value"] == "0.1"
    validate_ocsf(ev)


def test_map_runtime_valid_detection_finding():
    ev = map_runtime(RUNTIME_SPAN, _ctx("runtime"))
    assert ev["class_uid"] == 2004
    assert ev["severity_id"] == 5
    assert ev["unmapped"]["trace_id"] == "t1"
    validate_ocsf(ev)


@pytest.mark.parametrize("source,row", [
    ("sast", SAST_ROW), ("sca", SCA_ROW), ("secret", SECRET_ROW),
    ("iac", IAC_ROW), ("dast", _dast_row()), ("runtime", RUNTIME_SPAN),
])
def test_dispatch_every_source_validates(source, row):
    ev = map_finding(source, row, _ctx(source))
    validate_ocsf(ev)


def test_dispatch_unknown_source_raises():
    with pytest.raises(ValueError):
        map_finding("nope", {}, _ctx("nope"))


def test_sast_missing_location_has_no_none_literal_and_is_distinct():
    bare = {"scanner": "semgrep", "rule_id": "r1", "severity": "high", "title": "x",
            "description": "", "file_path": None, "line_start": None, "line_end": None,
            "code_snippet": None, "cve": None, "package": None, "installed_version": None,
            "fixed_version": None, "raw": {}}
    ev1 = map_sast(bare, _ctx("sast"))
    ev2 = map_sast({**bare, "rule_id": "r2"}, _ctx("sast"))
    # different rules must not collide, and no literal "None" in the fingerprint input
    assert ev1["finding_info"]["uid"] != ev2["finding_info"]["uid"]
    validate_ocsf(ev1)


def test_sast_without_severity_omits_vuln_severity():
    row = {**SAST_ROW, "severity": None}
    ev = map_sast(row, _ctx("sast"))
    assert "severity" not in ev["vulnerabilities"][0]
    assert ev["severity_id"] == 0  # top-level Unknown is the authoritative signal
    validate_ocsf(ev)


def test_map_sca_without_fixed_version_omits_field_and_validates():
    # A dependency with no known fix: fixed_in_version must be omitted, not null
    # (OCSF types it as string). Regression for prod quarantine of no-fix SCA findings.
    row = {**SCA_ROW, "fixed_version": None}
    ev = map_sca(row, _ctx("sca"))
    pkg = ev["vulnerabilities"][0]["affected_packages"][0]
    assert "fixed_in_version" not in pkg
    validate_ocsf(ev)
