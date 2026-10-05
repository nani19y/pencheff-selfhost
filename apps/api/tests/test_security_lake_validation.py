from __future__ import annotations

import pytest

from pencheff_api.services.security_lake.validation import (
    validate_ocsf,
    OCSFValidationError,
)


def _vuln_finding() -> dict:
    return {
        "activity_id": 1,
        "category_uid": 2,
        "class_uid": 2002,
        "type_uid": 200201,
        "time": 1_700_000_000_000,
        "severity_id": 4,
        "status_id": 1,
        "metadata": {
            "version": "1.3.0",
            "product": {"name": "Pencheff", "vendor_name": "Pencheff"},
        },
        "finding_info": {"title": "Test finding", "uid": "abc123"},
        "vulnerabilities": [{"title": "Test finding", "severity": "high", "cve": {"uid": "CVE-2024-0001"}}],
    }


def _compliance_finding() -> dict:
    ev = _vuln_finding()
    ev["class_uid"] = 2003
    ev["type_uid"] = 200301
    del ev["vulnerabilities"]
    ev["compliance"] = {"standards": ["checkov"], "control": "CKV_AWS_20"}
    return ev


def _detection_finding() -> dict:
    ev = _vuln_finding()
    ev["class_uid"] = 2004
    ev["type_uid"] = 200401
    del ev["vulnerabilities"]
    return ev


def test_vulnerability_finding_validates():
    validate_ocsf(_vuln_finding())


def test_compliance_finding_validates():
    validate_ocsf(_compliance_finding())


def test_detection_finding_validates():
    validate_ocsf(_detection_finding())


def test_missing_required_field_raises():
    bad = _vuln_finding()
    del bad["finding_info"]
    with pytest.raises(OCSFValidationError):
        validate_ocsf(bad)


def test_vuln_finding_without_vulnerabilities_raises():
    bad = _vuln_finding()
    del bad["vulnerabilities"]
    with pytest.raises(OCSFValidationError):
        validate_ocsf(bad)


def test_unknown_class_uid_raises():
    bad = _vuln_finding()
    bad["class_uid"] = 9999
    bad["type_uid"] = 999901
    with pytest.raises(OCSFValidationError):
        validate_ocsf(bad)
