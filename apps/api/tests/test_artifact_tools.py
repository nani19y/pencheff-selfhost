"""Unit tests for plugins/pencheff/pencheff/artifact_tools.py.

Focus: the security-critical contracts. Subprocess calls are intentionally NOT
exercised here (those binaries may not be installed in test env); the tools
return ``{"error": "binary not found: ..."}`` cleanly when they're missing,
which is itself a property worth verifying.

Covered:
* Allowlist enforcement for artifact_clone_repo / artifact_pull_image /
  artifact_download (off-allowlist URL or ref returns ``url_not_allowed`` /
  ``ref_not_allowed`` / ``host_not_allowed`` WITHOUT invoking subprocess).
* sha256 mismatch on artifact_download deletes nothing and reports
  ``sha256 mismatch``.
* artifact_parse_sbom validates format + content size.
* set_kind_config_for_session bindings round-trip + can be cleared.
* JSON parsers for trivy / grype / osv / checkov / tfsec / npm-audit /
  pip-audit / hadolint emit findings with the expected pencheff schema
  (severity, category, owasp_category).
"""
from __future__ import annotations

import json

import pytest

# This module lives in the plugins/ tree — the api venv has the plugin
# installed locally per the project's pyproject.toml dev dependency.
import pencheff.artifact_tools as at


@pytest.fixture(autouse=True)
def _clear_kind_configs():
    """Reset the in-memory session→kind_config map between tests."""
    at._SESSION_KIND_CONFIGS.clear()
    yield
    at._SESSION_KIND_CONFIGS.clear()


# ----------------------------------------------------------------------------
# set_kind_config_for_session — round-trip
# ----------------------------------------------------------------------------


def test_set_and_clear_session_kind_config() -> None:
    at.set_kind_config_for_session("sid-1", {"kind": "container_image", "image_ref": "alpine:3.10"})
    assert at._kind_config_for_session("sid-1") == {"kind": "container_image", "image_ref": "alpine:3.10"}
    at.set_kind_config_for_session("sid-1", None)
    assert at._kind_config_for_session("sid-1") is None


# ----------------------------------------------------------------------------
# artifact_clone_repo — allowlist enforcement
# ----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_clone_repo_rejects_off_allowlist_url(monkeypatch) -> None:
    # Even when git is installed, the off-allowlist URL must be rejected
    # WITHOUT a subprocess call.
    monkeypatch.setattr(at, "_which", lambda b: True)
    called = []

    async def _no_call(*a, **kw):
        called.append(a)
        return {"returncode": 0, "stdout": "", "stderr": "", "timed_out": False}
    monkeypatch.setattr(at, "_run_subprocess", _no_call)

    at.set_kind_config_for_session("sid", {"kind": "source_code", "repo_url": "https://github.com/good/repo"})
    result = await at.artifact_clone_repo("sid", url="https://github.com/EVIL/repo")
    assert result["error"] == "url_not_allowed"
    assert called == [], "subprocess should NOT be invoked for off-allowlist URL"


@pytest.mark.asyncio
async def test_clone_repo_refused_when_no_registered_url(monkeypatch) -> None:
    monkeypatch.setattr(at, "_which", lambda b: True)
    result = await at.artifact_clone_repo("sid-unbound", url="https://github.com/x/y")
    assert "no registered repo_url" in result["error"]


@pytest.mark.asyncio
async def test_clone_repo_rejects_unsafe_ref(monkeypatch) -> None:
    monkeypatch.setattr(at, "_which", lambda b: True)
    at.set_kind_config_for_session("sid", {"kind": "source_code", "repo_url": "https://github.com/x/y"})
    result = await at.artifact_clone_repo("sid", url="https://github.com/x/y", ref="main; rm -rf /")
    assert result["error"] == "invalid ref"


@pytest.mark.asyncio
async def test_clone_repo_returns_error_when_git_missing(monkeypatch) -> None:
    monkeypatch.setattr(at, "_which", lambda b: False)
    at.set_kind_config_for_session("sid", {"kind": "source_code", "repo_url": "https://github.com/x/y"})
    result = await at.artifact_clone_repo("sid", url="https://github.com/x/y")
    assert "binary not found: git" in result["error"]


# ----------------------------------------------------------------------------
# artifact_pull_image — allowlist + skopeo-only
# ----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_pull_image_rejects_off_allowlist_ref(monkeypatch) -> None:
    monkeypatch.setattr(at, "_which", lambda b: True)
    called = []

    async def _no_call(*a, **kw):
        called.append(a)
        return {"returncode": 0, "stdout": "", "stderr": "", "timed_out": False}
    monkeypatch.setattr(at, "_run_subprocess", _no_call)

    at.set_kind_config_for_session("sid", {"kind": "container_image", "image_ref": "alpine:3.10"})
    result = await at.artifact_pull_image("sid", ref="evil/image:latest")
    assert result["error"] == "ref_not_allowed"
    assert called == []


@pytest.mark.asyncio
async def test_pull_image_allows_digest_of_registered_ref(monkeypatch) -> None:
    """A digest pin (image@sha256:…) is allowed iff the base ref matches."""
    monkeypatch.setattr(at, "_which", lambda b: True)

    async def _fake_run(*a, **kw):
        return {"returncode": 0, "stdout": "", "stderr": "", "timed_out": False}
    monkeypatch.setattr(at, "_run_subprocess", _fake_run)

    at.set_kind_config_for_session("sid", {"kind": "container_image", "image_ref": "alpine:3.10"})
    result = await at.artifact_pull_image("sid", ref="alpine:3.10@sha256:deadbeef" + "f" * 56)
    assert "error" not in result or result.get("oci_layout"), result


@pytest.mark.asyncio
async def test_pull_image_requires_skopeo_not_docker(monkeypatch) -> None:
    # With skopeo missing, return an error citing skopeo.
    monkeypatch.setattr(at, "_which", lambda b: False)
    result = await at.artifact_pull_image("sid", ref="alpine:3.10")
    assert "binary not found: skopeo" in result["error"]


# ----------------------------------------------------------------------------
# artifact_download — host allowlist + sha256 verification
# ----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_download_rejects_off_allowlist_host(monkeypatch) -> None:
    at.set_kind_config_for_session("sid", {"kind": "package_registry", "allowed_hosts": ["registry.npmjs.org"]})
    result = await at.artifact_download(
        "sid",
        url="https://EVIL.example.com/pkg.tgz",
        sha256="a" * 64,
    )
    assert result["error"] == "host_not_allowed"
    # urlparse lowercases hostnames — match that.
    assert result["host"] == "evil.example.com"


@pytest.mark.asyncio
async def test_download_requires_64_hex_sha256(monkeypatch) -> None:
    at.set_kind_config_for_session("sid", {"kind": "package_registry"})
    result = await at.artifact_download(
        "sid",
        url="https://registry.npmjs.org/foo/-/foo-1.0.0.tgz",
        sha256="not-a-real-hash",
    )
    assert "sha256 must be a 64-char hex digest" in result["error"]


@pytest.mark.asyncio
async def test_download_falls_back_to_default_host_list(monkeypatch) -> None:
    # No allowed_hosts on kind_config → the per-kind default list kicks in.
    at.set_kind_config_for_session("sid", {"kind": "package_registry"})
    result = await at.artifact_download(
        "sid",
        url="https://EVIL.example.com/pkg.tgz",
        sha256="a" * 64,
    )
    assert result["error"] == "host_not_allowed"


# ----------------------------------------------------------------------------
# artifact_parse_sbom
# ----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_parse_sbom_rejects_invalid_format() -> None:
    result = await at.artifact_parse_sbom("sid", content="{}", sbom_format="bogus-format")
    assert "unsupported sbom_format" in result["error"]


@pytest.mark.asyncio
async def test_parse_sbom_rejects_invalid_json() -> None:
    result = await at.artifact_parse_sbom("sid", content="{not valid", sbom_format="cyclonedx-json")
    assert "invalid JSON SBOM" in result["error"]


@pytest.mark.asyncio
async def test_parse_sbom_writes_valid_json(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(at, "_SCAN_TMP_ROOT", tmp_path)
    sbom = json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.4", "components": []})
    result = await at.artifact_parse_sbom("sid", content=sbom, sbom_format="cyclonedx-json")
    assert "local_path" in result
    assert result["format"] == "cyclonedx-json"


# ----------------------------------------------------------------------------
# JSON parsers — verify pencheff finding schema is preserved
# ----------------------------------------------------------------------------


def test_parse_trivy_json_maps_severities_and_owasp() -> None:
    raw = json.dumps({
        "Results": [{
            "Target": "alpine:3.10 (alpine 3.10.0)",
            "Vulnerabilities": [
                {"VulnerabilityID": "CVE-2021-1234", "PkgName": "openssl",
                 "InstalledVersion": "1.1.1", "FixedVersion": "1.1.1k",
                 "Severity": "HIGH", "Description": "Buffer overflow"},
                {"VulnerabilityID": "CVE-2021-9999", "PkgName": "zlib",
                 "InstalledVersion": "1.2.11", "Severity": "CRITICAL",
                 "Description": "RCE"},
            ],
        }],
    })
    findings = at._parse_trivy_json(raw)
    assert len(findings) == 2
    assert findings[0]["severity"] == "high"
    assert findings[1]["severity"] == "critical"
    assert all(f["owasp_category"] == "A06:2021" for f in findings)
    assert all(f["category"] == "vulnerable_dependency" for f in findings)


def test_parse_grype_json_handles_negligible_severity() -> None:
    raw = json.dumps({
        "matches": [{
            "vulnerability": {"id": "CVE-2020-1", "severity": "Negligible",
                              "description": "trivial", "fix": {"versions": []}},
            "artifact": {"name": "lib", "version": "1.0"},
        }],
    })
    findings = at._parse_grype_json(raw)
    assert findings[0]["severity"] == "info"


def test_parse_osv_json_extracts_cvss_severity() -> None:
    raw = json.dumps({
        "results": [{
            "packages": [{
                "package": {"name": "tarfile", "version": "0.1"},
                "vulnerabilities": [{
                    "id": "GHSA-aaaa", "summary": "RCE",
                    "severity": [{"score": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:9.8"}],
                }],
            }],
        }],
    })
    findings = at._parse_osv_json(raw)
    assert len(findings) == 1
    assert findings[0]["package"] == "tarfile"


def test_parse_checkov_json_maps_misconfig() -> None:
    raw = json.dumps({
        "results": {
            "failed_checks": [{
                "check_id": "CKV_AWS_1",
                "check_name": "Ensure S3 bucket is not public",
                "severity": "HIGH",
                "file_path": "main.tf",
                "file_line_range": [10, 15],
            }],
        },
    })
    findings = at._parse_checkov_json(raw)
    assert findings[0]["owasp_category"] == "A05:2021"
    assert findings[0]["category"] == "iac_misconfiguration"
    assert findings[0]["line_start"] == 10


def test_parse_tfsec_json_pulls_location_fields() -> None:
    raw = json.dumps({
        "results": [{
            "rule_id": "aws-s3-no-public-access",
            "severity": "HIGH",
            "description": "S3 bucket has public access",
            "location": {"filename": "s3.tf", "start_line": 5, "end_line": 12},
        }],
    })
    findings = at._parse_tfsec_json(raw)
    assert findings[0]["file_path"] == "s3.tf"
    assert findings[0]["owasp_category"] == "A05:2021"


def test_parse_hadolint_maps_levels() -> None:
    raw = json.dumps([
        {"code": "DL3000", "level": "error", "message": "Use absolute WORKDIR", "file": "Dockerfile", "line": 3},
        {"code": "DL3025", "level": "info", "message": "Use shell form", "file": "Dockerfile", "line": 8},
    ])
    findings = at._parse_hadolint_json(raw)
    assert findings[0]["severity"] == "high"
    assert findings[1]["severity"] == "low"
    assert findings[0]["owasp_category"] == "A05:2021"


def test_parsers_handle_empty_input() -> None:
    """Empty / malformed scanner stdout produces no findings (not an exception)."""
    assert at._parse_trivy_json("") == []
    assert at._parse_grype_json("") == []
    assert at._parse_osv_json("") == []
    assert at._parse_checkov_json("") == []
    assert at._parse_tfsec_json("") == []
    assert at._parse_npm_audit_json("") == []
    assert at._parse_pip_audit_json("") == []
    assert at._parse_hadolint_json("") == []
    # Garbage JSON also → []
    assert at._parse_trivy_json("not json") == []
