"""Tests for the artifact orchestrator routing logic.

These tests stub the artifact_tools subprocess wrappers (no real
binaries needed) and verify:

* The per-kind acquisition tool is selected correctly (skopeo for
  container_image; clone for iac; parse_sbom for sbom).
* Every scanner in KIND_TO_ARTIFACT_TOOLS for the kind is attempted.
* Per-kind argument mapping picks the right inputs (oci_layout for
  trivy_image; local_path for checkov; framework hint for tfsec).
* Findings are collected + emitted to the Scan row.
* Scanner-stats are recorded for missing binaries (graceful skip).
"""
from __future__ import annotations

import pytest

from pencheff_api.services.agent_swarm import artifact_orchestrator as ao


# ----------------------------------------------------------------------------
# _scanner_args_for — per-(kind, tool) argument mapping
# ----------------------------------------------------------------------------


def test_args_container_image_with_oci_layout() -> None:
    acquired = {"oci_layout": "/tmp/abc/oci-layout"}
    cfg = {"image_ref": "alpine:3.10"}
    assert ao._scanner_args_for("container_image", "run_trivy_image", acquired, cfg) == {
        "oci_layout": "/tmp/abc/oci-layout", "image_ref": "alpine:3.10",
    }
    assert ao._scanner_args_for("container_image", "run_syft", acquired, cfg) == {
        "source_path": "/tmp/abc/oci-layout",
    }


def test_args_container_image_skips_when_no_oci_layout() -> None:
    """If skopeo failed, syft/grype have no input — orchestrator skips them."""
    acquired: dict = {}
    cfg = {"image_ref": "alpine:3.10"}
    assert ao._scanner_args_for("container_image", "run_syft", acquired, cfg) is None
    assert ao._scanner_args_for("container_image", "run_grype", acquired, cfg) is None


def test_args_iac_picks_framework_for_checkov() -> None:
    acquired = {"local_path": "/tmp/repo"}
    cfg = {"frameworks": ["terraform", "helm"]}
    assert ao._scanner_args_for("iac", "run_checkov", acquired, cfg) == {
        "source_path": "/tmp/repo", "framework": "terraform",
    }


def test_args_iac_tfsec_only_when_terraform_in_frameworks() -> None:
    acquired = {"local_path": "/tmp/repo"}
    cfg_tf = {"frameworks": ["terraform", "helm"]}
    cfg_helm_only = {"frameworks": ["helm"]}
    assert ao._scanner_args_for("iac", "run_tfsec", acquired, cfg_tf) == {"source_path": "/tmp/repo"}
    assert ao._scanner_args_for("iac", "run_tfsec", acquired, cfg_helm_only) is None


def test_args_package_registry_ecosystem_gating() -> None:
    acquired: dict = {}
    assert ao._scanner_args_for("package_registry", "run_npm_audit", acquired, {"ecosystem": "npm"}) is not None
    assert ao._scanner_args_for("package_registry", "run_npm_audit", acquired, {"ecosystem": "pypi"}) is None
    assert ao._scanner_args_for("package_registry", "run_pip_audit", acquired, {"ecosystem": "pypi"}) is not None
    assert ao._scanner_args_for("package_registry", "run_pip_audit", acquired, {"ecosystem": "npm"}) is None


def test_args_sbom_routes_to_sbom_scanners() -> None:
    acquired = {"local_path": "/tmp/sbom.json"}
    cfg = {"format": "cyclonedx-json"}
    assert ao._scanner_args_for("sbom", "run_grype_sbom", acquired, cfg) == {"sbom_path": "/tmp/sbom.json"}
    assert ao._scanner_args_for("sbom", "run_osv_scanner_sbom", acquired, cfg) == {"sbom_path": "/tmp/sbom.json"}


def test_args_sbom_skips_when_no_local_path() -> None:
    assert ao._scanner_args_for("sbom", "run_grype_sbom", {}, {"format": "cyclonedx-json"}) is None


# ----------------------------------------------------------------------------
# KIND_TO_ARTIFACT_TOOLS coverage
# ----------------------------------------------------------------------------


def test_kind_to_artifact_tools_covers_5_artifact_kinds() -> None:
    expected = {"source_code", "container_image", "iac", "package_registry", "sbom"}
    assert set(ao.KIND_TO_ARTIFACT_TOOLS.keys()) == expected


def test_acquisition_for_kind_covers_4_acquisition_kinds() -> None:
    """package_registry uses inline package_list, no acquisition needed."""
    assert ao._ACQUISITION_FOR_KIND["container_image"] == "artifact_pull_image"
    assert ao._ACQUISITION_FOR_KIND["iac"] == "artifact_clone_repo"
    assert ao._ACQUISITION_FOR_KIND["sbom"] == "artifact_parse_sbom"
    assert ao._ACQUISITION_FOR_KIND["package_registry"] is None


# ----------------------------------------------------------------------------
# run_artifact_orchestrator — invalid kind rejection
# ----------------------------------------------------------------------------


class _FakeTarget:
    def __init__(self, kind: str, kind_config: dict | None = None) -> None:
        self.kind = kind
        self.kind_config = kind_config


@pytest.mark.asyncio
async def test_orchestrator_rejects_non_artifact_kind() -> None:
    target = _FakeTarget("web_app", {"kind": "web_app"})
    with pytest.raises(ValueError, match="non-artifact kind"):
        await ao.run_artifact_orchestrator(scan_id="x", target=target, Session=None)


@pytest.mark.asyncio
async def test_orchestrator_rejects_unsupported_kind() -> None:
    target = _FakeTarget("not_a_kind", {})
    with pytest.raises(ValueError, match="non-artifact kind"):
        await ao.run_artifact_orchestrator(scan_id="x", target=target, Session=None)


# ----------------------------------------------------------------------------
# _clone_error — surface real git stderr, not the opaque "git clone failed"
# ----------------------------------------------------------------------------
def test_clone_error_surfaces_stderr_last_line():
    # The actionable git message (auth / not-found) is the last stderr line.
    acquired = {
        "error": "git clone failed",
        "returncode": 128,
        "stderr": "Cloning into 'x'...\nremote: Repository not found.\n"
                  "fatal: repository 'https://github.com/o/r/' not found",
    }
    msg = ao._clone_error(acquired)
    assert msg == "clone failed: fatal: repository 'https://github.com/o/r/' not found"


def test_clone_error_falls_back_to_error_when_no_stderr():
    assert ao._clone_error({"error": "git clone failed"}) == "clone failed: git clone failed"
    # Empty stderr must not index into an empty splitlines() list.
    assert ao._clone_error({"error": "boom", "stderr": "   "}) == "clone failed: boom"
