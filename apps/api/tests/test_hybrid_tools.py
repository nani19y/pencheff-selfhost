"""Tests for plugins/pencheff/pencheff/hybrid_tools.py (feature 001 Phase B).

Subprocess + httpx calls are stubbed; verify:
* Kubeconfig materialised to a 0600 tempfile, ``_unlink_kubeconfig`` removes it.
* ``run_kubectl_get`` rejects off-allowlist resources without invoking kubectl.
* ``run_kubectl_get`` rejects namespaces outside the operator-registered list.
* ``run_kubectl_describe`` rejects shell-metachar names.
* RBAC JSON parser flags wildcard verbs / impersonate / escalate.
* ``run_github_actions_api`` requires kind_credentials with provider=github_actions
  and a token; emits findings for admin-suggestive secret names + read-write
  deploy keys.
"""
from __future__ import annotations

import json
import os
import stat

import pytest

import pencheff.artifact_tools as at
import pencheff.hybrid_tools as ht


@pytest.fixture(autouse=True)
def _clear_session_state():
    at._SESSION_KIND_CONFIGS.clear()
    at._SESSION_KIND_CREDS.clear()
    yield
    at._SESSION_KIND_CONFIGS.clear()
    at._SESSION_KIND_CREDS.clear()


# ----------------------------------------------------------------------------
# Kubeconfig lifecycle
# ----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_materialize_kubeconfig_writes_0600(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(at, "_SCAN_TMP_ROOT", tmp_path)
    monkeypatch.setattr(ht, "_SCAN_TMP_ROOT", tmp_path)
    at.set_kind_credentials_for_session("sid", {"kind": "k8s_cluster", "kubeconfig": "apiVersion: v1\nkind: Config"})
    path_str = await ht._materialize_kubeconfig("sid")
    assert path_str is not None
    path = tmp_path / "sid" / ".kube" / "config"
    assert path.exists()
    # Mode should be 0600 (owner read+write only).
    mode = stat.S_IMODE(os.stat(path).st_mode)
    assert mode == 0o600


@pytest.mark.asyncio
async def test_materialize_kubeconfig_returns_none_when_no_creds() -> None:
    assert await ht._materialize_kubeconfig("unbound-sid") is None


@pytest.mark.asyncio
async def test_materialize_kubeconfig_returns_none_when_wrong_creds_kind() -> None:
    at.set_kind_credentials_for_session("sid", {"kind": "cicd_pipeline", "token": "ghp_xxx"})
    assert await ht._materialize_kubeconfig("sid") is None


@pytest.mark.asyncio
async def test_unlink_kubeconfig_removes_tempfile(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(at, "_SCAN_TMP_ROOT", tmp_path)
    monkeypatch.setattr(ht, "_SCAN_TMP_ROOT", tmp_path)
    at.set_kind_credentials_for_session("sid", {"kind": "k8s_cluster", "kubeconfig": "apiVersion: v1"})
    await ht._materialize_kubeconfig("sid")
    path = tmp_path / "sid" / ".kube" / "config"
    assert path.exists()
    ht._unlink_kubeconfig("sid")
    assert not path.exists()


def test_unlink_kubeconfig_is_safe_when_file_missing(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(ht, "_SCAN_TMP_ROOT", tmp_path)
    # Should not raise — best-effort cleanup.
    ht._unlink_kubeconfig("never-existed-sid")


# ----------------------------------------------------------------------------
# run_kubectl_get
# ----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_kubectl_get_rejects_off_allowlist_resource(monkeypatch) -> None:
    monkeypatch.setattr(ht, "_which", lambda b: True)
    at.set_kind_credentials_for_session("sid", {"kind": "k8s_cluster", "kubeconfig": "apiVersion: v1"})
    result = await ht.run_kubectl_get("sid", resource="cronjobs")
    assert result["error"] == "resource_not_allowed"
    assert "rolebindings" in result["allowed"]


@pytest.mark.asyncio
async def test_kubectl_get_rejects_namespace_outside_operator_list(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(ht, "_which", lambda b: True)
    monkeypatch.setattr(at, "_SCAN_TMP_ROOT", tmp_path)
    monkeypatch.setattr(ht, "_SCAN_TMP_ROOT", tmp_path)
    at.set_kind_config_for_session("sid", {"kind": "k8s_cluster", "namespaces": ["default", "kube-system"]})
    at.set_kind_credentials_for_session("sid", {"kind": "k8s_cluster", "kubeconfig": "apiVersion: v1"})
    result = await ht.run_kubectl_get("sid", resource="pods", namespace="evil-ns")
    assert result["error"] == "namespace_not_in_operator_list"


@pytest.mark.asyncio
async def test_kubectl_get_refuses_without_kubeconfig(monkeypatch) -> None:
    monkeypatch.setattr(ht, "_which", lambda b: True)
    # No kind_credentials bound.
    result = await ht.run_kubectl_get("sid-no-creds", resource="pods")
    assert "no kubeconfig" in result["error"]


@pytest.mark.asyncio
async def test_kubectl_get_skips_when_kubectl_missing(monkeypatch) -> None:
    monkeypatch.setattr(ht, "_which", lambda b: False)
    result = await ht.run_kubectl_get("sid", resource="pods")
    assert result.get("skipped") is True


# ----------------------------------------------------------------------------
# _parse_kubectl_get_json — RBAC heuristic
# ----------------------------------------------------------------------------


def test_parse_kubectl_get_rolebindings_flags_admin_to_default_sa() -> None:
    raw = json.dumps({
        "items": [
            {
                "metadata": {"name": "evil-binding"},
                "roleRef": {"name": "cluster-admin"},
                "subjects": [{"kind": "ServiceAccount", "name": "default"}],
            },
            # benign control case
            {
                "metadata": {"name": "ok-binding"},
                "roleRef": {"name": "view"},
                "subjects": [{"kind": "User", "name": "alice"}],
            },
        ],
    })
    findings = ht._parse_kubectl_get_json("rolebindings", raw)
    # 1 INFO summary + 1 HIGH binding.
    assert len(findings) == 2
    high = [f for f in findings if f["severity"] == "high"]
    assert len(high) == 1
    assert high[0]["owasp_category"] == "A01:2021"
    assert "default ServiceAccount" in high[0]["title"]


def test_parse_kubectl_get_handles_empty() -> None:
    assert ht._parse_kubectl_get_json("pods", "") == []
    assert ht._parse_kubectl_get_json("pods", "not-json") == []
    # Empty items → no findings (we only emit the summary when items exist).
    assert ht._parse_kubectl_get_json("pods", '{"items":[]}') == []


# ----------------------------------------------------------------------------
# run_kubectl_describe
# ----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_kubectl_describe_rejects_shell_metachar_name(monkeypatch) -> None:
    monkeypatch.setattr(ht, "_which", lambda b: True)
    at.set_kind_credentials_for_session("sid", {"kind": "k8s_cluster", "kubeconfig": "apiVersion: v1"})
    result = await ht.run_kubectl_describe("sid", resource="pods", name="evil; rm -rf /")
    assert result["error"] == "invalid resource name"


@pytest.mark.asyncio
async def test_kubectl_describe_rejects_off_allowlist_resource(monkeypatch) -> None:
    monkeypatch.setattr(ht, "_which", lambda b: True)
    at.set_kind_credentials_for_session("sid", {"kind": "k8s_cluster", "kubeconfig": "apiVersion: v1"})
    result = await ht.run_kubectl_describe("sid", resource="cronjobs", name="anything")
    assert result["error"] == "resource_not_allowed"


# ----------------------------------------------------------------------------
# _parse_rakkess_json
# ----------------------------------------------------------------------------


def test_parse_rakkess_flags_wildcard_verb_as_critical() -> None:
    raw = json.dumps([
        {"name": "secrets", "verbs": ["get", "list", "*"]},
        {"name": "pods", "verbs": ["get", "list"]},  # benign
        {"name": "roles", "verbs": ["escalate"]},
    ])
    findings = ht._parse_rakkess_json(raw)
    # secrets → critical (wildcard), roles → high (escalate); pods doesn't fire
    assert len(findings) == 2
    severities = sorted(f["severity"] for f in findings)
    assert severities == ["critical", "high"]
    assert all(f["owasp_category"] == "A01:2021" for f in findings)


def test_parse_rakkess_empty_input() -> None:
    assert ht._parse_rakkess_json("") == []
    assert ht._parse_rakkess_json("not-json") == []


# ----------------------------------------------------------------------------
# run_github_actions_api
# ----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_github_actions_api_requires_kind_credentials() -> None:
    result = await ht.run_github_actions_api("sid-no-creds", owner="o", repo="r")
    assert "no github_actions credentials" in result["error"]


@pytest.mark.asyncio
async def test_github_actions_api_requires_token() -> None:
    at.set_kind_credentials_for_session("sid", {
        "kind": "cicd_pipeline", "provider": "github_actions",
        # token missing; GitHub App auth deferred
        "github_app_id": "12345", "github_app_private_key": "-----BEGIN…-----",
        "github_app_installation_id": "67890",
    })
    result = await ht.run_github_actions_api("sid", owner="o", repo="r")
    assert "PAT" in result["error"]


@pytest.mark.asyncio
async def test_github_actions_api_validates_owner_and_repo() -> None:
    at.set_kind_credentials_for_session("sid", {
        "kind": "cicd_pipeline", "provider": "github_actions", "token": "ghp_xxx",
    })
    # slash in owner is rejected (defends against url-injection like
    # ``owner=evil/../../`` being concatenated into the API URL).
    result = await ht.run_github_actions_api("sid", owner="evil/x", repo="r")
    assert result["error"] == "invalid owner"
    result = await ht.run_github_actions_api("sid", owner="ok", repo="r/x")
    assert result["error"] == "invalid repo"
