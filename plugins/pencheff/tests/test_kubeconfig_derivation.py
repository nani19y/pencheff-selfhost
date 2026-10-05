"""Unit tests for the cloud-managed kubeconfig derivation helpers in
``hybrid_tools.py``.

The actual cloud-SDK calls are mocked because we don't want to hit real
EKS / AKS / GKE control planes from CI. We verify:
  * ``_render_kubeconfig_yaml`` produces parseable YAML with the expected
    keys filled in.
  * Each ``_derive_*_kubeconfig`` raises ``_CloudDeriveError`` with a clear
    message when the required cluster identifiers are absent from cfg.
  * The EKS derivation works end-to-end with mocked boto3 clients.
"""
from __future__ import annotations

import sys
import types

import pytest
import yaml

from pencheff.hybrid_tools import (
    _CloudDeriveError,
    _derive_aks_kubeconfig,
    _derive_eks_kubeconfig,
    _derive_gke_kubeconfig,
    _render_kubeconfig_yaml,
)


def test_render_kubeconfig_yaml_round_trips_through_pyyaml():
    rendered = _render_kubeconfig_yaml(
        endpoint="https://eks.example.com",
        ca_b64="LS0tLS1CRUdJTi…",
        user_name="aws-prod",
        cluster_name="aws-prod",
        token="k8s-aws-v1.token-payload",
    )
    parsed = yaml.safe_load(rendered)
    assert parsed["apiVersion"] == "v1"
    assert parsed["kind"] == "Config"
    assert parsed["current-context"] == "aws-prod"
    assert parsed["clusters"][0]["cluster"]["server"] == "https://eks.example.com"
    assert parsed["users"][0]["user"]["token"] == "k8s-aws-v1.token-payload"


def test_aks_derivation_requires_cluster_identifiers():
    """Even if azure-mgmt isn't installed, the cfg-missing error fires first."""
    with pytest.raises(_CloudDeriveError, match="azure_subscription_id"):
        _derive_aks_kubeconfig(
            {"azure_tenant_id": "t", "azure_client_id": "c", "azure_client_secret": "s"},
            {},
        )


def test_gke_derivation_requires_cluster_identifiers():
    with pytest.raises(_CloudDeriveError, match="gcp_project_id"):
        _derive_gke_kubeconfig({"gcp_service_account_json": "{}"}, {})


def test_eks_derivation_requires_cluster_identifiers():
    with pytest.raises(_CloudDeriveError, match="aws_region"):
        _derive_eks_kubeconfig(
            {"aws_access_key_id": "AKIA", "aws_secret_access_key": "x"},
            {},
        )


def test_eks_derivation_with_mocked_boto3(monkeypatch):
    """Exercise the full EKS derivation path with a stub boto3."""
    fake_boto3 = types.ModuleType("boto3")
    fake_botocore_signers = types.ModuleType("botocore.signers")

    class _FakeEvents:
        pass

    class _FakeCredentials:
        access_key = "AKIA"
        secret_key = "sek"
        token = None

        def get_frozen_credentials(self):
            return self

    class _FakeEksClient:
        def describe_cluster(self, name: str):
            return {
                "cluster": {
                    "endpoint": "https://EKS123.gr7.us-east-1.eks.amazonaws.com",
                    "certificateAuthority": {"data": "LS0tLS1CRUdJTi…"},
                }
            }

    class _FakeStsClient:
        class _Meta:
            class _SvcModel:
                service_id = "sts"
            service_model = _SvcModel()
        meta = _Meta()

    class _FakeSession:
        def __init__(self, **kwargs):
            self.events = _FakeEvents()

        def client(self, name, region_name=None):
            if name == "eks":
                return _FakeEksClient()
            if name == "sts":
                return _FakeStsClient()
            raise AssertionError(name)

        def get_credentials(self):
            return _FakeCredentials()

    fake_boto3.Session = _FakeSession

    class _FakeRequestSigner:
        def __init__(self, *args, **kwargs):
            pass

        def generate_presigned_url(self, params, region_name, expires_in, operation_name):
            return f"https://sts.{region_name}.amazonaws.com/?presigned=1"

    fake_botocore_signers.RequestSigner = _FakeRequestSigner

    monkeypatch.setitem(sys.modules, "boto3", fake_boto3)
    monkeypatch.setitem(sys.modules, "botocore", types.ModuleType("botocore"))
    monkeypatch.setitem(sys.modules, "botocore.signers", fake_botocore_signers)

    out = _derive_eks_kubeconfig(
        {"aws_access_key_id": "AKIA", "aws_secret_access_key": "sek"},
        {"aws_region": "us-east-1", "aws_cluster_name": "prod-eks"},
    )
    parsed = yaml.safe_load(out)
    assert parsed["clusters"][0]["cluster"]["server"] \
        == "https://EKS123.gr7.us-east-1.eks.amazonaws.com"
    token = parsed["users"][0]["user"]["token"]
    assert token.startswith("k8s-aws-v1.")
