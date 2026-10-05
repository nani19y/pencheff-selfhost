"""Read-only cloud posture collector tests."""
from __future__ import annotations

from pencheff_api.services.agent_swarm.cloud_scanners import run_cloud_checks


def test_cloud_storage_flags_public_and_unencrypted_resources() -> None:
    findings, stats = run_cloud_checks(
        kind="cloud_storage",
        cfg={
            "kind": "cloud_storage",
            "provider": "aws",
            "account_id": "123456789012",
            "inventory": {
                "storage": [
                    {
                        "name": "prod-public-assets",
                        "public": True,
                        "encrypted": False,
                        "logging_enabled": False,
                    },
                ],
            },
        },
        kind_credentials={"provider": "aws"},
    )

    titles = {f["title"] for f in findings}
    assert "Cloud storage is publicly accessible: prod-public-assets" in titles
    assert "Cloud storage encryption disabled: prod-public-assets" in titles
    assert stats["CloudStorageAgent"]["findings_count"] == 3


def test_cloud_account_flags_overbroad_iam_actions() -> None:
    findings, stats = run_cloud_checks(
        kind="cloud_account",
        cfg={
            "kind": "cloud_account",
            "provider": "aws",
            "account_id": "123456789012",
            "inventory": {
                "iam": [
                    {
                        "principal": "arn:aws:iam::123456789012:role/AdminLike",
                        "actions": ["*", "iam:PassRole"],
                    },
                ],
            },
        },
        kind_credentials={"provider": "aws"},
    )

    assert any("Overbroad cloud IAM permissions" in f["title"] for f in findings)
    assert stats["CloudIamExposureAgent"]["findings_count"] == 1


def test_secrets_manager_checks_metadata_without_echoing_secret_values() -> None:
    findings, stats = run_cloud_checks(
        kind="secrets_manager",
        cfg={
            "kind": "secrets_manager",
            "provider": "aws",
            "account_id": "123456789012",
            "inventory": {
                "secrets": [
                    {
                        "name": "prod/db/password",
                        "rotation_enabled": False,
                        "policy_public": True,
                        "value": "super-secret-password",
                    },
                ],
            },
        },
        kind_credentials={"provider": "aws"},
    )

    assert stats["SecretsHygieneAgent"]["findings_count"] == 2
    serialized = "\n".join(str(f) for f in findings)
    assert "super-secret-password" not in serialized
