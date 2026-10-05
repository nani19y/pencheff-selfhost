"""Cloud privesc rule tables — viable-paths matching."""

from __future__ import annotations

from pencheff.modules.cloud_privesc import aws_privesc, azure_privesc, gcp_privesc


def test_aws_admin_wildcard_matches_everything():
    paths = aws_privesc.viable_paths({"*"})
    assert len(paths) == len(aws_privesc.PATHS)


def test_aws_iam_wildcard_matches_iam_paths():
    paths = aws_privesc.viable_paths({"iam:*"})
    iam_only = [
        p for p in aws_privesc.PATHS
        if all(a.startswith("iam:") for a in p.required_actions)
    ]
    assert len(paths) >= len(iam_only)


def test_aws_specific_path_matches():
    paths = aws_privesc.viable_paths({"iam:CreatePolicyVersion"})
    names = {p.name for p in paths}
    assert "CreateNewPolicyVersion" in names


def test_aws_no_match_when_actions_empty():
    paths = aws_privesc.viable_paths(set())
    assert paths == []


def test_gcp_match_actAs():
    paths = gcp_privesc.viable_paths({"iam.serviceAccounts.actAs"})
    names = {p.name for p in paths}
    assert "iam.serviceAccounts.actAs" in names


def test_azure_match_user_access_admin():
    paths = azure_privesc.viable_paths({"User Access Administrator"})
    names = {p.name for p in paths}
    assert "UserAccessAdministrator" in names
