"""Tests for the GitLab / Jenkins CI Phase B wrappers (feature 001)."""
from __future__ import annotations

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
# run_gitlab_ci_api
# ----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_gitlab_requires_credentials() -> None:
    result = await ht.run_gitlab_ci_api("sid-no-creds", project="namespace/project")
    assert "no gitlab_ci credentials" in result["error"]


@pytest.mark.asyncio
async def test_gitlab_requires_token() -> None:
    at.set_kind_credentials_for_session("sid", {
        "kind": "cicd_pipeline", "provider": "gitlab_ci",
    })  # missing token
    result = await ht.run_gitlab_ci_api("sid", project="namespace/project")
    assert "PAT" in result["error"]


@pytest.mark.asyncio
async def test_gitlab_rejects_double_slash_in_project() -> None:
    at.set_kind_credentials_for_session("sid", {
        "kind": "cicd_pipeline", "provider": "gitlab_ci", "token": "glpat-xxx",
    })
    result = await ht.run_gitlab_ci_api("sid", project="ns//evil")
    assert result["error"].startswith("invalid project")


@pytest.mark.asyncio
async def test_gitlab_rejects_shell_metachars_in_project() -> None:
    at.set_kind_credentials_for_session("sid", {
        "kind": "cicd_pipeline", "provider": "gitlab_ci", "token": "glpat-xxx",
    })
    for bad in ["ns/p;rm", "ns/p&id", "ns/p|cat", "ns/p$x"]:
        result = await ht.run_gitlab_ci_api("sid", project=bad)
        assert result["error"] == "invalid project", f"failed for {bad!r}"


@pytest.mark.asyncio
async def test_gitlab_rejects_invalid_base_url() -> None:
    at.set_kind_credentials_for_session("sid", {
        "kind": "cicd_pipeline", "provider": "gitlab_ci", "token": "glpat-xxx",
    })
    result = await ht.run_gitlab_ci_api(
        "sid", project="ns/p", base_url="javascript:alert(1)",
    )
    assert result["error"] == "invalid base_url"


# ----------------------------------------------------------------------------
# run_jenkins_api
# ----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_jenkins_requires_credentials() -> None:
    result = await ht.run_jenkins_api("sid-no-creds", base_url="https://jenkins.example.com")
    assert "no jenkins credentials" in result["error"]


@pytest.mark.asyncio
async def test_jenkins_requires_token_and_user() -> None:
    at.set_kind_credentials_for_session("sid", {
        "kind": "cicd_pipeline", "provider": "jenkins",
        # Missing both token + jenkins_user
    })
    result = await ht.run_jenkins_api("sid", base_url="https://jenkins.example.com")
    assert "jenkins_user" in result["error"]


@pytest.mark.asyncio
async def test_jenkins_requires_jenkins_user() -> None:
    at.set_kind_credentials_for_session("sid", {
        "kind": "cicd_pipeline", "provider": "jenkins", "token": "tkn",
        # Missing jenkins_user
    })
    result = await ht.run_jenkins_api("sid", base_url="https://jenkins.example.com")
    assert "jenkins_user" in result["error"]


@pytest.mark.asyncio
async def test_jenkins_rejects_invalid_base_url() -> None:
    at.set_kind_credentials_for_session("sid", {
        "kind": "cicd_pipeline", "provider": "jenkins",
        "token": "tkn", "jenkins_user": "admin",
    })
    result = await ht.run_jenkins_api("sid", base_url="not-a-url")
    assert result["error"] == "invalid base_url"


# ----------------------------------------------------------------------------
# run_azure_pipelines_api
# ----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_azure_requires_credentials() -> None:
    result = await ht.run_azure_pipelines_api("sid-no-creds", organization="o", project="p")
    assert "no azure_pipelines credentials" in result["error"]


@pytest.mark.asyncio
async def test_azure_requires_token() -> None:
    at.set_kind_credentials_for_session("sid", {
        "kind": "cicd_pipeline", "provider": "azure_pipelines",
    })  # no token
    result = await ht.run_azure_pipelines_api("sid", organization="o", project="p")
    assert "PAT" in result["error"]


@pytest.mark.asyncio
async def test_azure_rejects_shell_metachars_in_org_project() -> None:
    at.set_kind_credentials_for_session("sid", {
        "kind": "cicd_pipeline", "provider": "azure_pipelines", "token": "azp_xxx",
    })
    # Path-segment injection attempt — slash in either field is rejected.
    result = await ht.run_azure_pipelines_api("sid", organization="o/../etc", project="p")
    assert result["error"] == "invalid organization"
    result = await ht.run_azure_pipelines_api("sid", organization="o", project="p; rm")
    assert result["error"] == "invalid project"


# ----------------------------------------------------------------------------
# run_circleci_api
# ----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_circleci_requires_credentials() -> None:
    result = await ht.run_circleci_api("sid-no-creds", project_slug="gh/owner/repo")
    assert "no circleci credentials" in result["error"]


@pytest.mark.asyncio
async def test_circleci_requires_token() -> None:
    at.set_kind_credentials_for_session("sid", {
        "kind": "cicd_pipeline", "provider": "circleci",
    })
    result = await ht.run_circleci_api("sid", project_slug="gh/o/r")
    assert "token" in result["error"]


@pytest.mark.asyncio
async def test_circleci_rejects_invalid_project_slug() -> None:
    at.set_kind_credentials_for_session("sid", {
        "kind": "cicd_pipeline", "provider": "circleci", "token": "cci_xxx",
    })
    # Missing segment.
    result = await ht.run_circleci_api("sid", project_slug="gh/owner")
    assert "invalid project_slug" in result["error"]
    # Shell metachar.
    result = await ht.run_circleci_api("sid", project_slug="gh/owner/repo;evil")
    assert "invalid project_slug" in result["error"]
    # Wrong VCS prefix.
    result = await ht.run_circleci_api("sid", project_slug="svn/owner/repo")
    assert "invalid vcs prefix" in result["error"]


@pytest.mark.asyncio
async def test_circleci_accepts_github_and_bitbucket_prefixes() -> None:
    """Verify both vcs prefixes pass past the validator (we don't actually hit
    the network — just check the input-validation branch returns past it)."""
    at.set_kind_credentials_for_session("sid", {
        "kind": "cicd_pipeline", "provider": "circleci", "token": "cci_xxx",
    })
    # Either path reaches the httpx call; we don't assert success here (no
    # network in tests), only that the validator doesn't reject the slug.
    for slug in ["gh/owner/repo", "github/owner/repo", "bb/owner/repo", "bitbucket/owner/repo"]:
        result = await ht.run_circleci_api("sid", project_slug=slug)
        # The validator path is the only code we control in test; once past it
        # we either succeed against circleci.com (unlikely in CI) or get a
        # network/HTTP error. Both are acceptable — the slug WAS valid.
        assert "invalid project_slug" not in result.get("error", "")
        assert "invalid vcs prefix" not in result.get("error", "")
