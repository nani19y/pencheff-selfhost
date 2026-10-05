"""Static contract tests for the web target edit page.

The web app does not currently have a JS unit-test runner, so backend tests
guard small cross-app contracts that commonly drift when new target kinds land.
"""
from __future__ import annotations

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[3]
EDIT_PAGE = REPO_ROOT / "apps/web/app/targets/[id]/edit/page.tsx"
NEW_TARGET_PAGE = REPO_ROOT / "apps/web/app/targets/new/page.tsx"

CLOUD_KINDS = {
    "cloud_account",
    "serverless_function",
    "cloud_storage",
    "load_balancer_cdn",
    "cloud_database",
    "secrets_manager",
}


def test_cloud_target_kinds_are_editable_in_web_edit_page() -> None:
    source = EDIT_PAGE.read_text()

    assert "CloudFormSection" in source
    assert "finalizeCloudDraft" in source
    for kind in CLOUD_KINDS:
        assert f'"{kind}"' in source


def test_memory_target_kind_is_editable_in_web_edit_page() -> None:
    source = EDIT_PAGE.read_text()

    assert "MemoryFormSection" in source
    assert '"memory"' in source


def test_llm_edit_page_reuses_register_form_section() -> None:
    source = EDIT_PAGE.read_text()

    assert "LlmFormSection" in source


def test_repo_attachments_are_not_url_only_on_target_edit_page() -> None:
    source = EDIT_PAGE.read_text()

    assert "canAttachRepos(kind)" in source
    assert "payload.attached_repository_ids = attachedRepoIds" in source
    assert 'kind === "url" &&' not in source


def test_repo_attachments_are_sent_for_runtime_targets_on_register_page() -> None:
    source = NEW_TARGET_PAGE.read_text()

    assert "attached_repository_ids: attachedRepoIds" in source
    assert "canAttachReposForKind" in source
