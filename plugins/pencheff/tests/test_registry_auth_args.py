"""Unit tests for ``_skopeo_src_auth_args`` — the registry-auth fragment
builder consumed by ``artifact_pull_image`` before invoking ``skopeo copy``.

Covers every supported auth_type:
  * basic / token  → ``--src-creds <u>:<p>``
  * gcr_service_account → ``--src-creds _json_key:<SA_JSON>``
  * acr_sp → ``--src-creds <client_id>:<client_secret>``
  * docker_config → ``--src-authfile <tempfile>`` (file must be 0600)

The ECR branch is not exercised here because it shells out to boto3; that
path is covered separately when the [cloud] extras are installed.
"""
from __future__ import annotations

import os
import stat

from pencheff.artifact_tools import _skopeo_src_auth_args


def test_no_creds_returns_empty_args():
    args, tf, err = _skopeo_src_auth_args(None)
    assert args == []
    assert tf is None
    assert err is None


def test_wrong_kind_returns_empty_args():
    args, tf, err = _skopeo_src_auth_args({"kind": "k8s_cluster", "kubeconfig": "..."})
    assert args == []
    assert tf is None
    assert err is None


def test_basic_auth_builds_src_creds():
    args, tf, err = _skopeo_src_auth_args({
        "kind": "container_image",
        "registry_host": "ghcr.io",
        "auth_type": "basic",
        "username": "alice",
        "password_or_token": "ghp_abc",
    })
    assert args == ["--src-creds", "alice:ghp_abc"]
    assert tf is None
    assert err is None


def test_basic_auth_empty_password_skipped():
    """Empty creds should fall through to anonymous pulls, not error."""
    args, tf, err = _skopeo_src_auth_args({
        "kind": "container_image",
        "registry_host": "index.docker.io",
        "auth_type": "basic",
        "username": "alice",
        "password_or_token": "",
    })
    assert args == []
    assert err is None


def test_token_auth_defaults_username():
    args, tf, err = _skopeo_src_auth_args({
        "kind": "container_image",
        "registry_host": "registry.example.com",
        "auth_type": "token",
        "password_or_token": "tok_xyz",
    })
    assert args == ["--src-creds", "token:tok_xyz"]


def test_gcr_service_account_passes_json_as_password():
    sa = '{"type":"service_account","project_id":"x"}'
    args, tf, err = _skopeo_src_auth_args({
        "kind": "container_image",
        "registry_host": "gcr.io",
        "auth_type": "gcr_service_account",
        "gcr_service_account_json": sa,
    })
    assert args == ["--src-creds", f"_json_key:{sa}"]
    assert err is None


def test_gcr_missing_json_errors():
    args, tf, err = _skopeo_src_auth_args({
        "kind": "container_image",
        "registry_host": "gcr.io",
        "auth_type": "gcr_service_account",
    })
    assert args == []
    assert err and "gcr_service_account_json" in err


def test_acr_sp_uses_client_creds_as_basic_auth():
    args, tf, err = _skopeo_src_auth_args({
        "kind": "container_image",
        "registry_host": "myreg.azurecr.io",
        "auth_type": "acr_sp",
        "acr_client_id": "cid",
        "acr_client_secret": "secret",
    })
    assert args == ["--src-creds", "cid:secret"]


def test_acr_sp_missing_secret_errors():
    args, tf, err = _skopeo_src_auth_args({
        "kind": "container_image",
        "registry_host": "myreg.azurecr.io",
        "auth_type": "acr_sp",
        "acr_client_id": "cid",
    })
    assert args == []
    assert err and "acr_sp" in err


def test_docker_config_writes_mode_0600_tempfile():
    args, tf, err = _skopeo_src_auth_args({
        "kind": "container_image",
        "registry_host": "registry.example.com",
        "auth_type": "docker_config",
        "docker_config_json": '{"auths":{"registry.example.com":{"auth":"abc"}}}',
    })
    try:
        assert err is None
        assert tf is not None
        assert tf.exists()
        # mode 0600 — read/write owner only.
        st = os.stat(tf)
        assert stat.S_IMODE(st.st_mode) == 0o600
        assert args[0] == "--src-authfile"
        assert args[1] == str(tf)
    finally:
        if tf is not None and tf.exists():
            tf.unlink()


def test_unknown_auth_type_errors():
    args, tf, err = _skopeo_src_auth_args({
        "kind": "container_image",
        "registry_host": "x.io",
        "auth_type": "novel",
    })
    assert args == []
    assert err and "novel" in err
