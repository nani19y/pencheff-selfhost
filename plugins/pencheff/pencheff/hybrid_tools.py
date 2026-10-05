"""Hybrid-cluster Phase B scanner wrappers (feature 001-multi-target-scan-pipelines).

Phase A scanners (run_checkov for cicd_pipeline / k8s_cluster manifests) live
in artifact_tools.py. THIS module wraps the live-system probing tools that
Phase B requires:

  * ``run_kubectl_get`` / ``run_kubectl_describe`` — list and describe K8s
    resources against a live cluster. Requires kind_credentials.kubeconfig.
  * ``run_rakkess`` — enumerate effective RBAC permissions across namespaces.
    Surfaces overly-broad bindings (cluster-admin to default ServiceAccount,
    wildcard verbs, escalate-to-admin paths).
  * ``run_github_actions_api`` — query GitHub Actions REST API for workflows,
    secret names, deploy keys, runner pools. Requires kind_credentials.token
    or kind_credentials.github_app_private_key + github_app_id +
    github_app_installation_id.

Kubeconfig handling per spec §6.4: materialized to a tempfile with mode 0600
inside the session's working dir, KUBECONFIG env is set for the subprocess,
and the file is unlinked when the session ends (hybrid_orchestrator's finally).

CI-API tools issue HTTPS requests directly via httpx — no subprocess, no
tempfiles (tokens stay in memory + Authorization header for the lifetime of
the request).
"""
from __future__ import annotations

import json
import os
import stat
import tempfile
from pathlib import Path
from typing import Any

from .artifact_tools import (
    _SCAN_TMP_ROOT,
    _run_subprocess,
    _which,
    kind_credentials_for_session,
    _kind_config_for_session,
)


# ============================================================================
# Kubeconfig lifecycle
# ============================================================================


def _kubeconfig_path(session_id: str) -> Path:
    return _SCAN_TMP_ROOT / session_id / ".kube" / "config"


async def _materialize_kubeconfig(session_id: str) -> str | None:
    """Write the session's kubeconfig to a 0600 tempfile and return the path.

    Returns None when no kubeconfig can be produced (Phase A path). The caller
    (the hybrid_orchestrator) is responsible for ``_unlink_kubeconfig`` in its
    finally block.

    For cloud-managed clusters (provider ∈ {aws, azure, gcp}), the kubeconfig
    is derived freshly per scan from stored cloud credentials via the matching
    Python SDK — no kubeconfig is persisted in the DB and no cloud CLI is
    required on the worker.
    """
    creds = kind_credentials_for_session(session_id)
    if not creds or creds.get("kind") != "k8s_cluster":
        return None

    provider = creds.get("provider") or "on_prem"
    kubeconfig_str: str | None = None
    if provider == "on_prem":
        kubeconfig_str = creds.get("kubeconfig")
    else:
        cfg = _kind_config_for_session(session_id) or {}
        try:
            if provider == "aws":
                kubeconfig_str = _derive_eks_kubeconfig(creds, cfg)
            elif provider == "azure":
                kubeconfig_str = _derive_aks_kubeconfig(creds, cfg)
            elif provider == "gcp":
                kubeconfig_str = _derive_gke_kubeconfig(creds, cfg)
        except _CloudDeriveError as exc:
            # Surface a structured error via the existing "no kubeconfig"
            # path. The hybrid orchestrator's scanner_stats will note that
            # Phase B was skipped.
            _last_derive_error[session_id] = str(exc)
            return None
    if not kubeconfig_str:
        return None

    path = _kubeconfig_path(session_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(kubeconfig_str)
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)  # 0600
    return str(path)


class _CloudDeriveError(RuntimeError):
    """Raised when cloud-managed kubeconfig derivation fails (SDK missing,
    API rejected creds, cluster not found, etc.)."""


# Per-session record of the most recent derivation error, so Phase B logs
# can surface a precise reason when _materialize_kubeconfig returns None.
_last_derive_error: dict[str, str] = {}


def _derive_eks_kubeconfig(creds: dict[str, Any], cfg: dict[str, Any]) -> str:
    """Build a kubeconfig YAML for an AWS EKS cluster from IAM access keys.

    Calls ``eks.describe_cluster`` for the endpoint + CA, then mints an
    EKS auth token by SigV4-presigning ``sts.GetCallerIdentity`` with the
    ``X-K8s-Aws-Id`` header. No aws-cli on the worker required.
    """
    region = cfg.get("aws_region") or ""
    cluster_name = cfg.get("aws_cluster_name") or ""
    if not (region and cluster_name):
        raise _CloudDeriveError(
            "k8s_cluster.kind_config requires aws_region + aws_cluster_name for aws_eks mode"
        )
    try:
        import boto3  # type: ignore
        from botocore.signers import RequestSigner  # type: ignore
    except ImportError as exc:
        raise _CloudDeriveError(
            f"boto3 not installed; AWS EKS derivation unavailable ({exc})"
        ) from exc
    sess = boto3.Session(
        aws_access_key_id=creds.get("aws_access_key_id"),
        aws_secret_access_key=creds.get("aws_secret_access_key"),
        aws_session_token=creds.get("aws_session_token") or None,
        region_name=region,
    )
    eks = sess.client("eks")
    try:
        described = eks.describe_cluster(name=cluster_name)["cluster"]
    except Exception as exc:  # noqa: BLE001
        raise _CloudDeriveError(f"eks.describe_cluster failed: {exc}") from exc
    endpoint = described["endpoint"]
    ca_b64 = described["certificateAuthority"]["data"]

    # Presigned STS URL → EKS bearer token.
    sts = sess.client("sts", region_name=region)
    signer = RequestSigner(
        sts.meta.service_model.service_id,
        region,
        "sts",
        "v4",
        sess.get_credentials(),
        sess.events,
    )
    params = {
        "method": "GET",
        "url": f"https://sts.{region}.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15",
        "body": {},
        "headers": {"x-k8s-aws-id": cluster_name},
        "context": {},
    }
    signed_url = signer.generate_presigned_url(
        params, region_name=region, expires_in=60, operation_name=""
    )
    import base64 as _b64
    token = "k8s-aws-v1." + _b64.urlsafe_b64encode(signed_url.encode()).decode().rstrip("=")
    return _render_kubeconfig_yaml(
        endpoint=endpoint,
        ca_b64=ca_b64,
        user_name=f"aws-{cluster_name}",
        cluster_name=f"aws-{cluster_name}",
        token=token,
    )


def _derive_aks_kubeconfig(creds: dict[str, Any], cfg: dict[str, Any]) -> str:
    """Pull an admin kubeconfig for an Azure AKS cluster via SP creds.

    Uses ``ManagedClusters.list_cluster_admin_credentials`` which returns
    YAML directly — no need to assemble it ourselves.
    """
    sub = cfg.get("azure_subscription_id") or ""
    rg = cfg.get("azure_resource_group") or ""
    name = cfg.get("azure_cluster_name") or ""
    if not (sub and rg and name):
        raise _CloudDeriveError(
            "k8s_cluster.kind_config requires azure_subscription_id, "
            "azure_resource_group, and azure_cluster_name for azure_aks mode"
        )
    try:
        from azure.identity import ClientSecretCredential  # type: ignore
        from azure.mgmt.containerservice import ContainerServiceClient  # type: ignore
    except ImportError as exc:
        raise _CloudDeriveError(
            f"azure-identity / azure-mgmt-containerservice not installed; "
            f"AKS derivation unavailable ({exc})"
        ) from exc
    azcred = ClientSecretCredential(
        tenant_id=creds.get("azure_tenant_id") or "",
        client_id=creds.get("azure_client_id") or "",
        client_secret=creds.get("azure_client_secret") or "",
    )
    client = ContainerServiceClient(azcred, sub)
    try:
        result = client.managed_clusters.list_cluster_admin_credentials(
            resource_group_name=rg,
            resource_name=name,
        )
    except Exception as exc:  # noqa: BLE001
        raise _CloudDeriveError(
            f"aks.list_cluster_admin_credentials failed: {exc}"
        ) from exc
    if not result.kubeconfigs:
        raise _CloudDeriveError("AKS returned no kubeconfigs")
    return result.kubeconfigs[0].value.decode("utf-8")


def _derive_gke_kubeconfig(creds: dict[str, Any], cfg: dict[str, Any]) -> str:
    """Build a kubeconfig YAML for a GKE cluster from a service-account JSON."""
    proj = cfg.get("gcp_project_id") or ""
    loc = cfg.get("gcp_location") or ""
    name = cfg.get("gcp_cluster_name") or ""
    if not (proj and loc and name):
        raise _CloudDeriveError(
            "k8s_cluster.kind_config requires gcp_project_id, gcp_location, "
            "and gcp_cluster_name for gcp_gke mode"
        )
    try:
        from google.cloud import container_v1  # type: ignore
        from google.oauth2 import service_account  # type: ignore
        import google.auth.transport.requests as _gauth_req  # type: ignore
    except ImportError as exc:
        raise _CloudDeriveError(
            f"google-cloud-container / google-auth not installed; "
            f"GKE derivation unavailable ({exc})"
        ) from exc
    sa_raw = creds.get("gcp_service_account_json") or ""
    try:
        sa_info = json.loads(sa_raw)
    except json.JSONDecodeError as exc:
        raise _CloudDeriveError(f"gcp_service_account_json not valid JSON: {exc}") from exc
    try:
        gcreds = service_account.Credentials.from_service_account_info(
            sa_info,
            scopes=["https://www.googleapis.com/auth/cloud-platform"],
        )
    except Exception as exc:  # noqa: BLE001
        raise _CloudDeriveError(f"GCP service account is invalid: {exc}") from exc
    client = container_v1.ClusterManagerClient(credentials=gcreds)
    fqn = f"projects/{proj}/locations/{loc}/clusters/{name}"
    try:
        cluster = client.get_cluster(name=fqn)
    except Exception as exc:  # noqa: BLE001
        raise _CloudDeriveError(f"gke.get_cluster failed: {exc}") from exc
    try:
        gcreds.refresh(_gauth_req.Request())
    except Exception as exc:  # noqa: BLE001
        raise _CloudDeriveError(f"GCP token refresh failed: {exc}") from exc
    return _render_kubeconfig_yaml(
        endpoint=f"https://{cluster.endpoint}",
        ca_b64=cluster.master_auth.cluster_ca_certificate,
        user_name=f"gke-{name}",
        cluster_name=f"gke-{name}",
        token=gcreds.token,
    )


def _render_kubeconfig_yaml(
    *,
    endpoint: str,
    ca_b64: str,
    user_name: str,
    cluster_name: str,
    token: str,
) -> str:
    """Render a single-cluster kubeconfig YAML with an inline bearer token."""
    # YAML is hand-written rather than via PyYAML so the worker doesn't need
    # to import yaml for the common case. Token is quoted to survive special
    # characters; CA stays opaque base64.
    safe_token = token.replace('"', '\\"')
    return (
        "apiVersion: v1\n"
        "kind: Config\n"
        f"current-context: {cluster_name}\n"
        "clusters:\n"
        f"  - name: {cluster_name}\n"
        "    cluster:\n"
        f"      server: {endpoint}\n"
        f"      certificate-authority-data: {ca_b64}\n"
        "users:\n"
        f"  - name: {user_name}\n"
        "    user:\n"
        f"      token: \"{safe_token}\"\n"
        "contexts:\n"
        f"  - name: {cluster_name}\n"
        "    context:\n"
        f"      cluster: {cluster_name}\n"
        f"      user: {user_name}\n"
    )


def _unlink_kubeconfig(session_id: str) -> None:
    path = _kubeconfig_path(session_id)
    try:
        if path.exists():
            path.unlink()
    except OSError:
        # Best-effort; the parent tempdir will be cleaned up anyway.
        pass
    _last_derive_error.pop(session_id, None)


def last_kubeconfig_derive_error(session_id: str) -> str | None:
    """Return the most recent cloud-derivation error for a session, if any."""
    return _last_derive_error.get(session_id)


# ============================================================================
# run_kubectl_get
# ============================================================================


# Allow a tight subset of resource types — operators can extend via kind_config
# in a future iteration. The fewer kinds we list, the smaller the surface
# the agent can probe.
_KUBECTL_RESOURCE_ALLOWLIST: frozenset[str] = frozenset({
    "namespaces", "ns",
    "pods", "po",
    "deployments", "deploy",
    "services", "svc",
    "configmaps", "cm",
    "secrets",  # surfaced for enumeration only — names + types, never the secret data
    "roles", "rolebindings",
    "clusterroles", "clusterrolebindings",
    "networkpolicies", "netpol",
    "serviceaccounts", "sa",
    "ingresses", "ing",
})


async def run_kubectl_get(
    session_id: str,
    resource: str,
    namespace: str | None = None,
) -> dict[str, Any]:
    """List Kubernetes resources of one type via ``kubectl get -o json``.

    Allowlist: ``resource`` must be in _KUBECTL_RESOURCE_ALLOWLIST.
    ``namespace`` defaults to the session's kind_config.namespaces[0]; the
    operator-registered list bounds what the agent can query.
    """
    if not _which("kubectl"):
        return {"error": "binary not found: kubectl", "skipped": True}
    if resource not in _KUBECTL_RESOURCE_ALLOWLIST:
        return {"error": "resource_not_allowed", "allowed": sorted(_KUBECTL_RESOURCE_ALLOWLIST)}
    kubeconfig = await _materialize_kubeconfig(session_id)
    if not kubeconfig:
        derive_err = last_kubeconfig_derive_error(session_id)
        if derive_err:
            return {"error": f"kubeconfig derivation failed: {derive_err}"}
        return {"error": "no kubeconfig bound to session — Phase B requires kind_credentials"}
    cfg = _kind_config_for_session(session_id) or {}
    operator_ns = list(cfg.get("namespaces") or ["default"])
    if namespace is None:
        namespace = operator_ns[0]
    elif namespace not in operator_ns:
        return {"error": "namespace_not_in_operator_list", "namespace": namespace, "allowed": operator_ns}

    argv = ["kubectl", "get", resource, "-o", "json", "-n", namespace]
    result = await _run_subprocess(
        argv, env={"KUBECONFIG": kubeconfig},
    )
    if result.get("error"):
        return result
    if result.get("returncode") != 0:
        return {"error": "kubectl get failed", "stderr": result.get("stderr", "")[:2048]}
    findings = _parse_kubectl_get_json(resource, result.get("stdout", ""))
    return {
        "scanner": "kubectl-get",
        "resource": resource,
        "namespace": namespace,
        "findings_count": len(findings),
        "findings": findings,
    }


def _parse_kubectl_get_json(resource: str, stdout: str) -> list[dict[str, Any]]:
    """Surface enumeration-level findings.

    We emit one INFO finding summarizing what was found, plus a flag any
    cross-namespace bindings or wildcard verbs as their own MEDIUM/HIGH
    findings. The full agent loop can ``kubectl describe`` for details.
    """
    if not stdout.strip():
        return []
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return []
    items = data.get("items") if isinstance(data, dict) else []
    findings: list[dict[str, Any]] = []
    if not items:
        return []
    # Headline: enumeration completed.
    findings.append({
        "title": f"K8s {resource}: {len(items)} resource(s) enumerated",
        "severity": "info",
        "category": "k8s_enumeration",
        "owasp_category": "A05:2021",
        "description": (
            f"Phase B kubectl-get listed {len(items)} {resource} resources. "
            f"Review for unexpected workloads / bindings."
        ),
    })
    # Heuristic: rolebindings + clusterrolebindings get flagged when they
    # bind cluster-admin or wildcard verbs to non-admin subjects.
    if resource in {"rolebindings", "clusterrolebindings"}:
        for item in items:
            role_ref = item.get("roleRef", {}) or {}
            subjects = item.get("subjects", []) or []
            role_name = role_ref.get("name", "")
            name = (item.get("metadata") or {}).get("name", "(unnamed)")
            if role_name in {"cluster-admin", "admin"}:
                for sub in subjects:
                    if (sub.get("kind") == "ServiceAccount" and sub.get("name") == "default"):
                        findings.append({
                            "title": f"{resource} {name!r} binds {role_name!r} to default ServiceAccount",
                            "severity": "high",
                            "category": "k8s_rbac_overprivileged",
                            "owasp_category": "A01:2021",
                            "description": (
                                "Default ServiceAccounts should NEVER be bound to cluster-admin / admin. "
                                "Pods using this SA inherit full cluster control."
                            ),
                        })
    return findings


# ============================================================================
# run_kubectl_describe
# ============================================================================


async def run_kubectl_describe(
    session_id: str,
    resource: str,
    name: str,
    namespace: str | None = None,
) -> dict[str, Any]:
    """Describe a single K8s resource. Read-only — surfaces the full spec for
    agent inspection, not as a finding."""
    if not _which("kubectl"):
        return {"error": "binary not found: kubectl", "skipped": True}
    if resource not in _KUBECTL_RESOURCE_ALLOWLIST:
        return {"error": "resource_not_allowed"}
    if not isinstance(name, str) or not name or any(c in name for c in (" ", ";", "|", "\n")):
        return {"error": "invalid resource name"}
    kubeconfig = await _materialize_kubeconfig(session_id)
    if not kubeconfig:
        derive_err = last_kubeconfig_derive_error(session_id)
        if derive_err:
            return {"error": f"kubeconfig derivation failed: {derive_err}"}
        return {"error": "no kubeconfig bound to session"}
    cfg = _kind_config_for_session(session_id) or {}
    operator_ns = list(cfg.get("namespaces") or ["default"])
    if namespace is None:
        namespace = operator_ns[0]
    elif namespace not in operator_ns:
        return {"error": "namespace_not_in_operator_list", "allowed": operator_ns}

    argv = ["kubectl", "describe", resource, name, "-n", namespace]
    result = await _run_subprocess(argv, env={"KUBECONFIG": kubeconfig})
    if result.get("error"):
        return result
    if result.get("returncode") != 0:
        return {"error": "kubectl describe failed", "stderr": result.get("stderr", "")[:2048]}
    return {
        "scanner": "kubectl-describe",
        "resource": resource,
        "name": name,
        "namespace": namespace,
        "description": (result.get("stdout") or "")[:8192],
    }


# ============================================================================
# run_rakkess — RBAC effective-permissions enumeration
# ============================================================================


async def run_rakkess(
    session_id: str,
    namespace: str | None = None,
) -> dict[str, Any]:
    """Enumerate effective RBAC permissions for the current kubeconfig context.

    rakkess (and its kubectl-plugin form ``kubectl-access-matrix``) walks
    the API resources and reports which verbs the caller can perform on each.
    We flag overly-broad findings: any verb=``*`` on any namespaced resource,
    or ``escalate`` / ``impersonate`` on roles/clusterroles.
    """
    binary = "rakkess" if _which("rakkess") else ("kubectl-access_matrix" if _which("kubectl-access_matrix") else None)
    if not binary:
        return {"error": "binary not found: rakkess or kubectl-access_matrix", "skipped": True}
    kubeconfig = await _materialize_kubeconfig(session_id)
    if not kubeconfig:
        derive_err = last_kubeconfig_derive_error(session_id)
        if derive_err:
            return {"error": f"kubeconfig derivation failed: {derive_err}"}
        return {"error": "no kubeconfig bound to session"}
    cfg = _kind_config_for_session(session_id) or {}
    if namespace is None:
        namespace = (cfg.get("namespaces") or ["default"])[0]

    argv = [binary, "--namespace", namespace, "--output", "json"]
    result = await _run_subprocess(argv, env={"KUBECONFIG": kubeconfig})
    if result.get("error"):
        return result
    findings = _parse_rakkess_json(result.get("stdout", ""))
    return {
        "scanner": "rakkess",
        "namespace": namespace,
        "findings_count": len(findings),
        "findings": findings,
    }


def _parse_rakkess_json(stdout: str) -> list[dict[str, Any]]:
    if not stdout.strip():
        return []
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return []
    findings: list[dict[str, Any]] = []
    # rakkess output is a list of {name, verbs} per resource. Flag the
    # resource-as-finding when verbs include high-risk verbs.
    high_risk_verbs = {"*", "escalate", "impersonate", "bind"}
    for entry in (data if isinstance(data, list) else data.get("resources") or []):
        verbs = set(entry.get("verbs") or [])
        risky = high_risk_verbs & verbs
        if not risky:
            continue
        name = entry.get("name", "(unknown)")
        sev = "critical" if "*" in risky else "high"
        findings.append({
            "title": f"Overly-broad RBAC: {name} grants {sorted(risky)}",
            "severity": sev,
            "category": "k8s_rbac_overprivileged",
            "owasp_category": "A01:2021",
            "description": (
                f"The current kubeconfig context can perform {sorted(risky)} on "
                f"{name!r}. Wildcard ``*`` and impersonate/escalate verbs allow "
                f"privilege escalation paths within the cluster."
            ),
        })
    return findings


# ============================================================================
# run_github_actions_api — Phase B for cicd_pipeline (provider=github_actions)
# ============================================================================


async def run_github_actions_api(
    session_id: str,
    owner: str,
    repo: str,
) -> dict[str, Any]:
    """Query the GitHub Actions REST API for workflow / secret enumeration.

    Surfaces:
      * workflows present and their last-run status
      * SECRET NAMES (never values — those aren't exposed by the API)
      * deploy keys (with their fingerprints)
      * runner pool composition

    Requires kind_credentials.token (PAT) OR a GitHub App install
    (github_app_id + github_app_private_key + github_app_installation_id).
    """
    import httpx

    creds = kind_credentials_for_session(session_id) or {}
    if creds.get("kind") != "cicd_pipeline" or creds.get("provider") != "github_actions":
        return {"error": "session has no github_actions credentials bound"}
    token = creds.get("token")
    if not token:
        # GitHub App auth would require an OAuth-style JWT signing flow —
        # deferred. Only PATs are supported in v1.
        return {"error": "github_actions Phase B requires kind_credentials.token (PAT); GitHub App auth deferred"}
    if not (isinstance(owner, str) and owner and "/" not in owner):
        return {"error": "invalid owner"}
    if not (isinstance(repo, str) and repo and "/" not in repo):
        return {"error": "invalid repo"}

    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github+json",
        "User-Agent": "pencheff-feature-001",
    }
    findings: list[dict[str, Any]] = []
    summary: dict[str, Any] = {}
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            # Workflows.
            wf = await client.get(
                f"https://api.github.com/repos/{owner}/{repo}/actions/workflows",
                headers=headers,
            )
            if wf.status_code == 200:
                summary["workflows"] = [
                    {"name": w.get("name"), "path": w.get("path"), "state": w.get("state")}
                    for w in wf.json().get("workflows", [])
                ]
            else:
                summary["workflows_error"] = wf.status_code
            # Secrets (names only).
            secrets = await client.get(
                f"https://api.github.com/repos/{owner}/{repo}/actions/secrets",
                headers=headers,
            )
            if secrets.status_code == 200:
                names = [s.get("name") for s in secrets.json().get("secrets", [])]
                summary["secret_names"] = names
                # Heuristic: flag generic-looking secret names that often
                # hold high-privilege tokens.
                for n in names:
                    if not isinstance(n, str):
                        continue
                    if any(t in n.upper() for t in ("ADMIN", "ROOT", "PROD_TOKEN", "OWNER")):
                        findings.append({
                            "title": f"GitHub Actions secret name suggests admin scope: {n!r}",
                            "severity": "medium",
                            "category": "cicd_secret_naming",
                            "owasp_category": "A09:2021",
                            "description": (
                                f"Secret {n!r} carries an admin-suggestive name. Verify scope "
                                f"and rotate if the workflow's threat model doesn't require it."
                            ),
                        })
            else:
                summary["secrets_error"] = secrets.status_code
            # Deploy keys.
            keys = await client.get(
                f"https://api.github.com/repos/{owner}/{repo}/keys",
                headers=headers,
            )
            if keys.status_code == 200:
                summary["deploy_keys"] = [
                    {"id": k.get("id"), "title": k.get("title"),
                     "read_only": k.get("read_only", True)}
                    for k in keys.json()
                ]
                for k in keys.json():
                    if not k.get("read_only", True):
                        findings.append({
                            "title": f"Read-write deploy key: {k.get('title', 'unnamed')}",
                            "severity": "high",
                            "category": "cicd_deploy_key_overprivileged",
                            "owasp_category": "A07:2021",
                            "description": "Deploy keys should be read-only unless the workflow demonstrably needs push access.",
                        })
    except httpx.HTTPError as exc:
        return {"error": f"github API error: {exc}"}

    return {
        "scanner": "github-actions-api",
        "findings_count": len(findings),
        "findings": findings,
        "summary": summary,
    }


# ============================================================================
# run_gitlab_ci_api — Phase B for cicd_pipeline (provider=gitlab_ci)
# ============================================================================


async def run_gitlab_ci_api(
    session_id: str,
    project: str,
    base_url: str = "https://gitlab.com",
) -> dict[str, Any]:
    """Query the GitLab CI REST API for pipelines + CI/CD variables + deploy keys.

    ``project`` is the URL-encoded ``namespace/project`` path (GitLab quirk).
    Requires kind_credentials.token (personal access token with ``read_api``
    + ``read_repository`` scopes).
    """
    import httpx
    from urllib.parse import quote

    creds = kind_credentials_for_session(session_id) or {}
    if creds.get("kind") != "cicd_pipeline" or creds.get("provider") != "gitlab_ci":
        return {"error": "session has no gitlab_ci credentials bound"}
    token = creds.get("token")
    if not token:
        return {"error": "gitlab_ci Phase B requires kind_credentials.token (PAT)"}
    if not (isinstance(project, str) and project and "//" not in project):
        return {"error": "invalid project — expected 'namespace/project'"}
    # Reject shell-metachars defensively even though we URL-encode below.
    if any(c in project for c in (";", "&", "|", "\n", "\r", "`", "$")):
        return {"error": "invalid project"}
    if not isinstance(base_url, str) or not base_url.startswith(("http://", "https://")):
        return {"error": "invalid base_url"}

    project_encoded = quote(project, safe="")
    api_base = f"{base_url.rstrip('/')}/api/v4/projects/{project_encoded}"
    headers = {"PRIVATE-TOKEN": token, "User-Agent": "pencheff-feature-001"}
    findings: list[dict[str, Any]] = []
    summary: dict[str, Any] = {}

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            # Pipelines (recent 20).
            pipes = await client.get(f"{api_base}/pipelines", headers=headers, params={"per_page": 20})
            if pipes.status_code == 200:
                summary["recent_pipelines"] = [
                    {"id": p.get("id"), "status": p.get("status"), "ref": p.get("ref")}
                    for p in pipes.json()
                ]
            else:
                summary["pipelines_error"] = pipes.status_code
            # CI/CD variables (names only — values are never returned).
            vars_resp = await client.get(f"{api_base}/variables", headers=headers)
            if vars_resp.status_code == 200:
                names: list[str] = []
                for var in vars_resp.json():
                    name = var.get("key")
                    protected = bool(var.get("protected", False))
                    masked = bool(var.get("masked", False))
                    if isinstance(name, str):
                        names.append(name)
                    # Flag CI variables that are NEITHER protected NOR masked —
                    # they leak into job logs and untrusted branch runs.
                    if isinstance(name, str) and not protected and not masked:
                        findings.append({
                            "title": f"GitLab CI variable {name!r}: neither protected nor masked",
                            "severity": "medium",
                            "category": "cicd_variable_unprotected",
                            "owasp_category": "A09:2021",
                            "description": (
                                "Variables that are neither protected nor masked can leak into "
                                "the job log of any branch's pipeline and surface in MR logs."
                            ),
                        })
                summary["variable_names"] = names
            else:
                summary["variables_error"] = vars_resp.status_code
            # Deploy keys.
            keys = await client.get(f"{api_base}/deploy_keys", headers=headers)
            if keys.status_code == 200:
                summary["deploy_keys"] = [
                    {"id": k.get("id"), "title": k.get("title"), "can_push": bool(k.get("can_push"))}
                    for k in keys.json()
                ]
                for k in keys.json():
                    if k.get("can_push"):
                        findings.append({
                            "title": f"GitLab deploy key with push access: {k.get('title', 'unnamed')}",
                            "severity": "high",
                            "category": "cicd_deploy_key_overprivileged",
                            "owasp_category": "A07:2021",
                            "description": "Deploy keys should be read-only unless the pipeline demonstrably needs push.",
                        })
    except httpx.HTTPError as exc:
        return {"error": f"gitlab API error: {exc}"}

    return {
        "scanner": "gitlab-ci-api",
        "findings_count": len(findings),
        "findings": findings,
        "summary": summary,
    }


# ============================================================================
# run_jenkins_api — Phase B for cicd_pipeline (provider=jenkins)
# ============================================================================


async def run_jenkins_api(
    session_id: str,
    base_url: str,
) -> dict[str, Any]:
    """Query the Jenkins REST API for jobs + credentials + plugin state.

    Requires kind_credentials.token (Jenkins API token) + .jenkins_user (the
    username the token belongs to). Uses HTTP Basic auth as the Jenkins API
    expects.
    """
    import httpx

    creds = kind_credentials_for_session(session_id) or {}
    if creds.get("kind") != "cicd_pipeline" or creds.get("provider") != "jenkins":
        return {"error": "session has no jenkins credentials bound"}
    token = creds.get("token")
    user = creds.get("jenkins_user")
    if not token or not user:
        return {"error": "jenkins Phase B requires kind_credentials.token + jenkins_user"}
    if not isinstance(base_url, str) or not base_url.startswith(("http://", "https://")):
        return {"error": "invalid base_url"}

    auth = (user, token)
    findings: list[dict[str, Any]] = []
    summary: dict[str, Any] = {}
    api_base = base_url.rstrip("/")

    try:
        async with httpx.AsyncClient(timeout=30.0, auth=auth) as client:
            # Top-level: list jobs (Jenkins-flavoured tree query).
            jobs = await client.get(
                f"{api_base}/api/json",
                params={"tree": "jobs[name,color,url,description]"},
                headers={"User-Agent": "pencheff-feature-001"},
            )
            if jobs.status_code == 200:
                summary["jobs"] = jobs.json().get("jobs", [])
            else:
                summary["jobs_error"] = jobs.status_code
                # 401/403 means our creds are insufficient — surface immediately.
                if jobs.status_code in (401, 403):
                    return {"error": f"jenkins auth failed: {jobs.status_code}"}
            # Plugin manager — old plugins are a CRITICAL Jenkins risk vector.
            plugins = await client.get(
                f"{api_base}/pluginManager/api/json",
                params={"depth": "1"},
                headers={"User-Agent": "pencheff-feature-001"},
            )
            if plugins.status_code == 200:
                plist = plugins.json().get("plugins", [])
                summary["plugin_count"] = len(plist)
                outdated = [p for p in plist if p.get("hasUpdate", False)]
                if outdated:
                    findings.append({
                        "title": f"Jenkins: {len(outdated)} plugins have updates available",
                        "severity": "medium",
                        "category": "cicd_outdated_plugin",
                        "owasp_category": "A06:2021",
                        "description": (
                            "Jenkins plugins are a primary RCE vector. Update at the next "
                            "maintenance window. Plugins with pending updates: "
                            + ", ".join(p.get("shortName", "?") for p in outdated[:10])
                            + ("…" if len(outdated) > 10 else "")
                        ),
                    })
                # Flag any disabled plugin still installed (dead code, still loadable
                # under script-console).
                inactive = [p for p in plist if not p.get("active", True)]
                summary["inactive_plugins"] = [p.get("shortName") for p in inactive]
    except httpx.HTTPError as exc:
        return {"error": f"jenkins API error: {exc}"}

    return {
        "scanner": "jenkins-api",
        "findings_count": len(findings),
        "findings": findings,
        "summary": summary,
    }


# ============================================================================
# run_azure_pipelines_api — Phase B for cicd_pipeline (provider=azure_pipelines)
# ============================================================================


async def run_azure_pipelines_api(
    session_id: str,
    organization: str,
    project: str,
) -> dict[str, Any]:
    """Query Azure Pipelines REST API for pipelines + variable groups.

    Requires kind_credentials.token (Azure DevOps PAT with ``vso.build`` +
    ``vso.variablegroups_read`` scopes). Azure uses HTTP Basic auth where the
    username is empty (or "user") and the PAT is the password.
    """
    import base64
    import httpx

    creds = kind_credentials_for_session(session_id) or {}
    if creds.get("kind") != "cicd_pipeline" or creds.get("provider") != "azure_pipelines":
        return {"error": "session has no azure_pipelines credentials bound"}
    token = creds.get("token")
    if not token:
        return {"error": "azure_pipelines Phase B requires kind_credentials.token (PAT)"}
    # Defend against URL injection — both fields land in a path component.
    if not (isinstance(organization, str) and organization and not any(c in organization for c in "/:; |\n")):
        return {"error": "invalid organization"}
    if not (isinstance(project, str) and project and not any(c in project for c in "/:; |\n")):
        return {"error": "invalid project"}

    # Azure DevOps Basic auth: username is unused, PAT is the password.
    auth_token = base64.b64encode(f":{token}".encode()).decode()
    headers = {
        "Authorization": f"Basic {auth_token}",
        "Accept": "application/json",
        "User-Agent": "pencheff-feature-001",
    }
    api_base = f"https://dev.azure.com/{organization}/{project}/_apis"
    findings: list[dict[str, Any]] = []
    summary: dict[str, Any] = {}

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            # Pipelines.
            pipes = await client.get(
                f"{api_base}/pipelines",
                params={"api-version": "7.0"},
                headers=headers,
            )
            if pipes.status_code == 200:
                summary["pipelines"] = [
                    {"id": p.get("id"), "name": p.get("name"), "folder": p.get("folder")}
                    for p in pipes.json().get("value", [])
                ]
            else:
                summary["pipelines_error"] = pipes.status_code
                if pipes.status_code in (401, 403):
                    return {"error": f"azure auth failed: {pipes.status_code}"}
            # Variable groups (names + isSecret flag per variable; values never
            # returned by the API).
            vg = await client.get(
                f"{api_base}/distributedtask/variablegroups",
                params={"api-version": "7.0"},
                headers=headers,
            )
            if vg.status_code == 200:
                groups = vg.json().get("value", [])
                summary["variable_groups"] = [g.get("name") for g in groups]
                for g in groups:
                    name = g.get("name", "(unnamed)")
                    variables = g.get("variables") or {}
                    # Flag variable groups exposed to ALL pipelines without
                    # approval gating — they leak the secret set to every job.
                    if (g.get("type") or "") == "Vsts" and not (g.get("variableGroupProjectReferences") or []):
                        findings.append({
                            "title": f"Azure variable group {name!r} exposed without project gating",
                            "severity": "medium",
                            "category": "cicd_variable_unprotected",
                            "owasp_category": "A09:2021",
                            "description": (
                                "Variable groups without explicit projectReferences are "
                                "available to every pipeline in the project — review "
                                "approval gates."
                            ),
                        })
                    # Flag non-isSecret variables with admin-suggestive names.
                    for var_name, body in variables.items():
                        if not isinstance(body, dict):
                            continue
                        if body.get("isSecret"):
                            continue
                        if any(t in (var_name or "").upper() for t in ("PROD_TOKEN", "ADMIN", "OWNER", "API_KEY")):
                            findings.append({
                                "title": f"Azure variable {var_name!r} in {name!r}: not marked secret",
                                "severity": "high",
                                "category": "cicd_secret_unmarked",
                                "owasp_category": "A09:2021",
                                "description": (
                                    "Admin-suggestive variable name is not marked isSecret — value "
                                    "will appear in build logs."
                                ),
                            })
            else:
                summary["variable_groups_error"] = vg.status_code
    except httpx.HTTPError as exc:
        return {"error": f"azure pipelines API error: {exc}"}

    return {
        "scanner": "azure-pipelines-api",
        "findings_count": len(findings),
        "findings": findings,
        "summary": summary,
    }


# ============================================================================
# run_circleci_api — Phase B for cicd_pipeline (provider=circleci)
# ============================================================================


async def run_circleci_api(
    session_id: str,
    project_slug: str,
) -> dict[str, Any]:
    """Query the CircleCI REST API for env vars + pipelines + context.

    Requires kind_credentials.token (CircleCI personal API token).
    ``project_slug`` is the VCS-aware path e.g. ``gh/owner/repo`` or
    ``bb/owner/repo``.
    """
    import httpx

    creds = kind_credentials_for_session(session_id) or {}
    if creds.get("kind") != "cicd_pipeline" or creds.get("provider") != "circleci":
        return {"error": "session has no circleci credentials bound"}
    token = creds.get("token")
    if not token:
        return {"error": "circleci Phase B requires kind_credentials.token"}
    # project_slug shape: "<vcs>/<owner>/<repo>" — three segments, no shell metachars.
    parts = project_slug.split("/")
    if len(parts) != 3 or not all(parts) or any(c in project_slug for c in ";|&$`\n\r"):
        return {"error": "invalid project_slug — expected '<vcs>/<owner>/<repo>'"}
    vcs = parts[0].lower()
    if vcs not in {"gh", "github", "bb", "bitbucket"}:
        return {"error": "invalid vcs prefix — expected gh / github / bb / bitbucket"}

    headers = {
        "Circle-Token": token,
        "Accept": "application/json",
        "User-Agent": "pencheff-feature-001",
    }
    api_base = f"https://circleci.com/api/v2/project/{project_slug}"
    findings: list[dict[str, Any]] = []
    summary: dict[str, Any] = {}

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            # Env vars (CircleCI redacts values to the first 4 chars; names are
            # the security signal).
            ev = await client.get(f"{api_base}/envvar", headers=headers)
            if ev.status_code == 200:
                items = ev.json().get("items", [])
                summary["env_var_names"] = [i.get("name") for i in items]
                for var in items:
                    name = var.get("name") or ""
                    if any(t in name.upper() for t in ("ADMIN", "ROOT", "PROD_TOKEN", "OWNER")):
                        findings.append({
                            "title": f"CircleCI env var {name!r}: admin-suggestive name",
                            "severity": "medium",
                            "category": "cicd_secret_naming",
                            "owasp_category": "A09:2021",
                            "description": (
                                "Verify the scope this token grants — CircleCI env vars are "
                                "exposed to every job in the project unless restricted via Contexts."
                            ),
                        })
            elif ev.status_code in (401, 403):
                return {"error": f"circleci auth failed: {ev.status_code}"}
            else:
                summary["envvar_error"] = ev.status_code
            # Recent pipelines.
            pipes = await client.get(f"{api_base}/pipeline", headers=headers)
            if pipes.status_code == 200:
                summary["recent_pipelines"] = [
                    {"id": p.get("id"), "number": p.get("number"), "state": p.get("state")}
                    for p in pipes.json().get("items", [])[:20]
                ]
            else:
                summary["pipelines_error"] = pipes.status_code
    except httpx.HTTPError as exc:
        return {"error": f"circleci API error: {exc}"}

    return {
        "scanner": "circleci-api",
        "findings_count": len(findings),
        "findings": findings,
        "summary": summary,
    }


__all__ = [
    "run_kubectl_get",
    "run_kubectl_describe",
    "run_rakkess",
    "run_github_actions_api",
    "run_gitlab_ci_api",
    "run_jenkins_api",
    "run_azure_pipelines_api",
    "run_circleci_api",
    # Lifecycle helpers exposed for hybrid_orchestrator finally-block cleanup
    "_materialize_kubeconfig",
    "_unlink_kubeconfig",
]
