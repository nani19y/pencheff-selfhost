# k8s multi-provider creds + container-image registry auth — design

**Status:** approved 2026-05-21 · scope confirmed Part A only

## Problem

Two target kinds register fine but can't actually be scanned against real assets:

1. **`k8s_cluster`** — only accepts a pasted kubeconfig YAML. Customers running EKS / AKS / GKE expect to give us cloud credentials and a cluster name; we should derive the kubeconfig at scan time. On-prem cluster operators still need the paste-kubeconfig path.

2. **`container_image`** — UI asks for the registry type (Docker Hub / GHCR / ECR / GCR / ACR / custom) but never collects credentials. Backend `RegistryCreds` schema already exists but isn't surfaced. `artifact_pull_image` calls `skopeo copy` with no auth, so only public images work.

The originating ask listed many additional discipline-style features (AI-SPM, CSPM, KSPM, ASPM, …). Those are coming-soon placeholders on existing target cards or aren't asset-registrable concepts. Scope confirmed with the user: **fix k8s + container image; defer discipline-style features.**

## Goals

- K8s target supports four credential modes: `on_prem` (kubeconfig paste, today's behaviour), `aws_eks`, `azure_aks`, `gcp_gke`.
- Cloud modes collect cloud creds + cluster identifiers, store them encrypted, and the scan worker derives a fresh kubeconfig per scan.
- Container-image target collects registry credentials per registry type and authenticates skopeo at pull time.
- No DB migration. Existing live-cluster rows continue to work.

## Non-goals

- No new discipline categories (AI-SPM, CSPM badges, etc.).
- No CLI shell-out to `aws` / `az` / `gcloud` / `kubectl-cli-derived kubeconfig`. We use Python SDKs.
- No EKS Pod Identity / IRSA paths — only static IAM creds in v1.
- No GKE Workload Identity Federation — only service-account JSON in v1.
- No registry-credential rotation or expiry surfacing in the UI beyond the standard error.

## Schema changes (`apps/api/pencheff_api/schemas/targets.py`)

### `K8sClusterConfig`

Extend `target` literal:

```python
target: Literal[
    "manifests_only",
    "on_prem",         # NEW canonical name for paste-kubeconfig
    "live_cluster",    # DEPRECATED alias of on_prem — accepted in, normalised to on_prem on write
    "aws_eks",         # NEW
    "azure_aks",       # NEW
    "gcp_gke",         # NEW
] = "manifests_only"
```

Add optional cluster identifiers. All `None` unless the matching `target` is selected; validator enforces.

```python
# AWS EKS
aws_region: str | None = None
aws_cluster_name: str | None = None
# Azure AKS
azure_subscription_id: str | None = None
azure_resource_group: str | None = None
azure_cluster_name: str | None = None
# GCP GKE
gcp_project_id: str | None = None
gcp_location: str | None = None  # region or zone
gcp_cluster_name: str | None = None
```

`model_validator` rules:
- `target == "manifests_only"` ⇒ `manifests_archive_url` required (unchanged).
- `target == "on_prem"` ⇒ kubeconfig collected via `kind_credentials`, none of the cloud fields set.
- `target == "aws_eks"` ⇒ `aws_region` + `aws_cluster_name` required; other cloud fields `None`.
- `target == "azure_aks"` ⇒ `azure_subscription_id` + `azure_resource_group` + `azure_cluster_name` required.
- `target == "gcp_gke"` ⇒ `gcp_project_id` + `gcp_location` + `gcp_cluster_name` required.
- `target == "live_cluster"` normalises to `on_prem` post-validation (single-line rewrite).

### `K8sCreds` — replaces `KubeconfigCreds`

Single discriminated kind credential keyed off `provider`:

```python
class K8sCreds(_KindCredsBase):
    kind: Literal["k8s_cluster"] = "k8s_cluster"
    provider: Literal["on_prem", "aws", "azure", "gcp"] = "on_prem"
    # on_prem
    kubeconfig: str | None = Field(default=None, max_length=65536)
    context: str | None = None
    # AWS
    aws_access_key_id: str | None = None
    aws_secret_access_key: str | None = None
    aws_session_token: str | None = None
    # Azure
    azure_tenant_id: str | None = None
    azure_client_id: str | None = None
    azure_client_secret: str | None = None
    # GCP
    gcp_service_account_json: str | None = Field(default=None, max_length=16 * 1024)

    @model_validator(mode="after")
    def _validate(self) -> "K8sCreds":
        if self.provider == "on_prem" and (not self.kubeconfig or len(self.kubeconfig) < 10):
            raise ValueError("k8s_creds.provider='on_prem' requires kubeconfig")
        if self.provider == "aws" and not (self.aws_access_key_id and self.aws_secret_access_key):
            raise ValueError("k8s_creds.provider='aws' requires aws_access_key_id + aws_secret_access_key")
        if self.provider == "azure" and not (
            self.azure_tenant_id and self.azure_client_id and self.azure_client_secret
        ):
            raise ValueError("k8s_creds.provider='azure' requires tenant_id + client_id + client_secret")
        if self.provider == "gcp" and not self.gcp_service_account_json:
            raise ValueError("k8s_creds.provider='gcp' requires gcp_service_account_json")
        return self
```

Backwards compatibility for the discriminated `KindCredentials` union: accept payloads that omit `provider` (default to `on_prem`). Old rows stored as `{kind: "k8s_cluster", kubeconfig: "..."}` parse cleanly because `provider` defaults to `on_prem`.

Update the `KindCredentials = Annotated[Union[...]]` line: swap `KubeconfigCreds` → `K8sCreds`. Keep `KubeconfigCreds` as a re-export alias so any external import keeps working:
```python
KubeconfigCreds = K8sCreds  # back-compat alias
```

### `RegistryCreds`

No schema changes. (Already accepts `basic` / `token` / `docker_config` / `ecr_sts` / `gcr_service_account` / `acr_sp`.)

## UI changes

### `k8s-cluster-form-section.tsx`

Replace 2-button target-mode grid with 5 buttons: Manifests Only / On-Prem / AWS EKS / Azure AKS / GCP GKE. Add conditional sub-sections:

- **On-Prem**: existing kubeconfig paste/upload (unchanged content; relocated under this branch).
- **AWS EKS**: cluster name + region + access key + secret + (optional) session token. Hint mentions IAM permissions required (`eks:DescribeCluster`, `sts:GetCallerIdentity`).
- **Azure AKS**: subscription + resource group + cluster name + tenant + client ID + client secret. Hint: SP needs `Azure Kubernetes Service Cluster Admin` role.
- **GCP GKE**: project + location + cluster name + service-account JSON paste/upload. Hint: SA needs `roles/container.clusterViewer` minimum.

State shape on the page extends `K8sClusterConfig` to carry cluster identifiers, and replaces the lone `kubeconfig` string with a `K8sCredsDraft` object. Submission builds `kind_credentials` with the right provider discriminator.

### `container-image-form-section.tsx`

Below the registry selector, render an auth subform driven by the chosen registry:

- **`dockerhub` / `ghcr` / `custom`**: username + password/token (both optional → anonymous pull).
- **`ecr`**: AWS access key ID + secret access key + optional session token + region.
- **`gcr`**: SA JSON paste/upload.
- **`acr`**: tenant ID + client ID + client secret.

The state holds a `ContainerImageCredsDraft`; on submit, normalise into the existing `RegistryCreds` shape:
- dockerhub/ghcr/custom + creds present → `{auth_type: "basic", username, password_or_token, registry_host}` (registry_host derived from `image_ref`).
- dockerhub/ghcr/custom + creds empty → don't send `kind_credentials`.
- ecr → `{auth_type: "ecr_sts", username: <access_key>, password_or_token: <secret>, registry_host}` (we tunnel STS keys through the token field; the worker recognises the `ecr_sts` discriminator and uses boto3 to swap them for an ECR auth token — see scan-worker section).
- gcr → `{auth_type: "gcr_service_account", gcr_service_account_json, registry_host}`.
- acr → `{auth_type: "acr_sp", acr_client_id, acr_client_secret, acr_tenant_id, registry_host}`.

Update both `apps/web/app/targets/new/page.tsx` (registration) and `apps/web/app/targets/[id]/edit/page.tsx` (edit) to wire the new state through.

## Scan-worker changes

### `plugins/pencheff/pencheff/hybrid_tools.py::_materialize_kubeconfig`

Branch on `creds["provider"]`:

- `on_prem` (or missing — back-compat with old rows): existing path. Write the `kubeconfig` field to `/tmp/<session_id>/.kube/config` mode 0600.
- `aws`: call `_derive_eks_kubeconfig(creds, cfg)`. Returns YAML string.
- `azure`: call `_derive_aks_kubeconfig(creds, cfg)`.
- `gcp`: call `_derive_gke_kubeconfig(creds, cfg)`.

#### `_derive_eks_kubeconfig`

```python
def _derive_eks_kubeconfig(creds, cfg) -> str:
    import boto3
    region = cfg["aws_region"]
    name = cfg["aws_cluster_name"]
    session = boto3.Session(
        aws_access_key_id=creds["aws_access_key_id"],
        aws_secret_access_key=creds["aws_secret_access_key"],
        aws_session_token=creds.get("aws_session_token"),
        region_name=region,
    )
    cluster = session.client("eks").describe_cluster(name=name)["cluster"]
    endpoint = cluster["endpoint"]
    ca = cluster["certificateAuthority"]["data"]
    # EKS auth token: SigV4-presigned URL to STS GetCallerIdentity with
    # the EKS cluster name as the x-k8s-aws-id header. We compute the
    # token inline so the worker doesn't need the `aws` CLI.
    token = _eks_presigned_token(session, name)
    return _render_kubeconfig_yaml(endpoint, ca, "aws", token=token)
```

`_eks_presigned_token`: uses `botocore.signers.RequestSigner` to presign a `GET https://sts.<region>.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15` URL with `X-K8s-Aws-Id: <cluster_name>` and 60-second expiry, base64-url-encodes it with the `k8s-aws-v1.` prefix per the EKS auth scheme. Token TTL is 15 minutes server-side; ample for any single scan.

#### `_derive_aks_kubeconfig`

```python
def _derive_aks_kubeconfig(creds, cfg) -> str:
    from azure.identity import ClientSecretCredential
    from azure.mgmt.containerservice import ContainerServiceClient
    azcred = ClientSecretCredential(
        tenant_id=creds["azure_tenant_id"],
        client_id=creds["azure_client_id"],
        client_secret=creds["azure_client_secret"],
    )
    client = ContainerServiceClient(azcred, creds.get("subscription_id") or cfg["azure_subscription_id"])
    kc = client.managed_clusters.list_cluster_admin_credentials(
        resource_group_name=cfg["azure_resource_group"],
        resource_name=cfg["azure_cluster_name"],
    )
    return kc.kubeconfigs[0].value.decode("utf-8")
```

#### `_derive_gke_kubeconfig`

```python
def _derive_gke_kubeconfig(creds, cfg) -> str:
    import json
    from google.cloud import container_v1
    from google.oauth2 import service_account
    sa_info = json.loads(creds["gcp_service_account_json"])
    google_creds = service_account.Credentials.from_service_account_info(
        sa_info, scopes=["https://www.googleapis.com/auth/cloud-platform"],
    )
    client = container_v1.ClusterManagerClient(credentials=google_creds)
    name = f"projects/{cfg['gcp_project_id']}/locations/{cfg['gcp_location']}/clusters/{cfg['gcp_cluster_name']}"
    cluster = client.get_cluster(name=name)
    google_creds.refresh(google.auth.transport.requests.Request())
    return _render_kubeconfig_yaml(
        endpoint=f"https://{cluster.endpoint}",
        ca_b64=cluster.master_auth.cluster_ca_certificate,
        provider="gcp",
        token=google_creds.token,
    )
```

#### Missing-SDK handling

Each derivation wraps imports in try/except and returns `{"error": "boto3 not installed in this image", "skipped": True}` style errors. These propagate via `_materialize_kubeconfig` returning `None` and the existing "no kubeconfig bound" path.

### `plugins/pencheff/pencheff/artifact_tools.py::artifact_pull_image`

Before the `skopeo copy` invocation, build src-auth args from `kind_credentials_for_session(session_id)`:

```python
def _skopeo_src_auth_args(creds: dict | None) -> tuple[list[str], dict[str, str], Path | None]:
    """Returns (argv_args, env_overrides, tempfile_to_cleanup)."""
    if not creds or creds.get("kind") != "container_image":
        return [], {}, None
    auth = creds.get("auth_type")
    if auth == "basic" or auth == "token":
        u = creds.get("username") or ("token" if auth == "token" else "")
        p = creds.get("password_or_token") or ""
        if not p:
            return [], {}, None
        return ["--src-creds", f"{u}:{p}"], {}, None
    if auth == "ecr_sts":
        # boto3 to fetch a short-lived ECR token
        import base64, boto3
        sess = boto3.Session(
            aws_access_key_id=creds.get("username"),
            aws_secret_access_key=creds.get("password_or_token"),
            region_name=_extract_ecr_region(creds.get("registry_host")),
        )
        tok = sess.client("ecr").get_authorization_token()
        auth_b64 = tok["authorizationData"][0]["authorizationToken"]
        user, _, pwd = base64.b64decode(auth_b64).decode().partition(":")
        return ["--src-creds", f"{user}:{pwd}"], {}, None
    if auth == "gcr_service_account":
        sa = creds.get("gcr_service_account_json") or ""
        return ["--src-creds", f"_json_key:{sa}"], {}, None
    if auth == "acr_sp":
        return ["--src-creds", f"{creds['acr_client_id']}:{creds['acr_client_secret']}"], {}, None
    if auth == "docker_config":
        # Write to tempfile, return path for --src-authfile
        path = _SCAN_TMP_ROOT / "tmp_authfile.json"
        path.write_text(creds.get("docker_config_json") or "{}")
        os.chmod(path, 0o600)
        return ["--src-authfile", str(path)], {}, path
    return [], {}, None
```

Wrap the existing `skopeo copy` call to include the args; clean up tempfile in a try/finally.

## Migration / back-compat

- **K8sCreds:** existing rows stored as `{kind: "k8s_cluster", kubeconfig: "..."}` parse because `provider` defaults to `on_prem` and the validator sees a kubeconfig present. No DB migration.
- **K8sClusterConfig:** existing rows with `target: "live_cluster"` continue to validate; a post-parse normaliser rewrites to `target: "on_prem"` on read (memory only — leaving DB rows unchanged is fine since the validator accepts both).
- **RegistryCreds:** no shape change. Existing zero rows (UI never collected them) → unaffected.

## Testing

- Schema tests for `K8sCreds` validators (each provider's required-field set; back-compat for old shape).
- Schema tests for `K8sClusterConfig` validators (cloud-mode required fields).
- Schema test for `live_cluster` → `on_prem` normalisation.
- Hybrid-tools unit test for `_skopeo_src_auth_args` covering each `auth_type` branch.
- Mocked-boto / mocked-azure unit tests for the three `_derive_*_kubeconfig` functions confirming they produce a valid kubeconfig structure (parse YAML, assert `clusters`, `users`, `contexts` blocks present).
- E2E omitted — real cluster + cloud account required.

## Dependencies

Add to `plugins/pencheff/pyproject.toml`:
- `boto3>=1.34` (already a likely transitive — confirm)
- `azure-identity>=1.16`
- `azure-mgmt-containerservice>=29.0`
- `google-cloud-container>=2.40`
- `google-auth>=2.30`
- `pyyaml>=6` (likely already present — confirm)

These add ~30 MB of wheels and are import-guarded inside the derivation functions so the base API still boots if any of them fails to install.

## Out of scope (future work)

- AI-SPM / CSPM / KSPM / ASPM and other AccuKnox-style discipline categories. Tracked separately.
- IRSA / Workload Identity for EKS/GKE without static keys.
- Multi-cluster targets per row (currently one target = one cluster).
- Token caching across scans (each scan re-derives — acceptable since EKS tokens live 15 min).
