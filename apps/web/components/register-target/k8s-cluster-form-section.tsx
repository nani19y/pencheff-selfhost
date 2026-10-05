"use client";

import { Input, Label } from "@/components/brutal";

export type K8sTargetMode =
  | "manifests_only"
  | "on_prem"
  | "aws_eks"
  | "azure_aks"
  | "gcp_gke";

export type K8sClusterConfig = {
  kind: "k8s_cluster";
  target: K8sTargetMode;
  manifests_archive_url?: string;
  namespaces: string[];
  rbac_enum: boolean;
  network_policy_audit: boolean;
  // AWS EKS
  aws_region?: string;
  aws_cluster_name?: string;
  // Azure AKS
  azure_subscription_id?: string;
  azure_resource_group?: string;
  azure_cluster_name?: string;
  // GCP GKE
  gcp_project_id?: string;
  gcp_location?: string;
  gcp_cluster_name?: string;
};

export const DEFAULT_K8S_CLUSTER_CONFIG: K8sClusterConfig = {
  kind: "k8s_cluster",
  target: "manifests_only",
  manifests_archive_url: "",
  namespaces: ["default"],
  rbac_enum: true,
  network_policy_audit: true,
};

export type K8sCredsDraft = {
  provider: "on_prem" | "aws" | "azure" | "gcp";
  // on_prem
  kubeconfig: string;
  context: string;
  // AWS
  aws_access_key_id: string;
  aws_secret_access_key: string;
  aws_session_token: string;
  // Azure
  azure_tenant_id: string;
  azure_client_id: string;
  azure_client_secret: string;
  // GCP
  gcp_service_account_json: string;
};

export const EMPTY_K8S_CREDS: K8sCredsDraft = {
  provider: "on_prem",
  kubeconfig: "",
  context: "",
  aws_access_key_id: "",
  aws_secret_access_key: "",
  aws_session_token: "",
  azure_tenant_id: "",
  azure_client_id: "",
  azure_client_secret: "",
  gcp_service_account_json: "",
};

const TARGETS: Array<{ id: K8sTargetMode; label: string; hint: string }> = [
  {
    id: "manifests_only",
    label: "Manifests Only (offline)",
    hint: "Upload a tarball of Helm chart / Kustomize / raw YAML. Phase A only.",
  },
  {
    id: "on_prem",
    label: "On-Prem (kubeconfig)",
    hint: "Paste a kubeconfig YAML for any cluster reachable from the scanner.",
  },
  {
    id: "aws_eks",
    label: "AWS EKS",
    hint: "Connect via IAM access keys. Scanner derives a fresh kubeconfig per scan.",
  },
  {
    id: "azure_aks",
    label: "Azure AKS",
    hint: "Connect via Service Principal (tenant + client id + secret).",
  },
  {
    id: "gcp_gke",
    label: "GCP GKE",
    hint: "Connect via a Google service-account JSON key.",
  },
];

export function K8sClusterFormSection({
  value,
  onChange,
  name,
  setName,
  creds,
  setCreds,
  rawNamespaces,
  setRawNamespaces,
}: {
  value: K8sClusterConfig;
  onChange: (v: K8sClusterConfig) => void;
  name: string;
  setName: (v: string) => void;
  creds: K8sCredsDraft;
  setCreds: (v: K8sCredsDraft) => void;
  rawNamespaces: string;
  setRawNamespaces: (v: string) => void;
}) {
  function onNamespacesChange(raw: string) {
    setRawNamespaces(raw);
    const ns = raw.split(/[,\n]/).map((s) => s.trim()).filter(Boolean);
    onChange({ ...value, namespaces: ns.length > 0 ? ns : ["default"] });
  }

  function onModeChange(next: K8sTargetMode) {
    onChange({ ...value, target: next });
    const provider =
      next === "aws_eks" ? "aws"
        : next === "azure_aks" ? "azure"
        : next === "gcp_gke" ? "gcp"
        : "on_prem";
    setCreds({ ...creds, provider });
  }

  async function onKubeconfigUpload(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;
    if (file.size > 64 * 1024) {
      alert("Kubeconfig must be ≤ 64 KiB.");
      return;
    }
    const text = await file.text();
    setCreds({ ...creds, kubeconfig: text });
  }

  async function onSaJsonUpload(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;
    if (file.size > 16 * 1024) {
      alert("Service-account JSON must be ≤ 16 KiB.");
      return;
    }
    const text = await file.text();
    setCreds({ ...creds, gcp_service_account_json: text });
  }

  const isManifests = value.target === "manifests_only";
  const isOnPrem = value.target === "on_prem";
  const isAws = value.target === "aws_eks";
  const isAzure = value.target === "azure_aks";
  const isGcp = value.target === "gcp_gke";

  return (
    <>
      <section>
        <div className="flex items-baseline gap-3 mb-5">
          <span className="eyebrow-gilt">K1</span>
          <h2 className="font-display text-[18px] text-ink">Kubernetes Cluster</h2>
        </div>
        <div className="grid md:grid-cols-2 gap-5">
          <div className="md:col-span-2">
            <Label>Name (optional)</Label>
            <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="prod EKS us-east-1" />
          </div>
        </div>
      </section>

      <hr className="rule" />

      <section>
        <div className="flex items-baseline gap-3 mb-4">
          <span className="eyebrow-gilt">K2</span>
          <h2 className="font-display text-[18px] text-ink">Target mode</h2>
        </div>
        <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-3" role="radiogroup" aria-label="K8s target mode">
          {TARGETS.map((t) => {
            const active = value.target === t.id;
            return (
              <button
                key={t.id}
                type="button"
                role="radio"
                aria-checked={active}
                onClick={() => onModeChange(t.id)}
                className={
                  "text-left border rounded-sm p-4 transition-colors " +
                  (active ? "border-ink bg-vellum" : "border-hairline bg-paper hover:border-ink")
                }
              >
                <span className="block font-mono text-[12px] text-ink">{t.label}</span>
                <span className="mt-1 block font-mono text-[11px] text-mist">{t.hint}</span>
              </button>
            );
          })}
        </div>
      </section>

      <hr className="rule" />

      {isManifests && (
        <section>
          <div className="flex items-baseline gap-3 mb-3">
            <span className="eyebrow-gilt">K3</span>
            <h2 className="font-display text-[18px] text-ink">Manifests Archive URL</h2>
          </div>
          <p className="text-[13px] text-slate italic mb-4">
            HTTPS URL to a tar.gz archive of the manifests directory (Helm chart, Kustomize overlay,
            or raw YAML tree). Host must be on the operator-registered allowlist.
          </p>
          <Label>Archive URL</Label>
          <Input
            required
            type="url"
            placeholder="https://artifacts.example.com/k8s/prod-2026-q1.tar.gz"
            value={value.manifests_archive_url ?? ""}
            onChange={(e) => onChange({ ...value, manifests_archive_url: e.target.value })}
          />
        </section>
      )}

      {isOnPrem && (
        <section>
          <div className="flex items-baseline gap-3 mb-3">
            <span className="eyebrow-gilt">K3</span>
            <h2 className="font-display text-[18px] text-ink">Kubeconfig</h2>
          </div>
          <p className="text-[13px] text-slate italic mb-4">
            Paste the kubeconfig YAML or upload the file (≤ 64 KiB). Encrypted with Fernet, never
            logged or returned by GET endpoints, and materialised to <code>/tmp/&lt;scan_id&gt;/.kube/config</code>{" "}
            mode 0600 during scans — unlinked when the scan finishes.
          </p>
          <textarea
            required
            rows={12}
            value={creds.kubeconfig}
            onChange={(e) => setCreds({ ...creds, kubeconfig: e.target.value })}
            placeholder="apiVersion: v1&#10;kind: Config&#10;clusters:&#10;  - name: prod&#10;    cluster: {…}"
            className="w-full font-mono text-[11px] bg-paper border border-hairline rounded-sm p-3 focus:outline-none focus:border-ink"
          />
          <div className="mt-3 flex items-center gap-3">
            <input
              type="file"
              accept=".yaml,.yml,.config,*"
              onChange={onKubeconfigUpload}
              className="font-mono text-[11px] text-slate"
            />
            <span className="font-mono text-[11px] text-mist">≤ 64 KiB</span>
          </div>
          <div className="mt-3">
            <Label>Context (optional)</Label>
            <Input
              value={creds.context}
              onChange={(e) => setCreds({ ...creds, context: e.target.value })}
              placeholder="prod-cluster"
            />
          </div>
        </section>
      )}

      {isAws && (
        <section>
          <div className="flex items-baseline gap-3 mb-3">
            <span className="eyebrow-gilt">K3</span>
            <h2 className="font-display text-[18px] text-ink">AWS EKS connection</h2>
          </div>
          <p className="text-[13px] text-slate italic mb-4">
            IAM principal needs <code>eks:DescribeCluster</code> and{" "}
            <code>sts:GetCallerIdentity</code>. The scanner uses these keys at scan time to
            describe the cluster and mint a short-lived auth token — no kubeconfig is stored.
          </p>
          <div className="grid md:grid-cols-2 gap-5">
            <div>
              <Label>Region</Label>
              <Input
                required
                value={value.aws_region ?? ""}
                onChange={(e) => onChange({ ...value, aws_region: e.target.value })}
                placeholder="us-east-1"
              />
            </div>
            <div>
              <Label>Cluster name</Label>
              <Input
                required
                value={value.aws_cluster_name ?? ""}
                onChange={(e) => onChange({ ...value, aws_cluster_name: e.target.value })}
                placeholder="prod-eks"
              />
            </div>
            <div>
              <Label>Access key ID</Label>
              <Input
                required
                autoComplete="off"
                value={creds.aws_access_key_id}
                onChange={(e) => setCreds({ ...creds, aws_access_key_id: e.target.value })}
                placeholder="AKIA…"
              />
            </div>
            <div>
              <Label>Secret access key</Label>
              <Input
                required
                type="password"
                autoComplete="off"
                value={creds.aws_secret_access_key}
                onChange={(e) => setCreds({ ...creds, aws_secret_access_key: e.target.value })}
                placeholder="••••••••"
              />
            </div>
            <div className="md:col-span-2">
              <Label>Session token (optional, for assumed-role creds)</Label>
              <Input
                type="password"
                autoComplete="off"
                value={creds.aws_session_token}
                onChange={(e) => setCreds({ ...creds, aws_session_token: e.target.value })}
                placeholder="IQoJb3JpZ2luX2VjE…"
              />
            </div>
          </div>
        </section>
      )}

      {isAzure && (
        <section>
          <div className="flex items-baseline gap-3 mb-3">
            <span className="eyebrow-gilt">K3</span>
            <h2 className="font-display text-[18px] text-ink">Azure AKS connection</h2>
          </div>
          <p className="text-[13px] text-slate italic mb-4">
            Use a Service Principal with the{" "}
            <code>Azure Kubernetes Service Cluster Admin Role</code> on the target cluster. The
            scanner exchanges these creds for an admin kubeconfig at scan time via the AKS
            management API.
          </p>
          <div className="grid md:grid-cols-2 gap-5">
            <div>
              <Label>Subscription ID</Label>
              <Input
                required
                value={value.azure_subscription_id ?? ""}
                onChange={(e) => onChange({ ...value, azure_subscription_id: e.target.value })}
                placeholder="00000000-0000-0000-0000-000000000000"
              />
            </div>
            <div>
              <Label>Resource group</Label>
              <Input
                required
                value={value.azure_resource_group ?? ""}
                onChange={(e) => onChange({ ...value, azure_resource_group: e.target.value })}
                placeholder="prod-rg"
              />
            </div>
            <div className="md:col-span-2">
              <Label>Cluster name</Label>
              <Input
                required
                value={value.azure_cluster_name ?? ""}
                onChange={(e) => onChange({ ...value, azure_cluster_name: e.target.value })}
                placeholder="prod-aks"
              />
            </div>
            <div>
              <Label>Tenant ID</Label>
              <Input
                required
                value={creds.azure_tenant_id}
                onChange={(e) => setCreds({ ...creds, azure_tenant_id: e.target.value })}
                placeholder="00000000-0000-0000-0000-000000000000"
              />
            </div>
            <div>
              <Label>Client ID</Label>
              <Input
                required
                value={creds.azure_client_id}
                onChange={(e) => setCreds({ ...creds, azure_client_id: e.target.value })}
                placeholder="App registration client ID"
              />
            </div>
            <div className="md:col-span-2">
              <Label>Client secret</Label>
              <Input
                required
                type="password"
                autoComplete="off"
                value={creds.azure_client_secret}
                onChange={(e) => setCreds({ ...creds, azure_client_secret: e.target.value })}
                placeholder="••••••••"
              />
            </div>
          </div>
        </section>
      )}

      {isGcp && (
        <section>
          <div className="flex items-baseline gap-3 mb-3">
            <span className="eyebrow-gilt">K3</span>
            <h2 className="font-display text-[18px] text-ink">GCP GKE connection</h2>
          </div>
          <p className="text-[13px] text-slate italic mb-4">
            Service account needs at minimum <code>roles/container.clusterViewer</code> on the
            target project (use <code>container.clusterAdmin</code> for RBAC enumeration). The
            scanner uses the SA JSON to fetch cluster details and a short-lived access token.
          </p>
          <div className="grid md:grid-cols-3 gap-5">
            <div>
              <Label>Project ID</Label>
              <Input
                required
                value={value.gcp_project_id ?? ""}
                onChange={(e) => onChange({ ...value, gcp_project_id: e.target.value })}
                placeholder="my-gcp-project"
              />
            </div>
            <div>
              <Label>Location (region or zone)</Label>
              <Input
                required
                value={value.gcp_location ?? ""}
                onChange={(e) => onChange({ ...value, gcp_location: e.target.value })}
                placeholder="us-central1 or us-central1-a"
              />
            </div>
            <div>
              <Label>Cluster name</Label>
              <Input
                required
                value={value.gcp_cluster_name ?? ""}
                onChange={(e) => onChange({ ...value, gcp_cluster_name: e.target.value })}
                placeholder="prod-gke"
              />
            </div>
          </div>
          <div className="mt-5">
            <Label>Service account JSON</Label>
            <textarea
              required
              rows={10}
              value={creds.gcp_service_account_json}
              onChange={(e) => setCreds({ ...creds, gcp_service_account_json: e.target.value })}
              placeholder='{&#10;  "type": "service_account",&#10;  "project_id": "…",&#10;  "private_key_id": "…",&#10;  "private_key": "-----BEGIN PRIVATE KEY-----&#10;  …&#10;}'
              className="w-full font-mono text-[11px] bg-paper border border-hairline rounded-sm p-3 focus:outline-none focus:border-ink"
            />
            <div className="mt-3 flex items-center gap-3">
              <input
                type="file"
                accept=".json,application/json"
                onChange={onSaJsonUpload}
                className="font-mono text-[11px] text-slate"
              />
              <span className="font-mono text-[11px] text-mist">≤ 16 KiB</span>
            </div>
          </div>
        </section>
      )}

      <hr className="rule" />

      <section>
        <div className="flex items-baseline gap-3 mb-3">
          <span className="eyebrow-gilt">K4</span>
          <h2 className="font-display text-[18px] text-ink">Namespaces</h2>
        </div>
        <textarea
          rows={3}
          value={rawNamespaces}
          onChange={(e) => onNamespacesChange(e.target.value)}
          placeholder="default&#10;production&#10;monitoring"
          className="w-full font-mono text-[12px] bg-paper border border-hairline rounded-sm p-3 focus:outline-none focus:border-ink"
        />
        <p className="mt-1.5 font-mono text-[11px] text-mist">
          One per line, comma-separated also accepted. Empty falls back to <code>default</code>.
        </p>
      </section>

      <hr className="rule" />

      <section className="space-y-3">
        <label className="flex items-center gap-3 cursor-pointer">
          <input
            type="checkbox"
            checked={value.rbac_enum}
            onChange={(e) => onChange({ ...value, rbac_enum: e.target.checked })}
            className="w-[16px] h-[16px] border border-hairline rounded-sm accent-ink"
          />
          <span className="font-body text-[13px] text-ink">Enumerate RBAC bindings (rakkess)</span>
        </label>
        <label className="flex items-center gap-3 cursor-pointer">
          <input
            type="checkbox"
            checked={value.network_policy_audit}
            onChange={(e) => onChange({ ...value, network_policy_audit: e.target.checked })}
            className="w-[16px] h-[16px] border border-hairline rounded-sm accent-ink"
          />
          <span className="font-body text-[13px] text-ink">Audit network policies + exposed services</span>
        </label>
      </section>
    </>
  );
}

export function buildK8sKindCredentials(
  cfg: K8sClusterConfig,
  creds: K8sCredsDraft,
): Record<string, unknown> | null {
  if (cfg.target === "manifests_only") return null;
  if (cfg.target === "on_prem") {
    if (!creds.kubeconfig.trim()) return null;
    return {
      kind: "k8s_cluster",
      provider: "on_prem",
      kubeconfig: creds.kubeconfig,
      context: creds.context || null,
    };
  }
  if (cfg.target === "aws_eks") {
    return {
      kind: "k8s_cluster",
      provider: "aws",
      aws_access_key_id: creds.aws_access_key_id,
      aws_secret_access_key: creds.aws_secret_access_key,
      aws_session_token: creds.aws_session_token || null,
    };
  }
  if (cfg.target === "azure_aks") {
    return {
      kind: "k8s_cluster",
      provider: "azure",
      azure_tenant_id: creds.azure_tenant_id,
      azure_client_id: creds.azure_client_id,
      azure_client_secret: creds.azure_client_secret,
    };
  }
  if (cfg.target === "gcp_gke") {
    return {
      kind: "k8s_cluster",
      provider: "gcp",
      gcp_service_account_json: creds.gcp_service_account_json,
    };
  }
  return null;
}

export function validateK8sFormBeforeSubmit(
  cfg: K8sClusterConfig,
  creds: K8sCredsDraft,
): string | null {
  if (cfg.target === "manifests_only") {
    if (!cfg.manifests_archive_url?.trim()) {
      return "Manifests archive URL is required for manifests-only mode.";
    }
    return null;
  }
  if (cfg.target === "on_prem") {
    if (!creds.kubeconfig.trim()) {
      return "Kubeconfig is required for on-prem mode.";
    }
    return null;
  }
  if (cfg.target === "aws_eks") {
    if (!cfg.aws_region?.trim() || !cfg.aws_cluster_name?.trim()) {
      return "AWS region and cluster name are required for EKS mode.";
    }
    if (!creds.aws_access_key_id || !creds.aws_secret_access_key) {
      return "AWS access key ID and secret access key are required for EKS mode.";
    }
    return null;
  }
  if (cfg.target === "azure_aks") {
    if (
      !cfg.azure_subscription_id?.trim()
      || !cfg.azure_resource_group?.trim()
      || !cfg.azure_cluster_name?.trim()
    ) {
      return "Azure subscription, resource group, and cluster name are required for AKS mode.";
    }
    if (
      !creds.azure_tenant_id || !creds.azure_client_id || !creds.azure_client_secret
    ) {
      return "Azure tenant ID, client ID, and client secret are required for AKS mode.";
    }
    return null;
  }
  if (cfg.target === "gcp_gke") {
    if (
      !cfg.gcp_project_id?.trim()
      || !cfg.gcp_location?.trim()
      || !cfg.gcp_cluster_name?.trim()
    ) {
      return "GCP project ID, location, and cluster name are required for GKE mode.";
    }
    if (!creds.gcp_service_account_json.trim()) {
      return "GCP service-account JSON is required for GKE mode.";
    }
    return null;
  }
  return null;
}
