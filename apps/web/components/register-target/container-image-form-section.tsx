"use client";

import { Input, Label } from "@/components/brutal";

export type ContainerImageConfig = {
  kind: "container_image";
  image_ref: string;
  registry: "dockerhub" | "ecr" | "gcr" | "ghcr" | "acr" | "custom";
  scan_layers: boolean;
  scan_secrets: boolean;
  scan_misconfigs: boolean;
};

export const DEFAULT_CONTAINER_IMAGE_CONFIG: ContainerImageConfig = {
  kind: "container_image",
  image_ref: "",
  registry: "dockerhub",
  scan_layers: true,
  scan_secrets: true,
  scan_misconfigs: true,
};

export type ContainerImageCredsDraft = {
  // Shared by dockerhub/ghcr/custom (basic) and registry-auth-token paths.
  username: string;
  password_or_token: string;
  // AWS ECR
  aws_access_key_id: string;
  aws_secret_access_key: string;
  aws_session_token: string;
  aws_region: string;
  // GCP GCR / Artifact Registry
  gcr_service_account_json: string;
  // Azure ACR
  acr_client_id: string;
  acr_client_secret: string;
  acr_tenant_id: string;
};

export const EMPTY_CONTAINER_IMAGE_CREDS: ContainerImageCredsDraft = {
  username: "",
  password_or_token: "",
  aws_access_key_id: "",
  aws_secret_access_key: "",
  aws_session_token: "",
  aws_region: "",
  gcr_service_account_json: "",
  acr_client_id: "",
  acr_client_secret: "",
  acr_tenant_id: "",
};

const REGISTRIES: Array<{ id: ContainerImageConfig["registry"]; label: string; hint: string }> = [
  { id: "dockerhub", label: "Docker Hub", hint: "Public by default; supply username + token for private repos." },
  { id: "ghcr", label: "GHCR", hint: "GitHub Container Registry. Use a classic PAT with read:packages for private." },
  { id: "ecr", label: "AWS ECR", hint: "Private — supply AWS IAM keys with ecr:GetAuthorizationToken." },
  { id: "gcr", label: "Google GCR / Artifact Registry", hint: "Private — supply a service account JSON key." },
  { id: "acr", label: "Azure ACR", hint: "Private — supply a Service Principal (client id + secret + tenant)." },
  { id: "custom", label: "Custom Registry", hint: "Any OCI-compatible registry. Optional basic auth." },
];

function inferRegistryHost(imageRef: string, registry: ContainerImageConfig["registry"]): string {
  // Pull the host portion off the image ref if present; otherwise apply a sane default
  // per registry type. Empty string is acceptable — backend only requires non-empty
  // when creds are present, and the worker can override via the auth flow.
  const ref = imageRef.trim();
  if (ref.includes("/")) {
    const head = ref.split("/")[0];
    // Registry hosts conventionally include a dot or port — bare "library/foo" lookups
    // are dockerhub.
    if (head.includes(".") || head.includes(":") || head === "localhost") {
      return head;
    }
  }
  switch (registry) {
    case "dockerhub": return "index.docker.io";
    case "ghcr": return "ghcr.io";
    case "ecr": return ""; // ECR host is account-specific; rely on image_ref.
    case "gcr": return ""; // ditto for GCR / Artifact Registry
    case "acr": return ""; // ditto
    case "custom": return "";
  }
}

export function buildContainerImageKindCredentials(
  cfg: ContainerImageConfig,
  creds: ContainerImageCredsDraft,
): Record<string, unknown> | null {
  const registry_host = inferRegistryHost(cfg.image_ref, cfg.registry);
  switch (cfg.registry) {
    case "dockerhub":
    case "ghcr":
    case "custom": {
      if (!creds.password_or_token) return null;
      return {
        kind: "container_image",
        registry_host: registry_host || "index.docker.io",
        auth_type: "basic",
        username: creds.username || null,
        password_or_token: creds.password_or_token,
      };
    }
    case "ecr": {
      if (!creds.aws_access_key_id || !creds.aws_secret_access_key) return null;
      return {
        kind: "container_image",
        registry_host: registry_host || "",
        auth_type: "ecr_sts",
        aws_access_key_id: creds.aws_access_key_id,
        aws_secret_access_key: creds.aws_secret_access_key,
        aws_session_token: creds.aws_session_token || null,
        aws_region: creds.aws_region || null,
      };
    }
    case "gcr": {
      if (!creds.gcr_service_account_json) return null;
      return {
        kind: "container_image",
        registry_host: registry_host || "",
        auth_type: "gcr_service_account",
        gcr_service_account_json: creds.gcr_service_account_json,
      };
    }
    case "acr": {
      if (!creds.acr_client_id || !creds.acr_client_secret) return null;
      return {
        kind: "container_image",
        registry_host: registry_host || "",
        auth_type: "acr_sp",
        acr_client_id: creds.acr_client_id,
        acr_client_secret: creds.acr_client_secret,
        acr_tenant_id: creds.acr_tenant_id || null,
      };
    }
  }
  return null;
}

export function ContainerImageFormSection({
  value,
  onChange,
  name,
  setName,
  creds,
  setCreds,
}: {
  value: ContainerImageConfig;
  onChange: (v: ContainerImageConfig) => void;
  name: string;
  setName: (v: string) => void;
  creds: ContainerImageCredsDraft;
  setCreds: (v: ContainerImageCredsDraft) => void;
}) {
  async function onSaJsonUpload(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;
    if (file.size > 16 * 1024) {
      alert("Service-account JSON must be ≤ 16 KiB.");
      return;
    }
    const text = await file.text();
    setCreds({ ...creds, gcr_service_account_json: text });
  }

  const showBasicAuth =
    value.registry === "dockerhub"
    || value.registry === "ghcr"
    || value.registry === "custom";
  const showEcr = value.registry === "ecr";
  const showGcr = value.registry === "gcr";
  const showAcr = value.registry === "acr";

  return (
    <>
      <section>
        <div className="flex items-baseline gap-3 mb-5">
          <span className="eyebrow-gilt">CI1</span>
          <h2 className="font-display text-[18px] text-ink">Container Image</h2>
        </div>
        <div className="grid md:grid-cols-2 gap-5">
          <div className="md:col-span-2">
            <Label>Image Reference</Label>
            <Input
              required
              placeholder="alpine:3.10  ·  myorg/api:1.2.3  ·  ghcr.io/owner/img:sha256:…"
              value={value.image_ref}
              onChange={(e) => onChange({ ...value, image_ref: e.target.value })}
            />
            <p className="mt-1.5 font-mono text-[11px] text-mist">
              The scanner pulls this image via <code>skopeo copy</code> (never <code>docker pull</code>)
              into a sandboxed OCI layout — no exec during pull. For private images the credentials
              below are passed to skopeo as <code>--src-creds</code> or via a short-lived authfile.
            </p>
          </div>
          <div className="md:col-span-2">
            <Label>Name (optional)</Label>
            <Input
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="Production API container"
            />
          </div>
        </div>
      </section>

      <hr className="rule" />

      <section>
        <div className="flex items-baseline gap-3 mb-1">
          <span className="eyebrow-gilt">CI2</span>
          <h2 className="font-display text-[18px] text-ink">Registry</h2>
        </div>
        <p className="text-[13px] text-slate italic mb-4">
          Pick the registry hosting the image. Credentials are Fernet-encrypted at rest and
          never returned by GET endpoints.
        </p>
        <div className="grid sm:grid-cols-2 gap-3" role="radiogroup" aria-label="Registry">
          {REGISTRIES.map((r) => {
            const active = value.registry === r.id;
            return (
              <button
                key={r.id}
                type="button"
                role="radio"
                aria-checked={active}
                onClick={() => onChange({ ...value, registry: r.id })}
                className={
                  "text-left border rounded-sm p-4 transition-colors " +
                  (active ? "border-ink bg-vellum" : "border-hairline bg-paper hover:border-ink")
                }
              >
                <span className="block font-mono text-[12px] text-ink">{r.label}</span>
                <span className="mt-1 block font-mono text-[11px] text-mist">{r.hint}</span>
              </button>
            );
          })}
        </div>
      </section>

      <hr className="rule" />

      {showBasicAuth && (
        <section>
          <div className="flex items-baseline gap-3 mb-3">
            <span className="eyebrow-gilt">CI3</span>
            <h2 className="font-display text-[18px] text-ink">Registry credentials (optional)</h2>
          </div>
          <p className="text-[13px] text-slate italic mb-4">
            Leave blank for anonymous pulls (public images). For private images, supply a username
            and a personal access token / password.
          </p>
          <div className="grid md:grid-cols-2 gap-5">
            <div>
              <Label>Username</Label>
              <Input
                autoComplete="off"
                value={creds.username}
                onChange={(e) => setCreds({ ...creds, username: e.target.value })}
                placeholder={value.registry === "ghcr" ? "github-username" : "username"}
              />
            </div>
            <div>
              <Label>Password / token</Label>
              <Input
                type="password"
                autoComplete="off"
                value={creds.password_or_token}
                onChange={(e) => setCreds({ ...creds, password_or_token: e.target.value })}
                placeholder="••••••••"
              />
            </div>
          </div>
        </section>
      )}

      {showEcr && (
        <section>
          <div className="flex items-baseline gap-3 mb-3">
            <span className="eyebrow-gilt">CI3</span>
            <h2 className="font-display text-[18px] text-ink">AWS ECR credentials</h2>
          </div>
          <p className="text-[13px] text-slate italic mb-4">
            IAM principal needs <code>ecr:GetAuthorizationToken</code> and{" "}
            <code>ecr:BatchGetImage</code> on the target repository. The scanner exchanges these
            keys for a short-lived (12 h) ECR auth token at pull time.
          </p>
          <div className="grid md:grid-cols-2 gap-5">
            <div>
              <Label>AWS region</Label>
              <Input
                required
                value={creds.aws_region}
                onChange={(e) => setCreds({ ...creds, aws_region: e.target.value })}
                placeholder="us-east-1"
              />
            </div>
            <div />
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

      {showGcr && (
        <section>
          <div className="flex items-baseline gap-3 mb-3">
            <span className="eyebrow-gilt">CI3</span>
            <h2 className="font-display text-[18px] text-ink">GCP service-account credentials</h2>
          </div>
          <p className="text-[13px] text-slate italic mb-4">
            Service account needs <code>roles/artifactregistry.reader</code> (Artifact Registry)
            or <code>roles/storage.objectViewer</code> (legacy GCR) on the target repo. The
            scanner authenticates skopeo as <code>_json_key</code> with the SA JSON as the
            password.
          </p>
          <Label>Service account JSON</Label>
          <textarea
            required
            rows={10}
            value={creds.gcr_service_account_json}
            onChange={(e) => setCreds({ ...creds, gcr_service_account_json: e.target.value })}
            placeholder='{&#10;  "type": "service_account",&#10;  "project_id": "…",&#10;  "private_key": "-----BEGIN PRIVATE KEY-----…"&#10;}'
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
        </section>
      )}

      {showAcr && (
        <section>
          <div className="flex items-baseline gap-3 mb-3">
            <span className="eyebrow-gilt">CI3</span>
            <h2 className="font-display text-[18px] text-ink">Azure ACR credentials</h2>
          </div>
          <p className="text-[13px] text-slate italic mb-4">
            Use a Service Principal with <code>AcrPull</code> role on the registry. ACR accepts
            the SP credentials as basic auth (client id : client secret) to the registry endpoint.
          </p>
          <div className="grid md:grid-cols-2 gap-5">
            <div>
              <Label>Client ID</Label>
              <Input
                required
                autoComplete="off"
                value={creds.acr_client_id}
                onChange={(e) => setCreds({ ...creds, acr_client_id: e.target.value })}
                placeholder="00000000-0000-0000-0000-000000000000"
              />
            </div>
            <div>
              <Label>Client secret</Label>
              <Input
                required
                type="password"
                autoComplete="off"
                value={creds.acr_client_secret}
                onChange={(e) => setCreds({ ...creds, acr_client_secret: e.target.value })}
                placeholder="••••••••"
              />
            </div>
            <div className="md:col-span-2">
              <Label>Tenant ID (optional)</Label>
              <Input
                value={creds.acr_tenant_id}
                onChange={(e) => setCreds({ ...creds, acr_tenant_id: e.target.value })}
                placeholder="00000000-0000-0000-0000-000000000000"
              />
            </div>
          </div>
        </section>
      )}

      <hr className="rule" />

      <section>
        <div className="flex items-baseline gap-3 mb-4">
          <span className="eyebrow-gilt">CI4</span>
          <h2 className="font-display text-[18px] text-ink">Scan coverage</h2>
        </div>
        <div className="space-y-3">
          {[
            { key: "scan_layers", label: "Scan image layers for CVEs (trivy + grype)" },
            { key: "scan_secrets", label: "Scan layers for embedded secrets (trivy --scanners secret)" },
            { key: "scan_misconfigs", label: "Lint Dockerfile-style misconfigurations (hadolint, when source available)" },
          ].map(({ key, label }) => (
            <label key={key} className="flex items-center gap-3 cursor-pointer">
              <input
                type="checkbox"
                checked={value[key as keyof ContainerImageConfig] as boolean}
                onChange={(e) => onChange({ ...value, [key]: e.target.checked })}
                className="w-[16px] h-[16px] border border-hairline rounded-sm accent-ink"
              />
              <span className="font-body text-[13px] text-ink">{label}</span>
            </label>
          ))}
        </div>
      </section>
    </>
  );
}
