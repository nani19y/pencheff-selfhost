"use client";

import { Input, Label } from "@/components/brutal";

export type CloudProvider = "aws" | "azure" | "gcp";
export type CloudKind =
  | "cloud_account"
  | "serverless_function"
  | "cloud_storage"
  | "load_balancer_cdn"
  | "cloud_database"
  | "secrets_manager";

export type CloudConfig = {
  kind: CloudKind;
  provider: CloudProvider;
  account_id?: string;
  subscription_id?: string;
  project_id?: string;
  regions: string[];
  resource_tags: Record<string, string>;
  inventory?: Record<string, unknown> | null;
  read_only: true;
  services?: string[];
  include_iam?: boolean;
  include_network?: boolean;
  include_audit_logging?: boolean;
  function_names?: string[];
  include_env_metadata?: boolean;
  check_public_invocation?: boolean;
  check_runtime?: boolean;
  resource_names?: string[];
  domains?: string[];
  engines?: string[];
  check_public_access?: boolean;
  check_encryption?: boolean;
  check_logging?: boolean;
  check_tls?: boolean;
  check_origin_exposure?: boolean;
  check_waf?: boolean;
  check_cache_policy?: boolean;
  check_backups?: boolean;
  check_rotation?: boolean;
  check_policy?: boolean;
};

export type CloudCredsDraft = {
  aws_access_key_id: string;
  aws_secret_access_key: string;
  aws_session_token: string;
  aws_role_arn: string;
  azure_tenant_id: string;
  azure_client_id: string;
  azure_client_secret: string;
  gcp_service_account_json: string;
};

export type CloudTargetDraft = {
  name: string;
  config: CloudConfig;
  creds: CloudCredsDraft;
  rawRegions: string;
  rawResourceNames: string;
  rawResourceTagsJson: string;
  rawInventoryJson: string;
};

export const CLOUD_KINDS: CloudKind[] = [
  "cloud_account",
  "serverless_function",
  "cloud_storage",
  "load_balancer_cdn",
  "cloud_database",
  "secrets_manager",
];

export const EMPTY_CLOUD_CREDS: CloudCredsDraft = {
  aws_access_key_id: "",
  aws_secret_access_key: "",
  aws_session_token: "",
  aws_role_arn: "",
  azure_tenant_id: "",
  azure_client_id: "",
  azure_client_secret: "",
  gcp_service_account_json: "",
};

const PROVIDERS: Array<{ id: CloudProvider; label: string; hint: string }> = [
  {
    id: "aws",
    label: "AWS",
    hint: "Use read-only IAM keys or an assumed role with SecurityAudit-style permissions.",
  },
  {
    id: "azure",
    label: "Azure",
    hint: "Use a Service Principal with Reader and Security Reader permissions.",
  },
  {
    id: "gcp",
    label: "GCP",
    hint: "Use a service-account JSON key with Viewer and Security Reviewer-style access.",
  },
];

const KIND_LABEL: Record<CloudKind, string> = {
  cloud_account: "Cloud Account (CSPM)",
  serverless_function: "Serverless Functions",
  cloud_storage: "Cloud Storage",
  load_balancer_cdn: "Load Balancer / CDN",
  cloud_database: "Database (Cloud)",
  secrets_manager: "Secrets Manager",
};

const KIND_HINT: Record<CloudKind, string> = {
  cloud_account:
    "Runs account-level IAM, public exposure, storage, database, edge, secret metadata, and audit logging checks.",
  serverless_function:
    "Checks function invocation policies, deprecated runtimes, secret-like environment metadata, and execution-role permissions.",
  cloud_storage:
    "Checks bucket/container public access, encryption at rest, access logging, and related IAM metadata.",
  load_balancer_cdn:
    "Checks edge TLS posture, WAF coverage, origin exposure, and cache policies.",
  cloud_database:
    "Checks managed database public access, encryption, backups, deletion protection, and IAM metadata.",
  secrets_manager:
    "Checks secret metadata, rotation, policies, and encryption. Pencheff never reads or stores secret values.",
};

export function defaultCloudConfig(kind: CloudKind): CloudConfig {
  const base = {
    kind,
    provider: "aws" as CloudProvider,
    account_id: "",
    subscription_id: "",
    project_id: "",
    regions: ["us-east-1"],
    resource_tags: {},
    inventory: null,
    read_only: true as const,
  };
  switch (kind) {
    case "cloud_account":
      return {
        ...base,
        services: ["iam", "storage", "serverless", "edge", "database", "secrets", "audit_logging"],
        include_iam: true,
        include_network: true,
        include_audit_logging: true,
      };
    case "serverless_function":
      return {
        ...base,
        function_names: [],
        include_env_metadata: true,
        check_public_invocation: true,
        check_runtime: true,
      };
    case "cloud_storage":
      return {
        ...base,
        resource_names: [],
        check_public_access: true,
        check_encryption: true,
        check_logging: true,
      };
    case "load_balancer_cdn":
      return {
        ...base,
        resource_names: [],
        domains: [],
        check_tls: true,
        check_origin_exposure: true,
        check_waf: true,
        check_cache_policy: true,
      };
    case "cloud_database":
      return {
        ...base,
        resource_names: [],
        engines: [],
        check_public_access: true,
        check_encryption: true,
        check_backups: true,
      };
    case "secrets_manager":
      return {
        ...base,
        resource_names: [],
        check_rotation: true,
        check_policy: true,
        check_encryption: true,
      };
  }
}

export function defaultCloudDraft(kind: CloudKind): CloudTargetDraft {
  return {
    name: "",
    config: defaultCloudConfig(kind),
    creds: { ...EMPTY_CLOUD_CREDS },
    rawRegions: "us-east-1",
    rawResourceNames: "",
    rawResourceTagsJson: "{}",
    rawInventoryJson: "",
  };
}

export function buildCloudBaseUrl(kind: CloudKind, cfg: CloudConfig): string {
  const scope =
    cfg.provider === "aws"
      ? cfg.account_id
      : cfg.provider === "azure"
        ? cfg.subscription_id
        : cfg.project_id;
  return `cloud://${cfg.provider}/${scope || "scope"}/${kind}`;
}

export function cloudDisplayName(kind: CloudKind, cfg: CloudConfig): string {
  const scope =
    cfg.provider === "aws"
      ? cfg.account_id
      : cfg.provider === "azure"
        ? cfg.subscription_id
        : cfg.project_id;
  return `${KIND_LABEL[kind]} · ${cfg.provider.toUpperCase()} ${scope || "scope"}`;
}

export function buildCloudKindCredentials(
  kind: CloudKind,
  cfg: CloudConfig,
  creds: CloudCredsDraft,
): Record<string, unknown> | null {
  if (cfg.provider === "aws") {
    if (!creds.aws_access_key_id.trim() || !creds.aws_secret_access_key.trim()) {
      return null;
    }
    return {
      kind,
      provider: "aws",
      aws_access_key_id: creds.aws_access_key_id.trim(),
      aws_secret_access_key: creds.aws_secret_access_key,
      aws_session_token: creds.aws_session_token.trim() || null,
      aws_role_arn: creds.aws_role_arn.trim() || null,
    };
  }
  if (cfg.provider === "azure") {
    if (
      !creds.azure_tenant_id.trim() ||
      !creds.azure_client_id.trim() ||
      !creds.azure_client_secret.trim()
    ) {
      return null;
    }
    return {
      kind,
      provider: "azure",
      azure_tenant_id: creds.azure_tenant_id.trim(),
      azure_client_id: creds.azure_client_id.trim(),
      azure_client_secret: creds.azure_client_secret,
    };
  }
  if (!creds.gcp_service_account_json.trim()) {
    return null;
  }
  return {
    kind,
    provider: "gcp",
    gcp_service_account_json: creds.gcp_service_account_json,
  };
}

export function finalizeCloudDraft(draft: CloudTargetDraft): CloudConfig {
  const cfg = draft.config;
  const resourceTags = parseJsonObject(draft.rawResourceTagsJson, "Resource tags JSON");
  const inventory = draft.rawInventoryJson.trim()
    ? parseJsonObject(draft.rawInventoryJson, "Inventory JSON")
    : null;
  return {
    ...cfg,
    account_id: cfg.provider === "aws" ? cfg.account_id?.trim() : undefined,
    subscription_id:
      cfg.provider === "azure" ? cfg.subscription_id?.trim() : undefined,
    project_id: cfg.provider === "gcp" ? cfg.project_id?.trim() : undefined,
    regions: listFromText(draft.rawRegions),
    resource_tags: stringifyRecord(resourceTags),
    inventory,
    read_only: true,
  };
}

export function validateCloudDraft(
  draft: CloudTargetDraft,
  options: { allowStoredCredentials?: boolean } = {},
): string | null {
  const cfg = draft.config;
  if (cfg.provider === "aws" && !cfg.account_id?.trim()) {
    return "AWS account ID is required.";
  }
  if (cfg.provider === "azure" && !cfg.subscription_id?.trim()) {
    return "Azure subscription ID is required.";
  }
  if (cfg.provider === "gcp" && !cfg.project_id?.trim()) {
    return "GCP project ID is required.";
  }
  const hasInventory = Boolean(draft.rawInventoryJson.trim());
  const hasCreds = Boolean(buildCloudKindCredentials(draft.config.kind, draft.config, draft.creds));
  if (!hasInventory && !hasCreds && !options.allowStoredCredentials) {
    return "Add provider authorization or paste an inventory JSON sample.";
  }
  try {
    finalizeCloudDraft(draft);
  } catch (err) {
    return err instanceof Error ? err.message : "Cloud target JSON is invalid.";
  }
  return null;
}

export function CloudFormSection({
  draft,
  onChange,
}: {
  draft: CloudTargetDraft;
  onChange: (draft: CloudTargetDraft) => void;
}) {
  const { config: value, creds } = draft;
  const kind = value.kind;

  function updateConfig(next: Partial<CloudConfig>) {
    onChange({ ...draft, config: { ...value, ...next } });
  }

  function onProvider(next: CloudProvider) {
    const scopePatch =
      next === "aws"
        ? { provider: next, subscription_id: "", project_id: "" }
        : next === "azure"
          ? { provider: next, account_id: "", project_id: "" }
          : { provider: next, account_id: "", subscription_id: "" };
    onChange({ ...draft, config: { ...value, ...scopePatch } });
  }

  async function onGcpJsonUpload(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;
    if (file.size > 16 * 1024) {
      alert("Service-account JSON must be <= 16 KiB.");
      return;
    }
    const text = await file.text();
    onChange({ ...draft, creds: { ...creds, gcp_service_account_json: text } });
  }

  async function onInventoryUpload(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;
    if (file.size > 256 * 1024) {
      alert("Inventory JSON must be <= 256 KiB.");
      return;
    }
    const text = await file.text();
    onChange({ ...draft, rawInventoryJson: text });
  }

  const isAws = value.provider === "aws";
  const isAzure = value.provider === "azure";
  const isGcp = value.provider === "gcp";

  return (
    <>
      <section>
        <div className="flex items-baseline gap-3 mb-5">
          <span className="eyebrow-gilt">C1</span>
          <h2 className="font-display text-[18px] text-ink">{KIND_LABEL[kind]}</h2>
        </div>
        <p className="mb-5 max-w-[78ch] text-[13px] leading-5 text-slate italic">
          {KIND_HINT[kind]} All cloud scans are read-only and operate on metadata. Secret
          values are never requested, read, logged, or stored.
        </p>
        <div className="grid md:grid-cols-2 gap-5">
          <div className="md:col-span-2">
            <Label>Name</Label>
            <Input
              value={draft.name}
              onChange={(e) => onChange({ ...draft, name: e.target.value })}
              placeholder={cloudDisplayName(kind, value)}
            />
          </div>
        </div>
      </section>

      <hr className="rule" />

      <section>
        <div className="flex items-baseline gap-3 mb-4">
          <span className="eyebrow-gilt">C2</span>
          <h2 className="font-display text-[18px] text-ink">Provider and scope</h2>
        </div>
        <div className="grid sm:grid-cols-3 gap-3 mb-5" role="radiogroup" aria-label="Cloud provider">
          {PROVIDERS.map((provider) => {
            const active = value.provider === provider.id;
            return (
              <button
                key={provider.id}
                type="button"
                role="radio"
                aria-checked={active}
                onClick={() => onProvider(provider.id)}
                className={
                  "text-left border rounded-sm p-4 transition-colors " +
                  (active ? "border-ink bg-vellum" : "border-hairline bg-paper hover:border-ink")
                }
              >
                <span className="block font-mono text-[12px] text-ink">{provider.label}</span>
                <span className="mt-1 block font-mono text-[11px] text-mist">{provider.hint}</span>
              </button>
            );
          })}
        </div>
        <div className="grid md:grid-cols-2 gap-5">
          {isAws && (
            <div>
              <Label>AWS account ID</Label>
              <Input
                required
                value={value.account_id ?? ""}
                onChange={(e) => updateConfig({ account_id: e.target.value })}
                placeholder="123456789012"
              />
            </div>
          )}
          {isAzure && (
            <div>
              <Label>Azure subscription ID</Label>
              <Input
                required
                value={value.subscription_id ?? ""}
                onChange={(e) => updateConfig({ subscription_id: e.target.value })}
                placeholder="00000000-0000-0000-0000-000000000000"
              />
            </div>
          )}
          {isGcp && (
            <div>
              <Label>GCP project ID</Label>
              <Input
                required
                value={value.project_id ?? ""}
                onChange={(e) => updateConfig({ project_id: e.target.value })}
                placeholder="production-project"
              />
            </div>
          )}
          <div>
            <Label>Regions / locations</Label>
            <Input
              value={draft.rawRegions}
              onChange={(e) => onChange({ ...draft, rawRegions: e.target.value })}
              placeholder={isAzure ? "eastus, westus2" : isGcp ? "us-central1, europe-west1" : "us-east-1, us-west-2"}
            />
            <p className="mt-1.5 font-mono text-[11px] text-mist">
              Comma-separated. Leave blank only for global-only resources.
            </p>
          </div>
        </div>
      </section>

      <hr className="rule" />

      <section>
        <div className="flex items-baseline gap-3 mb-3">
          <span className="eyebrow-gilt">C3</span>
          <h2 className="font-display text-[18px] text-ink">Provider authorization</h2>
        </div>
        <p className="text-[13px] text-slate italic mb-4">
          Use read-only credentials. They are encrypted with the target and are never returned
          by target detail APIs. You can skip authorization only when you paste inventory JSON below.
        </p>

        {isAws && (
          <div className="grid md:grid-cols-2 gap-5">
            <div>
              <Label>Access key ID</Label>
              <Input
                autoComplete="off"
                value={creds.aws_access_key_id}
                onChange={(e) =>
                  onChange({ ...draft, creds: { ...creds, aws_access_key_id: e.target.value } })
                }
                placeholder="AKIA..."
              />
            </div>
            <div>
              <Label>Secret access key</Label>
              <Input
                type="password"
                autoComplete="off"
                value={creds.aws_secret_access_key}
                onChange={(e) =>
                  onChange({ ...draft, creds: { ...creds, aws_secret_access_key: e.target.value } })
                }
                placeholder="••••••••"
              />
            </div>
            <div>
              <Label>Session token (optional)</Label>
              <Input
                type="password"
                autoComplete="off"
                value={creds.aws_session_token}
                onChange={(e) =>
                  onChange({ ...draft, creds: { ...creds, aws_session_token: e.target.value } })
                }
                placeholder="For STS / SSO temporary credentials"
              />
            </div>
            <div>
              <Label>Role ARN (optional)</Label>
              <Input
                autoComplete="off"
                value={creds.aws_role_arn}
                onChange={(e) =>
                  onChange({ ...draft, creds: { ...creds, aws_role_arn: e.target.value } })
                }
                placeholder="arn:aws:iam::123456789012:role/PencheffReadOnly"
              />
            </div>
          </div>
        )}

        {isAzure && (
          <div className="grid md:grid-cols-3 gap-5">
            <div>
              <Label>Tenant ID</Label>
              <Input
                autoComplete="off"
                value={creds.azure_tenant_id}
                onChange={(e) =>
                  onChange({ ...draft, creds: { ...creds, azure_tenant_id: e.target.value } })
                }
                placeholder="Tenant UUID"
              />
            </div>
            <div>
              <Label>Client ID</Label>
              <Input
                autoComplete="off"
                value={creds.azure_client_id}
                onChange={(e) =>
                  onChange({ ...draft, creds: { ...creds, azure_client_id: e.target.value } })
                }
                placeholder="App registration client ID"
              />
            </div>
            <div>
              <Label>Client secret</Label>
              <Input
                type="password"
                autoComplete="off"
                value={creds.azure_client_secret}
                onChange={(e) =>
                  onChange({ ...draft, creds: { ...creds, azure_client_secret: e.target.value } })
                }
                placeholder="••••••••"
              />
            </div>
          </div>
        )}

        {isGcp && (
          <div>
            <Label>Service account JSON</Label>
            <textarea
              rows={9}
              value={creds.gcp_service_account_json}
              onChange={(e) =>
                onChange({ ...draft, creds: { ...creds, gcp_service_account_json: e.target.value } })
              }
              placeholder='{&#10;  "type": "service_account",&#10;  "project_id": "production-project",&#10;  "private_key": "-----BEGIN PRIVATE KEY-----..."&#10;}'
              className="w-full font-mono text-[11px] bg-paper border border-hairline rounded-sm p-3 focus:outline-none focus:border-ink"
            />
            <div className="mt-3 flex items-center gap-3">
              <input
                type="file"
                accept=".json,application/json"
                onChange={onGcpJsonUpload}
                className="font-mono text-[11px] text-slate"
              />
              <span className="font-mono text-[11px] text-mist">≤ 16 KiB</span>
            </div>
          </div>
        )}
      </section>

      <hr className="rule" />

      <section>
        <div className="flex items-baseline gap-3 mb-3">
          <span className="eyebrow-gilt">C4</span>
          <h2 className="font-display text-[18px] text-ink">Scan options</h2>
        </div>

        {kind !== "cloud_account" && (
          <div className="mb-5">
            <Label>{kind === "serverless_function" ? "Function names" : kind === "load_balancer_cdn" ? "Resource names / CDN IDs" : "Resource names"}</Label>
            <textarea
              rows={3}
              value={draft.rawResourceNames}
              onChange={(e) => {
                const names = listFromText(e.target.value);
                const patch =
                  kind === "serverless_function"
                    ? { function_names: names }
                    : { resource_names: names };
                onChange({
                  ...draft,
                  rawResourceNames: e.target.value,
                  config: { ...value, ...patch },
                });
              }}
              placeholder="One per line, or leave blank to test all visible resources"
              className="w-full font-mono text-[12px] bg-paper border border-hairline rounded-sm p-3 focus:outline-none focus:border-ink"
            />
          </div>
        )}

        <div className="grid md:grid-cols-2 gap-3">
          {checkboxFor("include_iam", "Check IAM and entitlements", value, updateConfig)}
          {checkboxFor("include_network", "Check network exposure", value, updateConfig)}
          {checkboxFor("include_audit_logging", "Check audit logging", value, updateConfig)}
          {checkboxFor("include_env_metadata", "Check environment metadata", value, updateConfig)}
          {checkboxFor("check_public_invocation", "Check public invocation", value, updateConfig)}
          {checkboxFor("check_runtime", "Check deprecated runtimes", value, updateConfig)}
          {checkboxFor("check_public_access", "Check public access", value, updateConfig)}
          {checkboxFor("check_encryption", "Check encryption", value, updateConfig)}
          {checkboxFor("check_logging", "Check access logging", value, updateConfig)}
          {checkboxFor("check_tls", "Check TLS configuration", value, updateConfig)}
          {checkboxFor("check_origin_exposure", "Check origin exposure", value, updateConfig)}
          {checkboxFor("check_waf", "Check WAF coverage", value, updateConfig)}
          {checkboxFor("check_cache_policy", "Check cache policy", value, updateConfig)}
          {checkboxFor("check_backups", "Check backups", value, updateConfig)}
          {checkboxFor("check_rotation", "Check rotation", value, updateConfig)}
          {checkboxFor("check_policy", "Check access policy", value, updateConfig)}
        </div>
      </section>

      <hr className="rule" />

      <section>
        <div className="flex items-baseline gap-3 mb-3">
          <span className="eyebrow-gilt">C5</span>
          <h2 className="font-display text-[18px] text-ink">Optional metadata inventory</h2>
        </div>
        <p className="text-[13px] text-slate italic mb-4">
          Paste provider metadata JSON when you want an offline scan or a simple high-school-friendly
          test target. Do not paste actual secret values. If a secret value key appears, API-side
          findings redact it before persistence.
        </p>
        <div className="grid md:grid-cols-2 gap-5">
          <div>
            <Label>Resource tags JSON</Label>
            <textarea
              rows={5}
              value={draft.rawResourceTagsJson}
              onChange={(e) => onChange({ ...draft, rawResourceTagsJson: e.target.value })}
              placeholder='{"environment":"prod","owner":"platform"}'
              className="w-full font-mono text-[12px] bg-paper border border-hairline rounded-sm p-3 focus:outline-none focus:border-ink"
            />
          </div>
          <div>
            <Label>Inventory JSON</Label>
            <textarea
              rows={5}
              value={draft.rawInventoryJson}
              onChange={(e) => onChange({ ...draft, rawInventoryJson: e.target.value })}
              placeholder={inventoryPlaceholder(kind)}
              className="w-full font-mono text-[12px] bg-paper border border-hairline rounded-sm p-3 focus:outline-none focus:border-ink"
            />
            <div className="mt-3 flex items-center gap-3">
              <input
                type="file"
                accept=".json,application/json"
                onChange={onInventoryUpload}
                className="font-mono text-[11px] text-slate"
              />
              <span className="font-mono text-[11px] text-mist">≤ 256 KiB</span>
            </div>
          </div>
        </div>
      </section>
    </>
  );
}

function checkboxFor(
  key: keyof CloudConfig,
  label: string,
  value: CloudConfig,
  updateConfig: (next: Partial<CloudConfig>) => void,
) {
  if (typeof value[key] !== "boolean") return null;
  return (
    <label key={String(key)} className="flex items-center gap-3 cursor-pointer">
      <input
        type="checkbox"
        checked={Boolean(value[key])}
        onChange={(e) => updateConfig({ [key]: e.target.checked } as Partial<CloudConfig>)}
        className="w-[16px] h-[16px] border border-hairline rounded-sm accent-ink"
      />
      <span className="font-body text-[13px] text-ink">{label}</span>
    </label>
  );
}

function listFromText(value: string): string[] {
  return value
    .split(/[,\n]/)
    .map((entry) => entry.trim())
    .filter(Boolean);
}

function parseJsonObject(value: string, label: string): Record<string, unknown> {
  if (!value.trim()) return {};
  const parsed = JSON.parse(value);
  if (!parsed || Array.isArray(parsed) || typeof parsed !== "object") {
    throw new Error(`${label} must be a JSON object.`);
  }
  return parsed as Record<string, unknown>;
}

function stringifyRecord(value: Record<string, unknown>): Record<string, string> {
  return Object.fromEntries(
    Object.entries(value).map(([key, entry]) => [key, String(entry)]),
  );
}

function inventoryPlaceholder(kind: CloudKind): string {
  switch (kind) {
    case "cloud_account":
      return '{"iam":[{"principal":"AdminLike","actions":["*"]}],"audit_logging":{"enabled":false}}';
    case "serverless_function":
      return '{"functions":[{"name":"billing-worker","public_invocation":true,"runtime":"nodejs12.x"}]}';
    case "cloud_storage":
      return '{"storage":[{"name":"prod-assets","public":true,"encrypted":false,"logging_enabled":false}]}';
    case "load_balancer_cdn":
      return '{"cdn":[{"name":"app-cdn","tls_min_version":"1.0","waf_enabled":false,"origin_public":true}]}';
    case "cloud_database":
      return '{"databases":[{"name":"prod-db","public_access":true,"encrypted":false,"backups_enabled":false}]}';
    case "secrets_manager":
      return '{"secrets":[{"name":"prod/db/password","rotation_enabled":false,"policy_public":true}]}';
  }
}
