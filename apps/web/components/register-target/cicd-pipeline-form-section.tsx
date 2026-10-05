"use client";

import { Input, Label } from "@/components/brutal";

export type CicdProvider =
  "github_actions" | "gitlab_ci" | "jenkins" | "azure_pipelines" | "circleci";

export type CicdPipelineConfig = {
  kind: "cicd_pipeline";
  provider: CicdProvider;
  repo_url?: string;
  config_paths: string[];
  live_api_enabled: boolean;
};

export const DEFAULT_CICD_PIPELINE_CONFIG: CicdPipelineConfig = {
  kind: "cicd_pipeline",
  provider: "github_actions",
  repo_url: "",
  config_paths: [],
  live_api_enabled: false,
};

// Write-only credentials (never returned by the API). Used to clone private
// repos, run Phase B live-API probing, and open agentic-fix PRs.
export type CicdPipelineCreds = {
  token?: string;
  jenkins_user?: string;
};

export const EMPTY_CICD_PIPELINE_CREDS: CicdPipelineCreds = {};

// Per-provider label + hint for the credential token field.
const TOKEN_HINTS: Record<CicdProvider, { label: string; hint: string }> = {
  github_actions: {
    label: "GitHub token (PAT)",
    hint: "Personal access token with repo scope — clones private repos and opens fix PRs.",
  },
  gitlab_ci: {
    label: "GitLab access token",
    hint: "Token with read_repository (+ api for live probing).",
  },
  jenkins: {
    label: "Jenkins API token",
    hint: "Paired with the Jenkins user below.",
  },
  azure_pipelines: {
    label: "Azure DevOps PAT",
    hint: "Personal access token with Code (read) scope.",
  },
  circleci: { label: "CircleCI API token", hint: "Personal API token." },
};

const PROVIDERS: Array<{
  id: CicdProvider;
  label: string;
  default_paths: string;
}> = [
  {
    id: "github_actions",
    label: "GitHub Actions",
    default_paths: ".github/workflows/*.yml",
  },
  { id: "gitlab_ci", label: "GitLab CI", default_paths: ".gitlab-ci.yml" },
  {
    id: "jenkins",
    label: "Jenkins",
    default_paths: "Jenkinsfile, .jenkins/*.groovy",
  },
  {
    id: "azure_pipelines",
    label: "Azure Pipelines",
    default_paths: "azure-pipelines.yml",
  },
  { id: "circleci", label: "CircleCI", default_paths: ".circleci/config.yml" },
];

export function CicdPipelineFormSection({
  value,
  onChange,
  name,
  setName,
  rawConfigPaths,
  setRawConfigPaths,
  creds,
  setCreds,
}: {
  value: CicdPipelineConfig;
  onChange: (v: CicdPipelineConfig) => void;
  name: string;
  setName: (v: string) => void;
  rawConfigPaths: string;
  setRawConfigPaths: (v: string) => void;
  creds: CicdPipelineCreds;
  setCreds: (v: CicdPipelineCreds) => void;
}) {
  function onPathsChange(raw: string) {
    setRawConfigPaths(raw);
    const paths = raw
      .split(/[,\n]/)
      .map((p) => p.trim())
      .filter(Boolean);
    onChange({ ...value, config_paths: paths });
  }

  const providerHint = PROVIDERS.find((p) => p.id === value.provider);
  const tokenHint = TOKEN_HINTS[value.provider];

  return (
    <>
      <section>
        <div className="flex items-baseline gap-3 mb-5">
          <span className="eyebrow-gilt">CP1</span>
          <h2 className="font-display text-[18px] text-ink">CI/CD Pipeline</h2>
        </div>
        <div className="grid md:grid-cols-2 gap-5">
          <div className="md:col-span-2">
            <Label>Name (optional)</Label>
            <Input
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="prod-api GitHub Actions"
            />
          </div>
          <div className="md:col-span-2">
            <Label>Repository URL</Label>
            <Input
              type="url"
              placeholder="https://github.com/org/repo"
              value={value.repo_url ?? ""}
              onChange={(e) => onChange({ ...value, repo_url: e.target.value })}
            />
            <p className="mt-1.5 font-mono text-[11px] text-mist">
              The scanner clones this repo and audits the workflow / pipeline
              configs.
            </p>
          </div>
        </div>
      </section>

      <hr className="rule" />

      <section>
        <div className="flex items-baseline gap-3 mb-4">
          <span className="eyebrow-gilt">CP2</span>
          <h2 className="font-display text-[18px] text-ink">Provider</h2>
        </div>
        <div
          className="grid sm:grid-cols-2 gap-2"
          role="radiogroup"
          aria-label="CI provider"
        >
          {PROVIDERS.map((p) => {
            const active = value.provider === p.id;
            return (
              <button
                key={p.id}
                type="button"
                role="radio"
                aria-checked={active}
                onClick={() => onChange({ ...value, provider: p.id })}
                className={
                  "text-left border rounded-sm p-3 transition-colors " +
                  (active
                    ? "border-ink bg-vellum"
                    : "border-hairline bg-paper hover:border-ink")
                }
              >
                <span className="block font-mono text-[12px] text-ink">
                  {p.label}
                </span>
                <span className="mt-0.5 block font-mono text-[10px] text-mist">
                  {p.default_paths}
                </span>
              </button>
            );
          })}
        </div>
      </section>

      <hr className="rule" />

      <section>
        <div className="flex items-baseline gap-3 mb-3">
          <span className="eyebrow-gilt">CP3</span>
          <h2 className="font-display text-[18px] text-ink">
            Config paths (optional)
          </h2>
        </div>
        <p className="text-[13px] text-slate italic mb-3">
          One path per line. Auto-detected from the provider above when empty
          (default: <code>{providerHint?.default_paths}</code>).
        </p>
        <textarea
          rows={4}
          value={rawConfigPaths}
          onChange={(e) => onPathsChange(e.target.value)}
          placeholder=".github/workflows/deploy.yml&#10;.github/workflows/test.yml"
          className="w-full font-mono text-[12px] bg-paper border border-hairline rounded-sm p-3 focus:outline-none focus:border-ink"
        />
      </section>

      <hr className="rule" />

      <section>
        <div className="flex items-baseline gap-3 mb-3">
          <span className="eyebrow-gilt">CP4</span>
          <h2 className="font-display text-[18px] text-ink">
            Credentials (optional)
          </h2>
        </div>
        <p className="text-[13px] text-slate italic mb-3">
          Needed for private repos, Phase B live-API probing, and the &ldquo;Fix
          all findings&rdquo; agent (which clones the repo and opens a PR). A
          public-repo config audit needs no credentials.
        </p>
        <div className="grid md:grid-cols-2 gap-5">
          {value.provider === "jenkins" && (
            <div>
              <Label>Jenkins user</Label>
              <Input
                value={creds.jenkins_user ?? ""}
                onChange={(e) =>
                  setCreds({ ...creds, jenkins_user: e.target.value })
                }
                placeholder="ci-bot"
                autoComplete="off"
              />
            </div>
          )}
          <div className={value.provider === "jenkins" ? "" : "md:col-span-2"}>
            <Label>{tokenHint.label}</Label>
            <Input
              type="password"
              value={creds.token ?? ""}
              onChange={(e) => setCreds({ ...creds, token: e.target.value })}
              placeholder="••••••••••••"
              autoComplete="off"
            />
            <p className="mt-1.5 font-mono text-[11px] text-mist">
              {tokenHint.hint}
            </p>
          </div>
        </div>
      </section>

      <hr className="rule" />

      <section>
        <label className="flex items-start gap-3 cursor-pointer">
          <input
            type="checkbox"
            checked={value.live_api_enabled}
            onChange={(e) =>
              onChange({ ...value, live_api_enabled: e.target.checked })
            }
            className="mt-1 w-[16px] h-[16px] border border-hairline rounded-sm accent-ink"
          />
          <span>
            <span className="block font-body text-[13px] text-ink">
              Enable Phase B live-API probing
            </span>
            <span className="block font-mono text-[11px] text-mist mt-0.5">
              When on, the scan also queries the provider API (GitHub Actions /
              GitLab CI / Jenkins REST) to enumerate workflows, secrets, deploy
              keys, runner pools. Uses the token above.
            </span>
          </span>
        </label>
      </section>
    </>
  );
}
