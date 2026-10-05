"use client";

import { Input, Label } from "@/components/brutal";

export type IacFramework =
  "terraform" | "cloudformation" | "helm" | "kustomize" | "arm";
export type IacSource = "repo" | "tarball_url" | "local_path";

export type IacConfig = {
  kind: "iac";
  frameworks: IacFramework[];
  source: IacSource;
  repo_url?: string;
};

export const DEFAULT_IAC_CONFIG: IacConfig = {
  kind: "iac",
  frameworks: ["terraform"],
  source: "repo",
  repo_url: "",
};

// Write-only token to clone a private IaC repo and open agentic-fix PRs.
export type IacCreds = { token?: string };
export const EMPTY_IAC_CREDS: IacCreds = {};

const FRAMEWORKS: Array<{ id: IacFramework; label: string }> = [
  { id: "terraform", label: "Terraform" },
  { id: "cloudformation", label: "CloudFormation" },
  { id: "helm", label: "Helm Charts" },
  { id: "kustomize", label: "Kustomize" },
  { id: "arm", label: "Azure ARM" },
];

const SOURCES: Array<{ id: IacSource; label: string; hint: string }> = [
  {
    id: "repo",
    label: "Git Repository",
    hint: "Clone from a github.com / gitlab.com / bitbucket URL.",
  },
  {
    id: "tarball_url",
    label: "Tarball URL",
    hint: "HTTPS link to a .tar.gz of the IaC tree.",
  },
  {
    id: "local_path",
    label: "Local Path (self-hosted)",
    hint: "Absolute path on the scanner host — requires self-hosted deployment.",
  },
];

export function IacFormSection({
  value,
  onChange,
  name,
  setName,
  creds,
  setCreds,
}: {
  value: IacConfig;
  onChange: (v: IacConfig) => void;
  name: string;
  setName: (v: string) => void;
  creds: IacCreds;
  setCreds: (v: IacCreds) => void;
}) {
  const needsRepoUrl =
    value.source === "repo" || value.source === "tarball_url";

  function toggleFramework(fw: IacFramework) {
    const next = value.frameworks.includes(fw)
      ? value.frameworks.filter((f) => f !== fw)
      : [...value.frameworks, fw];
    if (next.length === 0) return; // require at least one
    onChange({ ...value, frameworks: next });
  }

  return (
    <>
      <section>
        <div className="flex items-baseline gap-3 mb-5">
          <span className="eyebrow-gilt">I1</span>
          <h2 className="font-display text-[18px] text-ink">
            Infrastructure as Code
          </h2>
        </div>
        <div className="grid md:grid-cols-2 gap-5">
          <div className="md:col-span-2">
            <Label>Name (optional)</Label>
            <Input
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="prod-infra Terraform"
            />
          </div>
          {needsRepoUrl && (
            <div className="md:col-span-2">
              <Label>
                {value.source === "repo" ? "Git URL" : "Tarball URL"}
              </Label>
              <Input
                required
                type="url"
                placeholder={
                  value.source === "repo"
                    ? "https://github.com/org/infra"
                    : "https://archives.example.com/infra.tar.gz"
                }
                value={value.repo_url ?? ""}
                onChange={(e) =>
                  onChange({ ...value, repo_url: e.target.value })
                }
              />
            </div>
          )}
          {value.source === "repo" && (
            <div className="md:col-span-2">
              <Label>GitHub token (optional)</Label>
              <Input
                type="password"
                placeholder="••••••••••••"
                autoComplete="off"
                value={creds.token ?? ""}
                onChange={(e) => setCreds({ ...creds, token: e.target.value })}
              />
              <p className="mt-1.5 font-mono text-[11px] text-mist">
                PAT with repo scope — required for private repos and for the
                &ldquo;Fix all findings&rdquo; agent (clones the repo, opens a
                PR). Public repos need none.
              </p>
            </div>
          )}
        </div>
      </section>

      <hr className="rule" />

      <section>
        <div className="flex items-baseline gap-3 mb-4">
          <span className="eyebrow-gilt">I2</span>
          <h2 className="font-display text-[18px] text-ink">Frameworks</h2>
        </div>
        <p className="text-[13px] text-slate italic mb-4">
          Select every IaC framework present in the source tree. checkov scans
          all of them; tfsec runs only when Terraform is selected.
        </p>
        <div className="grid sm:grid-cols-2 gap-2">
          {FRAMEWORKS.map((fw) => {
            const active = value.frameworks.includes(fw.id);
            return (
              <label
                key={fw.id}
                className="flex items-center gap-3 cursor-pointer"
              >
                <input
                  type="checkbox"
                  checked={active}
                  onChange={() => toggleFramework(fw.id)}
                  className="w-[16px] h-[16px] border border-hairline rounded-sm accent-ink"
                />
                <span className="font-body text-[13px] text-ink">
                  {fw.label}
                </span>
              </label>
            );
          })}
        </div>
      </section>

      <hr className="rule" />

      <section>
        <div className="flex items-baseline gap-3 mb-4">
          <span className="eyebrow-gilt">I3</span>
          <h2 className="font-display text-[18px] text-ink">Source</h2>
        </div>
        <div
          className="grid sm:grid-cols-3 gap-3"
          role="radiogroup"
          aria-label="Source type"
        >
          {SOURCES.map((s) => {
            const active = value.source === s.id;
            return (
              <button
                key={s.id}
                type="button"
                role="radio"
                aria-checked={active}
                onClick={() => onChange({ ...value, source: s.id })}
                className={
                  "text-left border rounded-sm p-4 transition-colors " +
                  (active
                    ? "border-ink bg-vellum"
                    : "border-hairline bg-paper hover:border-ink")
                }
              >
                <span className="block font-mono text-[12px] text-ink">
                  {s.label}
                </span>
                <span className="mt-1 block font-mono text-[11px] text-mist">
                  {s.hint}
                </span>
              </button>
            );
          })}
        </div>
      </section>
    </>
  );
}
