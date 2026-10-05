"use client";

import { useEffect, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { zipSync } from "fflate";
import { Button, Input, Label } from "@/components/brutal";
import { api, apiUpload } from "@/lib/api";

type ConnectedRepo = {
  id: string;
  full_name: string;
  private: boolean;
  html_url: string;
};

export type SourceCodeSource =
  | "github_url"
  | "github_app"
  | "gitlab_url"
  | "bitbucket_url"
  | "local_path"
  | "tarball_url"
  | "upload";
export type SourceCodeAuthType = "pat" | "github_app" | "ssh_key";

export type SourceCodeConfig = {
  kind: "source_code";
  source: SourceCodeSource;
  repo_url?: string;
  // source="upload": R2 object key + metadata from POST /uploads.
  upload_key?: string;
  upload_filename?: string;
  upload_sha256?: string;
  git_ref: string;
  languages_hint?: string[];
  scanners_disabled: string[];
};

export const DEFAULT_SOURCE_CODE_CONFIG: SourceCodeConfig = {
  kind: "source_code",
  source: "github_url",
  repo_url: "",
  git_ref: "HEAD",
  languages_hint: undefined,
  scanners_disabled: [],
};

export type SourceCodeCreds = {
  kind: "source_code";
  auth_type: SourceCodeAuthType;
  pat?: string;
  github_app_id?: string;
  github_app_private_key?: string;
  github_app_installation_id?: string;
  ssh_private_key?: string;
};

export const EMPTY_SOURCE_CODE_CREDS: SourceCodeCreds = {
  kind: "source_code",
  auth_type: "pat",
  pat: "",
  github_app_id: "",
  github_app_private_key: "",
  github_app_installation_id: "",
  ssh_private_key: "",
};

const SOURCES: Array<{ id: SourceCodeSource; label: string; hint: string }> = [
  {
    id: "github_url",
    label: "GitHub URL",
    hint: "Public clone via HTTPS or PAT-authenticated private.",
  },
  {
    id: "github_app",
    label: "GitHub App",
    hint: "Use an installed GitHub App (no per-user PAT).",
  },
  {
    id: "gitlab_url",
    label: "GitLab URL",
    hint: "Public clone via HTTPS or PAT-authenticated private (gitlab.com or self-hosted).",
  },
  {
    id: "bitbucket_url",
    label: "Bitbucket URL",
    hint: "Public clone via HTTPS or access-token-authenticated private.",
  },
  {
    id: "tarball_url",
    label: "Tarball URL",
    hint: "HTTPS link to a .tar.gz of the source tree.",
  },
  {
    id: "upload",
    label: "Local upload",
    hint: "Upload a folder or a .zip/.tar.gz — scanned in place, no git needed.",
  },
  {
    id: "local_path",
    label: "Local Path (self-hosted)",
    hint: "Absolute path on the scanner host.",
  },
];

// Provider-specific token nomenclature. The backend clones each provider with
// its own auth username (github → x-access-token, gitlab → oauth2, bitbucket →
// x-token-auth) but a single token value, so the auth *method* is token/SSH for
// all — only the label, placeholder, and guidance differ per provider.
type GitProvider = "github" | "gitlab" | "bitbucket";
function providerOf(source: SourceCodeSource): GitProvider | null {
  if (source === "github_url" || source === "github_app") return "github";
  if (source === "gitlab_url") return "gitlab";
  if (source === "bitbucket_url") return "bitbucket";
  return null;
}
const TOKEN_META: Record<
  GitProvider,
  { label: string; placeholder: string; hint: string }
> = {
  github: {
    label: "Personal Access Token",
    placeholder: "ghp_… or github_pat_…",
    hint: "GitHub PAT (classic or fine-grained) with read access to repository contents.",
  },
  gitlab: {
    label: "Personal / Project Access Token",
    placeholder: "glpat-…",
    hint: "GitLab personal or project access token with the read_repository scope.",
  },
  bitbucket: {
    label: "Repository Access Token",
    placeholder: "Bitbucket access token",
    hint: "Bitbucket repository, project, or workspace Access Token (sent as x-token-auth). App passwords aren't supported.",
  },
};
const FALLBACK_TOKEN_META = {
  label: "Personal Access Token",
  placeholder: "ghp_… / glpat-… / etc.",
  hint: "",
};

const SCANNERS: Array<{ id: string; label: string }> = [
  { id: "semgrep", label: "semgrep" },
  { id: "bandit", label: "bandit (Python)" },
  { id: "gosec", label: "gosec (Go)" },
  { id: "brakeman", label: "brakeman (Ruby)" },
  { id: "eslint", label: "eslint (JS/TS)" },
  { id: "gitleaks", label: "gitleaks (secrets)" },
  { id: "osv-scanner", label: "osv-scanner (SCA)" },
];

export function SourceCodeFormSection({
  value,
  onChange,
  name,
  setName,
  creds,
  setCreds,
  rawLangsHint,
  setRawLangsHint,
}: {
  value: SourceCodeConfig;
  onChange: (v: SourceCodeConfig) => void;
  name: string;
  setName: (v: string) => void;
  creds: SourceCodeCreds;
  setCreds: (v: SourceCodeCreds) => void;
  /** CSV / newline list of language hints — parsed into ``value.languages_hint``. */
  rawLangsHint: string;
  setRawLangsHint: (v: string) => void;
}) {
  const GIT_URL_SOURCES: SourceCodeSource[] = [
    "github_url",
    "gitlab_url",
    "bitbucket_url",
  ];
  const needsRepoUrl =
    GIT_URL_SOURCES.includes(value.source) || value.source === "tarball_url";

  const gitProvider = providerOf(value.source);
  const tokenMeta = gitProvider ? TOKEN_META[gitProvider] : FALLBACK_TOKEN_META;

  const router = useRouter();
  // Centralised Pencheff GitHub App install + repo picker. Install opens in a
  // popup; /repos signals back the integration id when done; we then sync the
  // installation to list the repos the user granted access to.
  const [installing, setInstalling] = useState(false);
  const [installErr, setInstallErr] = useState<string | null>(null);
  const [awaitingInstall, setAwaitingInstall] = useState(false);
  const [syncing, setSyncing] = useState(false);
  const [repos, setRepos] = useState<ConnectedRepo[] | null>(null);
  const [selectedRepoId, setSelectedRepoId] = useState<string | null>(null);

  // ── source="upload": folder-or-archive upload → POST /uploads → R2 ──────
  const [uploading, setUploading] = useState(false);
  const [uploadErr, setUploadErr] = useState<string | null>(null);
  const folderInputRef = useRef<HTMLInputElement | null>(null);
  const archiveInputRef = useRef<HTMLInputElement | null>(null);

  async function uploadArchive(
    build: () => Promise<{ blob: Blob | File; name: string }>,
  ) {
    setUploading(true);
    setUploadErr(null);
    try {
      const { blob, name } = await build();
      const form = new FormData();
      form.append("file", blob, name);
      const r = await apiUpload<{
        key: string;
        filename: string;
        size: number;
        sha256: string;
      }>("/uploads", form);
      onChange({
        ...value,
        upload_key: r.key,
        upload_filename: r.filename,
        upload_sha256: r.sha256,
      });
    } catch (e) {
      setUploadErr(e instanceof Error ? e.message : "Upload failed.");
    } finally {
      setUploading(false);
    }
  }

  function onArchivePicked(f: File | null) {
    if (!f) return;
    void uploadArchive(async () => ({ blob: f, name: f.name }));
  }

  function onFolderPicked(files: FileList | null) {
    if (!files || files.length === 0) return;
    void uploadArchive(async () => {
      const entries: Record<string, Uint8Array> = {};
      let top = "folder";
      for (const f of Array.from(files)) {
        const rel =
          (f as File & { webkitRelativePath?: string }).webkitRelativePath ||
          f.name;
        // Skip VCS/dep junk so the zip (and the scan) stays lean.
        if (
          rel.includes("/.git/") ||
          rel.startsWith(".git/") ||
          rel.includes("/node_modules/") ||
          rel.startsWith("node_modules/")
        )
          continue;
        if (!top && rel.includes("/")) top = rel.split("/")[0];
        entries[rel] = new Uint8Array(await f.arrayBuffer());
      }
      const first = (files[0] as File & { webkitRelativePath?: string })
        .webkitRelativePath;
      if (first?.includes("/")) top = first.split("/")[0];
      const zipped = zipSync(entries, { level: 6 });
      // Copy into a fresh ArrayBuffer-backed view so the Blob part types cleanly
      // (fflate returns Uint8Array<ArrayBufferLike>, which the DOM lib rejects).
      return {
        blob: new Blob([new Uint8Array(zipped)], { type: "application/zip" }),
        name: `${top}.zip`,
      };
    });
  }

  async function installGithubApp() {
    setInstalling(true);
    setInstallErr(null);
    try {
      const r = await api<{ url: string; configured: boolean }>(
        "/repos/install-url",
      );
      if (!r.configured) {
        setInstallErr(
          "The Pencheff GitHub App isn't configured on the server yet — contact your admin.",
        );
        return;
      }
      // Open in a popup so this form stays put; /repos closes it and posts the
      // integration id back to us when the install completes.
      setAwaitingInstall(true);
      window.open(r.url, "pencheff-gh-install", "width=1024,height=760");
    } catch (e) {
      setInstallErr(
        e instanceof Error ? e.message : "Could not start install.",
      );
    } finally {
      setInstalling(false);
    }
  }

  async function syncRepos(integrationId: string) {
    setSyncing(true);
    setInstallErr(null);
    try {
      const list = await api<ConnectedRepo[]>(
        `/repos/integrations/${integrationId}/sync`,
        { method: "POST" },
      );
      setRepos(list);
      setAwaitingInstall(false);
      if (list.length === 1) setSelectedRepoId(list[0].id);
    } catch (e) {
      setInstallErr(
        e instanceof Error ? e.message : "Could not load repositories.",
      );
    } finally {
      setSyncing(false);
    }
  }

  // Fallback if the popup signal is missed (closed manually / blocked):
  // sync the most recent installation directly.
  async function loadReposFallback() {
    setSyncing(true);
    setInstallErr(null);
    try {
      const integ = await api<{ id: string }[]>("/repos/integrations");
      if (!integ.length) {
        setInstallErr(
          "No GitHub App installation found yet — install it first.",
        );
        return;
      }
      const list = await api<ConnectedRepo[]>(
        `/repos/integrations/${integ[integ.length - 1].id}/sync`,
        { method: "POST" },
      );
      setRepos(list);
      setAwaitingInstall(false);
      if (list.length === 1) setSelectedRepoId(list[0].id);
    } catch (e) {
      setInstallErr(
        e instanceof Error ? e.message : "Could not load repositories.",
      );
    } finally {
      setSyncing(false);
    }
  }

  // Receive the install-complete signal from the /repos popup.
  useEffect(() => {
    function onMessage(ev: MessageEvent) {
      if (ev.origin !== window.location.origin) return;
      const d = ev.data as { type?: string; integrationId?: string };
      if (d?.type === "pencheff:gh-installed" && d.integrationId) {
        syncRepos(d.integrationId);
      }
    }
    window.addEventListener("message", onMessage);
    return () => window.removeEventListener("message", onMessage);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Keep the auth type in step with the source: the "GitHub App" source IS the
  // app install (no PAT/SSH picker), and URL/tarball sources never use it.
  useEffect(() => {
    if (value.source === "github_app" && creds.auth_type !== "github_app") {
      setCreds({ ...creds, auth_type: "github_app" });
    } else if (
      value.source !== "github_app" &&
      creds.auth_type === "github_app"
    ) {
      setCreds({ ...creds, auth_type: "pat" });
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [value.source]);

  function onLangsHintChange(raw: string) {
    setRawLangsHint(raw);
    const items = raw
      .split(/[,\n]/)
      .map((s) => s.trim())
      .filter(Boolean);
    onChange({ ...value, languages_hint: items.length ? items : undefined });
  }

  function toggleScanner(id: string) {
    const next = value.scanners_disabled.includes(id)
      ? value.scanners_disabled.filter((s) => s !== id)
      : [...value.scanners_disabled, id];
    onChange({ ...value, scanners_disabled: next });
  }

  return (
    <>
      <section>
        <div className="flex items-baseline gap-3 mb-5">
          <span className="eyebrow-gilt">SC1</span>
          <h2 className="font-display text-[18px] text-ink">
            Source Code Repository
          </h2>
        </div>
        <div className="grid md:grid-cols-2 gap-5">
          <div className="md:col-span-2">
            <Label>Name (optional)</Label>
            <Input
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="payments-service"
            />
          </div>
        </div>
      </section>

      <hr className="rule" />

      <section>
        <div className="flex items-baseline gap-3 mb-4">
          <span className="eyebrow-gilt">SC2</span>
          <h2 className="font-display text-[18px] text-ink">Source</h2>
        </div>
        <div
          className="grid sm:grid-cols-2 gap-3 mb-5"
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
                onClick={() =>
                  onChange({
                    ...value,
                    source: s.id,
                    repo_url: s.id === "local_path" ? "" : value.repo_url,
                  })
                }
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

        {needsRepoUrl && (
          <div className="mb-4">
            <Label>
              {value.source === "gitlab_url"
                ? "GitLab URL"
                : value.source === "bitbucket_url"
                  ? "Bitbucket URL"
                  : value.source === "github_url"
                    ? "GitHub URL"
                    : "Tarball URL"}
            </Label>
            <Input
              required
              type="url"
              placeholder={
                value.source === "gitlab_url"
                  ? "https://gitlab.com/group/project"
                  : value.source === "bitbucket_url"
                    ? "https://bitbucket.org/workspace/repo"
                    : value.source === "github_url"
                      ? "https://github.com/org/repo"
                      : "https://archives.example.com/repo.tar.gz"
              }
              value={value.repo_url ?? ""}
              onChange={(e) => onChange({ ...value, repo_url: e.target.value })}
            />
          </div>
        )}

        {value.source === "upload" && (
          <div className="mb-4">
            <input
              ref={folderInputRef}
              type="file"
              // @ts-expect-error — non-standard but widely supported folder pick
              webkitdirectory=""
              directory=""
              multiple
              hidden
              onChange={(e) => onFolderPicked(e.target.files)}
            />
            <input
              ref={archiveInputRef}
              type="file"
              accept=".zip,.tar.gz,.tgz,application/zip,application/gzip"
              hidden
              onChange={(e) => onArchivePicked(e.target.files?.[0] ?? null)}
            />
            <div className="flex flex-wrap items-center gap-3">
              <Button
                type="button"
                variant="lime"
                disabled={uploading}
                onClick={() => folderInputRef.current?.click()}
              >
                {uploading ? "Uploading…" : "Upload folder"}
              </Button>
              <Button
                type="button"
                variant="yellow"
                disabled={uploading}
                onClick={() => archiveInputRef.current?.click()}
              >
                Upload .zip / .tar.gz
              </Button>
              {value.upload_key && !uploading && (
                <span className="font-mono text-[12px] text-forest">
                  ✓ {value.upload_filename || "archive uploaded"}
                </span>
              )}
            </div>
            <p className="mt-2 font-mono text-[11px] text-mist">
              Folders are zipped in your browser (.git / node_modules skipped).
              Stored in your object storage, extracted server-side, and scanned
              with the SAST suite. Max 100 MiB.
            </p>
            {uploadErr && (
              <p className="advisory-warn font-body text-[12px] mt-2">
                {uploadErr}
              </p>
            )}
          </div>
        )}

        <div className="grid sm:grid-cols-2 gap-5">
          <div>
            <Label>Git ref (branch / tag / sha)</Label>
            <Input
              value={value.git_ref}
              onChange={(e) =>
                onChange({ ...value, git_ref: e.target.value || "HEAD" })
              }
              placeholder="HEAD"
            />
          </div>
          <div>
            <Label>Language hints (optional, csv)</Label>
            <Input
              placeholder="python, go, typescript"
              value={rawLangsHint}
              onChange={(e) => onLangsHintChange(e.target.value)}
            />
          </div>
        </div>
      </section>

      <hr className="rule" />

      {value.source !== "local_path" && value.source !== "upload" && (
        <>
          <section>
            <div className="flex items-baseline gap-3 mb-1">
              <span className="eyebrow-gilt">SC3</span>
              <h2 className="font-display text-[18px] text-ink">
                Authentication
              </h2>
            </div>
            <p className="text-[13px] text-slate italic mb-4">
              Required for private repos. Stored encrypted with Fernet in{" "}
              <code>kind_credentials</code>.
            </p>

            {value.source !== "github_app" && (
              <div
                className="grid sm:grid-cols-2 gap-3 mb-4"
                role="radiogroup"
                aria-label="Auth type"
              >
                {(["pat", "ssh_key"] as SourceCodeAuthType[]).map((t) => {
                  const active = creds.auth_type === t;
                  const label =
                    t === "pat" ? tokenMeta.label : "SSH Private Key";
                  return (
                    <button
                      key={t}
                      type="button"
                      role="radio"
                      aria-checked={active}
                      onClick={() => setCreds({ ...creds, auth_type: t })}
                      className={
                        "text-left border rounded-sm p-3 transition-colors " +
                        (active
                          ? "border-ink bg-vellum"
                          : "border-hairline bg-paper hover:border-ink")
                      }
                    >
                      <span className="block font-mono text-[12px] text-ink">
                        {label}
                      </span>
                    </button>
                  );
                })}
              </div>
            )}

            {creds.auth_type === "pat" && (
              <div>
                <Label>{tokenMeta.label}</Label>
                <Input
                  type="password"
                  autoComplete="off"
                  value={creds.pat ?? ""}
                  onChange={(e) => setCreds({ ...creds, pat: e.target.value })}
                  placeholder={tokenMeta.placeholder}
                />
                {tokenMeta.hint && (
                  <p className="mt-1.5 font-mono text-[11px] text-mist">
                    {tokenMeta.hint}
                  </p>
                )}
              </div>
            )}

            {value.source === "github_app" &&
              (repos ? (
                /* ── Repo picker: choose an accessible repo, then Next ── */
                <div className="space-y-4">
                  <p className="font-body text-[13px] text-graphite">
                    <strong>{repos.length}</strong> repositor
                    {repos.length === 1 ? "y" : "ies"} accessible via the
                    Pencheff GitHub App. Select one to scan.
                  </p>
                  {repos.length === 0 ? (
                    <div className="advisory-warn font-body text-[12px]">
                      No repositories were granted. Re-open the install and pick
                      repositories, then sync again.
                    </div>
                  ) : (
                    <ul
                      className="divide-y divide-hairline border border-hairline rounded-sm max-h-[320px] overflow-auto"
                      role="radiogroup"
                      aria-label="Repository"
                    >
                      {repos.map((r) => {
                        const active = selectedRepoId === r.id;
                        return (
                          <li key={r.id}>
                            <button
                              type="button"
                              role="radio"
                              aria-checked={active}
                              onClick={() => setSelectedRepoId(r.id)}
                              className={
                                "w-full text-left px-4 py-3 flex items-center justify-between gap-3 transition-colors " +
                                (active
                                  ? "bg-vellum"
                                  : "bg-paper hover:bg-vellum/50")
                              }
                            >
                              <span className="font-mono text-[13px] text-ink">
                                {r.full_name}
                              </span>
                              <span className="font-mono text-[10px] uppercase tracking-[0.1em] text-slate">
                                {r.private ? "private" : "public"}
                                {active ? " · selected" : ""}
                              </span>
                            </button>
                          </li>
                        );
                      })}
                    </ul>
                  )}
                  {installErr && (
                    <p className="advisory-warn font-body text-[12px]">
                      {installErr}
                    </p>
                  )}
                  <div className="flex items-center gap-4">
                    <Button
                      type="button"
                      variant="pink"
                      disabled={!selectedRepoId}
                      onClick={() => {
                        if (selectedRepoId)
                          router.push(`/repos/${selectedRepoId}`);
                      }}
                    >
                      Next →
                    </Button>
                    <button
                      type="button"
                      onClick={() => {
                        setRepos(null);
                        setSelectedRepoId(null);
                      }}
                      className="font-body text-[12px] text-slate hover:text-ink underline underline-offset-[3px]"
                    >
                      Install / pick a different account
                    </button>
                  </div>
                </div>
              ) : (
                <div className="space-y-5">
                  {/* Recommended: one-click install of the centralised app */}
                  <div className="formal-surface p-5 space-y-3">
                    <p className="font-body text-[13px] text-graphite">
                      <strong>Recommended.</strong> Install the Pencheff GitHub
                      App on your account or org — no App ID, installation ID,
                      or private key to paste. Pencheff uses the installation to
                      clone and scan, and (with your approval) open fix PRs.
                    </p>
                    <Button
                      type="button"
                      variant="pink"
                      onClick={installGithubApp}
                      disabled={installing || syncing}
                    >
                      {installing
                        ? "Opening GitHub…"
                        : syncing
                          ? "Loading repositories…"
                          : "Install the Pencheff GitHub App →"}
                    </Button>
                    {installErr && (
                      <p className="advisory-warn font-body text-[12px]">
                        {installErr}
                      </p>
                    )}
                    {awaitingInstall ? (
                      <p className="font-body text-[11px] text-slate">
                        Waiting for the GitHub install to finish in the popup —
                        your repositories appear here automatically.{" "}
                        <button
                          type="button"
                          onClick={loadReposFallback}
                          disabled={syncing}
                          className="underline underline-offset-[3px] hover:text-ink"
                        >
                          Or load my repositories now
                        </button>
                      </p>
                    ) : (
                      <p className="font-body text-[11px] text-slate">
                        Opens in a new window; pick the repositories Pencheff
                        may access. The list appears here when you’re done.
                      </p>
                    )}
                  </div>

                  {/* Advanced: bring your own GitHub App credentials */}
                  <details className="formal-surface p-5">
                    <summary className="cursor-pointer font-body text-[13px] text-graphite">
                      Advanced: use your own GitHub App credentials instead
                    </summary>
                    <div className="grid sm:grid-cols-2 gap-5 mt-4">
                      <div>
                        <Label>App ID</Label>
                        <Input
                          value={creds.github_app_id ?? ""}
                          onChange={(e) =>
                            setCreds({
                              ...creds,
                              github_app_id: e.target.value,
                            })
                          }
                          placeholder="123456"
                        />
                      </div>
                      <div>
                        <Label>Installation ID</Label>
                        <Input
                          value={creds.github_app_installation_id ?? ""}
                          onChange={(e) =>
                            setCreds({
                              ...creds,
                              github_app_installation_id: e.target.value,
                            })
                          }
                          placeholder="78910"
                        />
                      </div>
                      <div className="sm:col-span-2">
                        <Label>Private key (PEM)</Label>
                        <textarea
                          rows={8}
                          value={creds.github_app_private_key ?? ""}
                          onChange={(e) =>
                            setCreds({
                              ...creds,
                              github_app_private_key: e.target.value,
                            })
                          }
                          placeholder="-----BEGIN RSA PRIVATE KEY-----&#10;…&#10;-----END RSA PRIVATE KEY-----"
                          className="w-full font-mono text-[11px] bg-paper border border-hairline rounded-sm p-3 focus:outline-none focus:border-ink"
                        />
                      </div>
                    </div>
                  </details>
                </div>
              ))}

            {creds.auth_type === "ssh_key" && (
              <div>
                <Label>SSH private key</Label>
                <textarea
                  rows={8}
                  value={creds.ssh_private_key ?? ""}
                  onChange={(e) =>
                    setCreds({ ...creds, ssh_private_key: e.target.value })
                  }
                  placeholder="-----BEGIN OPENSSH PRIVATE KEY-----&#10;…"
                  className="w-full font-mono text-[11px] bg-paper border border-hairline rounded-sm p-3 focus:outline-none focus:border-ink"
                />
              </div>
            )}
          </section>

          <hr className="rule" />
        </>
      )}

      <section>
        <div className="flex items-baseline gap-3 mb-1">
          <span className="eyebrow-gilt">SC4</span>
          <h2 className="font-display text-[18px] text-ink">
            Scanner exclusions (optional)
          </h2>
        </div>
        <p className="text-[13px] text-slate italic mb-4">
          Tick scanners to skip. All others run in parallel against the cloned
          tree.
        </p>
        <div className="grid sm:grid-cols-2 gap-2">
          {SCANNERS.map((sc) => {
            const disabled = value.scanners_disabled.includes(sc.id);
            return (
              <label
                key={sc.id}
                className="flex items-center gap-3 cursor-pointer"
              >
                <input
                  type="checkbox"
                  checked={disabled}
                  onChange={() => toggleScanner(sc.id)}
                  className="w-[16px] h-[16px] border border-hairline rounded-sm accent-ink"
                />
                <span className="font-body text-[13px] text-ink">
                  Skip <code>{sc.label}</code>
                </span>
              </label>
            );
          })}
        </div>
      </section>
    </>
  );
}
