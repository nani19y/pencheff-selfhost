"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { pathSegment } from "@/lib/route-params";
import { useEffect, useState } from "react";
import { Button, Input, Label } from "@/components/brutal";
import { InlineLoading } from "@/components/loading";
import { api } from "@/lib/api";

type Repo = {
  id: string;
  provider: string;
  integration_id: string | null;
  full_name: string;
  owner: string;
  name: string;
  default_branch: string;
  private: boolean;
  html_url: string;
  language: string | null;
  auto_scan_on_push: boolean;
  local_path: string | null;
};

type RepoUpdate = {
  default_branch?: string | null;
  language?: string | null;
  auto_scan_on_push?: boolean | null;
  local_path?: string | null;
  token?: string | null;
};

export default function RepoEditPage() {
  const pathname = usePathname();
  const router = useRouter();
  const [mounted, setMounted] = useState(false);
  useEffect(() => setMounted(true), []);
  const repoId = mounted ? pathSegment(pathname, 2) : "";

  const [repo, setRepo] = useState<Repo | null>(null);
  const [loadErr, setLoadErr] = useState<string | null>(null);

  const [defaultBranch, setDefaultBranch] = useState("");
  const [language, setLanguage] = useState("");
  const [autoScan, setAutoScan] = useState(true);
  const [localPath, setLocalPath] = useState("");
  const [token, setToken] = useState("");
  const [rotateToken, setRotateToken] = useState(false);

  const [saving, setSaving] = useState(false);
  const [saveErr, setSaveErr] = useState<string | null>(null);

  useEffect(() => {
    if (!repoId) return;
    let alive = true;
    (async () => {
      try {
        const r = await api<Repo>(`/repos/${repoId}`);
        if (!alive) return;
        setRepo(r);
        setDefaultBranch(r.default_branch);
        setLanguage(r.language ?? "");
        setAutoScan(r.auto_scan_on_push);
        setLocalPath(r.local_path ?? "");
      } catch (e) {
        if (alive) setLoadErr((e as Error).message);
      }
    })();
    return () => {
      alive = false;
    };
  }, [repoId]);

  async function save(e: React.FormEvent) {
    e.preventDefault();
    if (!repo) return;
    setSaveErr(null);
    setSaving(true);

    const body: RepoUpdate = {};
    if (defaultBranch.trim() && defaultBranch !== repo.default_branch) {
      body.default_branch = defaultBranch.trim();
    }
    if (language !== (repo.language ?? "")) {
      body.language = language.trim();
    }
    if (autoScan !== repo.auto_scan_on_push) {
      body.auto_scan_on_push = autoScan;
    }
    if (repo.provider === "local" && localPath !== (repo.local_path ?? "")) {
      body.local_path = localPath.trim();
    }
    if (rotateToken && repo.provider === "github") {
      body.token = token; // empty string clears, non-empty rotates
    }

    if (Object.keys(body).length === 0) {
      setSaving(false);
      router.push(`/repos/${repoId}`);
      return;
    }

    try {
      await api(`/repos/${repoId}`, { method: "PATCH", json: body });
      router.push(`/repos/${repoId}`);
    } catch (e) {
      setSaveErr((e as Error).message);
      setSaving(false);
    }
  }

  if (!repo) {
    if (loadErr) return <p className="text-[14px] text-oxblood">{loadErr}</p>;
    return (
      <div className="py-6">
        <InlineLoading label="Loading…" />
      </div>
    );
  }

  const isAppRepo = repo.provider === "github" && repo.integration_id !== null;
  const isLocal = repo.provider === "local";
  const isGithubPublic =
    repo.provider === "github" && repo.integration_id === null;

  return (
    <div>
      <div className="mb-4">
        <Link
          href={`/repos/${repoId}`}
          className="text-[13px] text-slate hover:text-ink underline underline-offset-[6px] decoration-gilt decoration-1"
        >
          ← Back to repo
        </Link>
      </div>

      <h1 className="font-display text-[36px] leading-[1.05] tracking-[-0.015em] text-ink">
        Edit repository
      </h1>
      <p className="mt-3 text-[13px] text-slate">
        {repo.full_name} · {repo.provider}
        {isAppRepo && " · GitHub App"}
        {isGithubPublic && " · public clone"}
        {isLocal && " · local"}
      </p>

      {isAppRepo && (
        <div className="mt-6 border border-hairline rounded-md px-4 py-3 text-[13px] text-graphite bg-vellum">
          This repo is managed by a GitHub App installation, so its branch,
          language, and access are synced from GitHub and can&apos;t be edited
          here. You can still control <strong>auto-scan on push</strong> below.
        </div>
      )}

      <form onSubmit={save} className="mt-10 max-w-[720px] space-y-8">
        <div>
          <Label htmlFor="default_branch">Default branch</Label>
          <Input
            id="default_branch"
            value={defaultBranch}
            onChange={(e) => setDefaultBranch(e.target.value)}
            disabled={isAppRepo}
            placeholder="main"
          />
          <p className="mt-2 text-[12px] text-slate">
            The branch every new scan checks out.
          </p>
        </div>

        <div>
          <Label htmlFor="language">Primary language</Label>
          <Input
            id="language"
            value={language}
            onChange={(e) => setLanguage(e.target.value)}
            disabled={isAppRepo}
            placeholder="Python, JavaScript, Go, …"
          />
          <p className="mt-2 text-[12px] text-slate">
            Drives CodeQL query suite selection. Leave blank to skip CodeQL.
          </p>
        </div>

        <div>
          <Label htmlFor="auto_scan">Auto-scan on push</Label>
          <label className="inline-flex items-center gap-3 mt-2">
            <input
              id="auto_scan"
              type="checkbox"
              checked={autoScan}
              onChange={(e) => setAutoScan(e.target.checked)}
              disabled={isLocal}
              className="h-4 w-4"
            />
            <span className="text-[14px] text-graphite">
              Run a scan automatically when a new commit lands on the default
              branch.
            </span>
          </label>
          <p className="mt-2 text-[12px] text-slate">
            {isLocal
              ? "Local-folder repos have no push events to react to."
              : isAppRepo
                ? "Off by default. Turn on to scan every push to the default branch (uses scan quota). Requires the GitHub App webhook to be active."
                : "Off by default."}
          </p>
        </div>

        {isLocal && (
          <div>
            <Label htmlFor="local_path">Local path</Label>
            <Input
              id="local_path"
              value={localPath}
              onChange={(e) => setLocalPath(e.target.value)}
              placeholder="/srv/repos/my-app"
            />
            <p className="mt-2 text-[12px] text-slate">
              Filesystem path readable by the worker container.
            </p>
          </div>
        )}

        {isGithubPublic && (
          <div>
            <Label htmlFor="rotate_token">Personal Access Token</Label>
            <label className="inline-flex items-center gap-3 mt-2">
              <input
                id="rotate_token"
                type="checkbox"
                checked={rotateToken}
                onChange={(e) => setRotateToken(e.target.checked)}
                className="h-4 w-4"
              />
              <span className="text-[14px] text-graphite">
                Rotate or set a new PAT for private-repo access
              </span>
            </label>
            {rotateToken && (
              <div className="mt-3">
                <Input
                  id="token"
                  type="password"
                  value={token}
                  onChange={(e) => setToken(e.target.value)}
                  placeholder="ghp_… (leave empty to clear stored token)"
                />
                <p className="mt-2 text-[12px] text-slate">
                  Stored Fernet-encrypted; never returned by the API.
                </p>
              </div>
            )}
          </div>
        )}

        {saveErr && (
          <div className="border border-oxblood rounded-md px-4 py-3 text-[13px] text-oxblood bg-vellum">
            {saveErr}
          </div>
        )}

        <div className="flex items-center gap-3">
          <Button type="submit" variant="pink" disabled={saving}>
            {saving ? "Saving…" : "Save changes"}
          </Button>
          <Link href={`/repos/${repoId}`}>
            <Button type="button" variant="lime">
              Cancel
            </Button>
          </Link>
        </div>
      </form>
    </div>
  );
}
