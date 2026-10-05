"use client";

import Link from "next/link";
import { useState } from "react";
import { Input, Label } from "@/components/brutal";

type RepoSource = "public" | "private" | "app";

export function RepoFormSection({
  repoSource, setRepoSource,
  githubUrl, setGithubUrl,
  pat, setPat,
}: {
  repoSource: RepoSource; setRepoSource: (v: RepoSource) => void;
  githubUrl: string; setGithubUrl: (v: string) => void;
  pat: string; setPat: (v: string) => void;
}) {
  const [showPatHelp, setShowPatHelp] = useState(false);
  const [showAppHelp, setShowAppHelp] = useState(false);

  return (
    <>
      <section>
        <div className="flex items-baseline gap-3 mb-5">
          <span className="eyebrow-gilt">B1</span>
          <h2 className="font-display text-[18px] text-ink">Repository / Code Source</h2>
        </div>
        <div
          className="grid sm:grid-cols-3 gap-4"
          role="radiogroup"
          aria-label="Repository source"
        >
          {([
            {
              value: "public" as RepoSource,
              label: "Public GitHub URL",
              body: "Anonymous shallow clone · public repos only",
            },
            {
              value: "private" as RepoSource,
              label: "Private GitHub (PAT)",
              body: "HTTPS clone authenticated with a Personal Access Token",
            },
            {
              value: "app" as RepoSource,
              label: "Pencheff GitHub App",
              body: "Recommended — webhooks, Dependabot, no token rotation",
            },
          ]).map(({ value, label, body }, i) => {
            const active = repoSource === value;
            return (
              <button
                key={value}
                type="button"
                role="radio"
                aria-checked={active}
                onClick={() => setRepoSource(value)}
                className={
                  "text-left border rounded-sm p-5 transition-colors duration-150 " +
                  (active
                    ? "border-ink bg-vellum shadow-subtle"
                    : "border-hairline bg-paper hover:border-ink")
                }
              >
                <span className={"eyebrow " + (active ? "text-gilt" : "")}>
                  Source {["i", "ii", "iii"][i]}
                </span>
                <span className="mt-2 block font-display text-[18px] text-ink">
                  {label}
                </span>
                <span className="mt-1 block font-mono text-[11px] text-mist">
                  {body}
                </span>
              </button>
            );
          })}
        </div>
      </section>

      <hr className="rule" />

      {repoSource === "public" && (
        <section>
          <div className="flex items-baseline gap-3 mb-5">
            <span className="eyebrow-gilt">B2</span>
            <h2 className="font-display text-[18px] text-ink">Public repository URL</h2>
          </div>
          <Label>github.com URL</Label>
          <Input
            type="url"
            required
            placeholder="https://github.com/acme/api"
            value={githubUrl}
            onChange={(e) => setGithubUrl(e.target.value)}
            className="font-mono text-[13px]"
          />
          <p className="mt-2 text-[13px] text-slate">
            Anonymous shallow clone of a public repo&rsquo;s default branch. The
            worker runs CodeQL · Semgrep · OSV · secret scanning · IaC checks.
          </p>
        </section>
      )}

      {repoSource === "private" && (
        <>
          <section>
            <div className="flex items-baseline gap-3 mb-5">
              <span className="eyebrow-gilt">B2</span>
              <h2 className="font-display text-[18px] text-ink">Private repository URL + token</h2>
            </div>
            <div className="grid gap-5">
              <div>
                <Label>github.com URL</Label>
                <Input
                  type="url"
                  required
                  placeholder="https://github.com/acme/private-api"
                  value={githubUrl}
                  onChange={(e) => setGithubUrl(e.target.value)}
                  className="font-mono text-[13px]"
                />
              </div>
              <div>
                <Label>Personal Access Token</Label>
                <Input
                  type="password"
                  required
                  placeholder="ghp_… (classic) or github_pat_… (fine-grained)"
                  value={pat}
                  onChange={(e) => setPat(e.target.value)}
                  className="font-mono text-[13px]"
                  autoComplete="off"
                />
                <p className="mt-2 text-[13px] text-slate">
                  Stored Fernet-encrypted. Never logged or returned through the API.
                </p>
              </div>
            </div>
          </section>

          <hr className="rule" />

          <section>
            <button
              type="button"
              onClick={() => setShowPatHelp((v) => !v)}
              className="flex items-baseline gap-3 mb-5 text-left"
            >
              <span className="eyebrow-gilt">B3</span>
              <h2 className="font-display text-[18px] text-ink underline underline-offset-[6px] decoration-gilt decoration-1">
                How do I create a Personal Access Token?
              </h2>
              <span className="font-mono text-[11px] text-slate">
                {showPatHelp ? "[hide]" : "[show]"}
              </span>
            </button>
            {showPatHelp && (
              <div className="formal-surface p-6 space-y-6 text-[14px]">
                <div>
                  <h3 className="font-display text-[16px] text-ink mb-3">Option A — Fine-grained PAT (recommended)</h3>
                  <ol className="list-decimal pl-6 space-y-2 text-graphite">
                    <li>Open <a href="https://github.com/settings/personal-access-tokens/new" target="_blank" rel="noopener" className="underline underline-offset-[4px] decoration-gilt decoration-1 hover:text-ink">github.com/settings/personal-access-tokens/new</a>.</li>
                    <li><strong>Repository access:</strong> select <em>Only select repositories</em>.</li>
                    <li><strong>Repository permissions:</strong> Contents → Read-only, Metadata → Read-only.</li>
                    <li>Click <strong>Generate token</strong>. Copy the <code>github_pat_</code> value and paste above.</li>
                  </ol>
                </div>
                <hr className="rule" />
                <div>
                  <h3 className="font-display text-[16px] text-ink mb-3">Option B — Classic PAT</h3>
                  <ol className="list-decimal pl-6 space-y-2 text-graphite">
                    <li>Open <a href="https://github.com/settings/tokens/new" target="_blank" rel="noopener" className="underline underline-offset-[4px] decoration-gilt decoration-1 hover:text-ink">github.com/settings/tokens/new</a>.</li>
                    <li>Scope: tick <code>repo</code>. Click <strong>Generate token</strong>.</li>
                  </ol>
                </div>
              </div>
            )}
          </section>
        </>
      )}

      {repoSource === "app" && (
        <>
          <section>
            <div className="flex items-baseline gap-3 mb-5">
              <span className="eyebrow-gilt">B2</span>
              <h2 className="font-display text-[18px] text-ink">GitHub App install</h2>
            </div>
            <div className="formal-surface p-6 text-[14px] space-y-3">
              <p className="text-graphite">
                The Pencheff GitHub App is the <strong>recommended</strong> path for
                private and org repos: no token rotation, push webhooks, Dependabot ingestion.
              </p>
              <p className="text-slate">
                Click <strong>Register repository</strong> below — it will redirect you to the install flow.
              </p>
            </div>
          </section>

          <hr className="rule" />

          <section>
            <button
              type="button"
              onClick={() => setShowAppHelp((v) => !v)}
              className="flex items-baseline gap-3 mb-5 text-left"
            >
              <span className="eyebrow-gilt">B3</span>
              <h2 className="font-display text-[18px] text-ink underline underline-offset-[6px] decoration-gilt decoration-1">
                How do I install the Pencheff GitHub App?
              </h2>
              <span className="font-mono text-[11px] text-slate">
                {showAppHelp ? "[hide]" : "[show]"}
              </span>
            </button>
            {showAppHelp && (
              <div className="formal-surface p-6 space-y-4 text-[14px]">
                <ol className="list-decimal pl-6 space-y-2 text-graphite">
                  <li>Click <strong>Register repository</strong> below → lands on <Link href="/repos" className="underline underline-offset-[4px] decoration-gilt decoration-1 hover:text-ink">/repos</Link>.</li>
                  <li>Click <strong>Install Pencheff</strong> → GitHub install flow.</li>
                  <li>Select the repositories Pencheff may access.</li>
                  <li>GitHub redirects back to <code>/repos/callback</code>.</li>
                  <li>Click <strong>Sync</strong> on the installation card.</li>
                </ol>
              </div>
            )}
          </section>
        </>
      )}
    </>
  );
}
