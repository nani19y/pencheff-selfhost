"use client";

import Link from "next/link";
import { Button, Input, Label } from "@/components/brutal";
import { InlineLoading } from "@/components/loading";

type Profile = "quick" | "standard" | "deep";

const PROFILE_COPY: Record<Profile, { label: string; body: string }> = {
  quick: { label: "Quick", body: "2–5 min · surface pass" },
  standard: { label: "Standard", body: "10–25 min · recommended" },
  deep: { label: "Deep", body: "30–90 min · exhaustive" },
};

type AttachableRepo = {
  id: string;
  full_name: string;
  provider: string;
  language: string | null;
  html_url: string;
  local_path: string | null;
};

export function UrlFormSection({
  url, setUrl,
  name, setName,
  username, setUsername,
  password, setPassword,
  apiKey, setApiKey,
  token, setToken,
  cookie, setCookie,
  profile, setProfile,
  availableRepos,
  reposLoading,
  reposError,
  attachedRepoIds,
  toggleAttachedRepo,
  repoFilter, setRepoFilter,
}: {
  url: string; setUrl: (v: string) => void;
  name: string; setName: (v: string) => void;
  username: string; setUsername: (v: string) => void;
  password: string; setPassword: (v: string) => void;
  apiKey: string; setApiKey: (v: string) => void;
  token: string; setToken: (v: string) => void;
  cookie: string; setCookie: (v: string) => void;
  profile: Profile; setProfile: (v: Profile) => void;
  availableRepos: AttachableRepo[];
  reposLoading: boolean;
  reposError: string | null;
  attachedRepoIds: string[];
  toggleAttachedRepo: (id: string) => void;
  repoFilter: string; setRepoFilter: (v: string) => void;
}) {
  return (
    <>
      <section>
        <div className="flex items-baseline gap-3 mb-5">
          <span className="eyebrow-gilt">A1</span>
          <h2 className="font-display text-[18px] text-ink">Web / API Target</h2>
        </div>
        <div className="grid md:grid-cols-2 gap-5">
          <div className="md:col-span-2">
            <Label>Application URL</Label>
            <Input
              type="url"
              required
              placeholder="https://staging.example.com"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
            />
          </div>
          <div className="md:col-span-2">
            <Label>Name (optional)</Label>
            <Input
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="Staging API"
            />
          </div>
        </div>
      </section>

      <hr className="rule" />

      <section>
        <div className="flex items-baseline gap-3 mb-1">
          <span className="eyebrow-gilt">A2</span>
          <h2 className="font-display text-[18px] text-ink">Credentials</h2>
        </div>
        <p className="text-[13px] text-slate italic mb-6">
          Optional — enables authenticated coverage. Stored encrypted with
          Fernet (AES-128 CBC + HMAC-SHA256).
        </p>
        <div className="grid sm:grid-cols-2 gap-5">
          <div>
            <Label>Username</Label>
            <Input value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="off" />
          </div>
          <div>
            <Label>Password</Label>
            <Input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="off" />
          </div>
          <div>
            <Label>API key</Label>
            <Input value={apiKey} onChange={(e) => setApiKey(e.target.value)} autoComplete="off" />
          </div>
          <div>
            <Label>Bearer token</Label>
            <Input value={token} onChange={(e) => setToken(e.target.value)} autoComplete="off" />
          </div>
          <div className="sm:col-span-2">
            <Label>Cookie header</Label>
            <Input
              value={cookie}
              onChange={(e) => setCookie(e.target.value)}
              placeholder="session=abc123; XSRF-TOKEN=…"
              autoComplete="off"
            />
          </div>
        </div>
      </section>

      <hr className="rule" />

      <section>
        <div className="flex items-baseline gap-3 mb-1">
          <span className="eyebrow-gilt">A3</span>
          <h2 className="font-display text-[18px] text-ink">Source repositories</h2>
        </div>
        <p className="text-[13px] text-slate italic mb-4">
          Optional — attach one or more registered repos and SAST runs
          against each in parallel with DAST. Findings merge into the
          same report.
        </p>

        {reposLoading && <InlineLoading label="Loading repos…" />}
        {reposError && (
          <p className="font-mono text-[12px] text-rust">{reposError}</p>
        )}
        {!reposLoading && !reposError && availableRepos.length === 0 && (
          <p className="font-body text-[13px] text-slate">
            No repositories registered yet.{" "}
            <Link
              href="/repos"
              className="underline underline-offset-[4px] decoration-gilt decoration-1 hover:text-ink"
            >
              Register a repository
            </Link>{" "}
            to attach it to a URL target.
          </p>
        )}
        {!reposLoading && !reposError && availableRepos.length > 0 && (
          <>
            <div className="mb-4 flex items-center gap-3">
              <Input
                type="search"
                placeholder="Filter by name or language…"
                value={repoFilter}
                onChange={(e) => setRepoFilter(e.target.value)}
                className="max-w-md"
              />
              <span className="font-mono text-[11px] text-mist whitespace-nowrap">
                {attachedRepoIds.length} of {availableRepos.length} selected
              </span>
            </div>
            <ul
              className="divide-y divide-hairline border border-hairline rounded-sm bg-paper max-h-[320px] overflow-y-auto"
              role="listbox"
              aria-label="Repositories to attach"
              aria-multiselectable="true"
            >
              {availableRepos
                .filter((r) => {
                  const q = repoFilter.trim().toLowerCase();
                  if (!q) return true;
                  return (
                    r.full_name.toLowerCase().includes(q) ||
                    (r.language || "").toLowerCase().includes(q)
                  );
                })
                .map((r) => {
                  const checked = attachedRepoIds.includes(r.id);
                  return (
                    <li key={r.id}>
                      <label
                        className={
                          "flex items-start gap-3 px-4 py-3 cursor-pointer transition-colors " +
                          (checked ? "bg-vellum" : "hover:bg-vellum/40")
                        }
                      >
                        <input
                          type="checkbox"
                          checked={checked}
                          onChange={() => toggleAttachedRepo(r.id)}
                          aria-label={`Attach ${r.full_name}`}
                          className="mt-1 w-[16px] h-[16px] border border-hairline rounded-sm accent-ink"
                        />
                        <span className="flex-1 min-w-0">
                          <span className="block font-mono text-[13px] text-ink truncate">
                            {r.full_name}
                          </span>
                          <span className="block font-mono text-[11px] text-mist truncate">
                            {r.provider}
                            {r.language ? ` · ${r.language}` : ""}
                            {r.local_path ? ` · ${r.local_path}` : ""}
                          </span>
                        </span>
                      </label>
                    </li>
                  );
                })}
            </ul>
          </>
        )}
      </section>

      <hr className="rule" />

      <section>
        <div className="flex items-baseline gap-3 mb-5">
          <span className="eyebrow-gilt">A4</span>
          <h2 className="font-display text-[18px] text-ink">Assessment profile</h2>
        </div>
        <div className="grid sm:grid-cols-3 gap-4" role="radiogroup" aria-label="Assessment profile">
          {(Object.keys(PROFILE_COPY) as Profile[]).map((p) => {
            const active = profile === p;
            return (
              <button
                key={p}
                type="button"
                role="radio"
                aria-checked={active}
                onClick={() => setProfile(p)}
                className={
                  "text-left border rounded-sm p-5 transition-colors duration-150 " +
                  (active
                    ? "border-ink bg-vellum shadow-subtle"
                    : "border-hairline bg-paper hover:border-ink")
                }
              >
                <span className={"eyebrow " + (active ? "text-gilt" : "")}>
                  Profile {p === "quick" ? "i" : p === "standard" ? "ii" : "iii"}
                </span>
                <span className="mt-2 block font-display text-[20px] text-ink">
                  {PROFILE_COPY[p].label}
                </span>
                <span className="mt-1 block font-mono text-[11px] text-mist">
                  {PROFILE_COPY[p].body}
                </span>
              </button>
            );
          })}
        </div>
      </section>
    </>
  );
}
