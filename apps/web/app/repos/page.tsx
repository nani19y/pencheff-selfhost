"use client";

import Link from "next/link";
import { Suspense, useEffect, useState } from "react";
import { useSearchParams } from "next/navigation";
import { Button } from "@/components/brutal";
import { InlineLoading } from "@/components/loading";
import { api } from "@/lib/api";

type Integration = {
  id: string;
  provider: string;
  installation_id: string;
  account_login: string;
  account_type: string;
  avatar_url: string | null;
  installed_at: string;
};

const CALLBACK_ERRORS: Record<string, string> = {
  "missing-installation": "GitHub didn't return an installation — try again.",
  "missing-state": "The install session expired — start from this page.",
  "no-workspace": "No workspace was found to attach the installation to.",
  "install-lookup-failed": "Couldn't read the installation back from GitHub.",
};

function ReposContent() {
  const params = useSearchParams();
  const callbackError = params.get("error");
  const justConnected = params.get("connected");

  const [integrations, setIntegrations] = useState<Integration[] | null>(null);
  const [installing, setInstalling] = useState(false);
  const [syncingId, setSyncingId] = useState<string | null>(null);
  const [msg, setMsg] = useState<string | null>(null);

  async function load() {
    try {
      setIntegrations(await api<Integration[]>("/repos/integrations"));
    } catch {
      setIntegrations([]);
    }
  }
  useEffect(() => {
    load();
  }, []);

  // When this page is the GitHub-App install popup (opened by the register
  // flow), signal the opener with the new integration id and close ourselves.
  useEffect(() => {
    if (
      justConnected &&
      typeof window !== "undefined" &&
      window.opener &&
      !window.opener.closed
    ) {
      try {
        window.opener.postMessage(
          { type: "pencheff:gh-installed", integrationId: justConnected },
          window.location.origin,
        );
      } catch {
        /* opener navigated away — ignore */
      }
      window.close();
    }
  }, [justConnected]);

  async function install() {
    setInstalling(true);
    setMsg(null);
    try {
      const r = await api<{ url: string; configured: boolean }>(
        "/repos/install-url",
      );
      if (!r.configured) {
        setMsg("The Pencheff GitHub App isn't configured on the server yet.");
        setInstalling(false);
        return;
      }
      window.location.href = r.url;
    } catch (e) {
      setMsg(e instanceof Error ? e.message : "Could not start the install.");
      setInstalling(false);
    }
  }

  async function sync(id: string) {
    setSyncingId(id);
    setMsg(null);
    try {
      await api(`/repos/integrations/${id}/sync`, { method: "POST" });
      await load();
      setMsg("Repositories synced.");
    } catch (e) {
      setMsg(e instanceof Error ? e.message : "Sync failed.");
    } finally {
      setSyncingId(null);
    }
  }

  return (
    <div>
      <div className="mb-8 flex items-start justify-between gap-4 flex-wrap">
        <div>
          <p className="font-mono text-[10px] uppercase tracking-[0.18em] text-mist">
            Repositories
          </p>
          <h1 className="mt-2 font-display text-[36px] leading-[1.05] tracking-[-0.015em] text-ink">
            Connected repositories.
          </h1>
          <p className="mt-2 text-[14px] text-slate">
            Install the Pencheff GitHub App to scan private and org repos with
            no tokens to manage.
          </p>
        </div>
        <Button variant="pink" onClick={install} disabled={installing}>
          {installing ? "Opening GitHub…" : "Install the Pencheff GitHub App →"}
        </Button>
      </div>

      {justConnected && !callbackError && (
        <div className="mb-6 formal-surface p-4 font-body text-[13px] text-graphite">
          GitHub App connected. Click <strong>Sync repos</strong> on the
          installation below to pull your repositories, then register one as a
          target.
        </div>
      )}
      {callbackError && (
        <div className="mb-6 advisory-warn font-body text-[13px]">
          {CALLBACK_ERRORS[callbackError] ?? `Install error: ${callbackError}`}
        </div>
      )}
      {msg && (
        <div className="mb-6 formal-surface p-4 font-body text-[13px] text-graphite">
          {msg}
        </div>
      )}

      {integrations === null ? (
        <InlineLoading label="Loading connections…" />
      ) : integrations.length === 0 ? (
        <div className="formal-surface p-10 text-center">
          <p className="eyebrow-gilt">Not connected</p>
          <h3 className="mt-3 font-display text-[22px] text-ink">
            No GitHub App installations yet.
          </h3>
          <p className="mt-2 text-[13px] text-slate">
            Click “Install the Pencheff GitHub App” above, choose the
            repositories Pencheff may access, and they’ll appear here.
          </p>
        </div>
      ) : (
        <ul className="space-y-3">
          {integrations.map((it) => (
            <li
              key={it.id}
              className="formal-surface p-5 flex items-center justify-between gap-4"
            >
              <div className="flex items-center gap-3">
                {/* eslint-disable-next-line @next/next/no-img-element */}
                {it.avatar_url && (
                  <img
                    src={it.avatar_url}
                    alt=""
                    className="w-9 h-9 rounded-sm border border-hairline"
                  />
                )}
                <div>
                  <p className="font-display text-[16px] text-ink">
                    {it.account_login}
                  </p>
                  <p className="font-mono text-[11px] text-slate">
                    {it.account_type} · GitHub App · installation{" "}
                    {it.installation_id}
                  </p>
                </div>
              </div>
              <Button
                variant="lime"
                onClick={() => sync(it.id)}
                disabled={syncingId === it.id}
              >
                {syncingId === it.id ? "Syncing…" : "Sync repos"}
              </Button>
            </li>
          ))}
        </ul>
      )}

      <div className="mt-8">
        <Link href="/targets/new">
          <Button variant="yellow">Register a repository as a target →</Button>
        </Link>
      </div>
    </div>
  );
}

export default function ReposPage() {
  return (
    <Suspense fallback={<InlineLoading label="Loading…" />}>
      <ReposContent />
    </Suspense>
  );
}
