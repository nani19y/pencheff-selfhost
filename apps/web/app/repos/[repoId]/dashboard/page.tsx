"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { usePathname } from "next/navigation";
import { pathSegment } from "@/lib/route-params";
import { Button } from "@/components/brutal";
import { InlineLoading } from "@/components/loading";
import { SeverityDonut } from "@/components/dashboard/SeverityDonut";
import { SeverityStack } from "@/components/dashboard/SeverityStack";
import { TrendLine } from "@/components/dashboard/TrendLine";
import { api } from "@/lib/api";
import type { Severity } from "@/lib/sev";

type RepoTrendScan = {
  id: string;
  commit_sha: string | null;
  completed_at: string | null;
  started_at: string | null;
  status: string;
  severity_counts: Record<Severity, number>;
  scanner_durations_ms: Record<string, number>;
};

type RepoTrend = {
  repository: {
    id: string;
    full_name: string | null;
    default_branch: string | null;
  };
  scans: RepoTrendScan[];
  open_total: number;
  fixed_total: number;
  mttr_days: number | null;
};

const SEV_WEIGHT: Record<Severity, number> = {
  critical: 25,
  high: 10,
  medium: 4,
  low: 1,
  info: 0,
};

function severityScore(counts: Record<Severity, number>): number {
  return (
    counts.critical * SEV_WEIGHT.critical +
    counts.high * SEV_WEIGHT.high +
    counts.medium * SEV_WEIGHT.medium +
    counts.low * SEV_WEIGHT.low +
    counts.info * SEV_WEIGHT.info
  );
}

function shortSha(sha: string | null) {
  return sha ? sha.slice(0, 7) : "—";
}

export default function RepoDashboardPage() {
  const pathname = usePathname();
  const [mounted, setMounted] = useState(false);
  useEffect(() => setMounted(true), []);
  const repoId = mounted ? pathSegment(pathname, 2) : "";
  const [trend, setTrend] = useState<RepoTrend | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!repoId) return;
    let alive = true;
    setLoading(true);
    api<RepoTrend>(`/repos/${repoId}/trend`)
      .then((t) => {
        if (alive) setTrend(t);
      })
      .catch((e) => {
        if (alive)
          setError(e instanceof Error ? e.message : "Failed to load trend");
      })
      .finally(() => {
        if (alive) setLoading(false);
      });
    return () => {
      alive = false;
    };
  }, [repoId]);

  if (loading) {
    return (
      <div className="py-6">
        <InlineLoading label="Loading repo dashboard…" />
      </div>
    );
  }

  if (error || !trend) {
    return (
      <div className="formal-surface p-10">
        <p className="eyebrow-gilt">Dashboard unavailable</p>
        <h2 className="mt-3 font-display text-[24px] text-ink">
          {error ?? "We couldn't load this repository's trend."}
        </h2>
        <div className="mt-6">
          <Link href={`/repos/${repoId}`}>
            <Button variant="lime">← Back to repository</Button>
          </Link>
        </div>
      </div>
    );
  }

  const completed = trend.scans.filter((s) => s.status === "succeeded");
  const latest = completed[completed.length - 1];

  if (completed.length < 2) {
    return (
      <div className="space-y-6">
        <header className="flex items-start justify-between flex-wrap gap-6">
          <div>
            <p className="eyebrow-gilt">Repo dashboard</p>
            <h1 className="mt-4 font-display text-[32px] md:text-[40px] leading-[1.05] tracking-[-0.015em] text-ink">
              {trend.repository.full_name}
            </h1>
          </div>
          <Link href={`/repos/${repoId}`}>
            <Button variant="lime">← Back to repository</Button>
          </Link>
        </header>
        <section className="formal-surface p-10 text-center">
          <p className="eyebrow-gilt">More data needed</p>
          <h3 className="mt-4 font-display text-[24px] text-ink">
            Trends appear after the second successful scan.
          </h3>
          <p className="mt-3 text-[14px] text-slate max-w-[52ch] mx-auto">
            One scan is a snapshot — two or more reveal trajectory. Trigger
            another scan from the repository page; the dashboard populates
            automatically.
          </p>
        </section>
      </div>
    );
  }

  const trendPoints = completed
    .filter((s) => s.completed_at)
    .map((s) => ({
      date: s.completed_at as string,
      value: severityScore(s.severity_counts),
      label: shortSha(s.commit_sha),
    }));

  const stackPoints = completed
    .filter((s) => s.completed_at)
    .map((s) => ({
      date: s.completed_at as string,
      summary: s.severity_counts,
    }));

  return (
    <div className="space-y-8">
      <header className="flex items-start justify-between flex-wrap gap-6">
        <div>
          <p className="eyebrow-gilt">Repo dashboard</p>
          <h1 className="mt-4 font-display text-[36px] md:text-[42px] leading-[1.05] tracking-[-0.015em] text-ink">
            {trend.repository.full_name}
          </h1>
          <p className="mt-2 font-mono text-[12px] text-mist">
            {completed.length} successful scans
            {trend.repository.default_branch &&
              ` · ${trend.repository.default_branch}`}
          </p>
        </div>
        <Link href={`/repos/${repoId}`}>
          <Button variant="lime">← Back to repository</Button>
        </Link>
      </header>

      <section className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <RepoStatTile
          label="Open findings"
          value={trend.open_total}
          hint="Across all scans"
        />
        <RepoStatTile
          label="Merged fixes"
          value={trend.fixed_total}
          hint="PRs landed"
          tone="forest"
        />
        <RepoStatTile
          label="Latest commit"
          value={shortSha(latest?.commit_sha ?? null)}
          hint={latest?.completed_at?.slice(0, 10) || "—"}
        />
        <RepoStatTile
          label="Severity score"
          value={latest ? severityScore(latest.severity_counts) : 0}
          hint="Weighted critical→info"
        />
      </section>

      <section>
        <p className="eyebrow mb-3">Severity score over time</p>
        <TrendLine points={trendPoints} yLabel="Score" stroke="#A04545" />
      </section>

      <section>
        <p className="eyebrow mb-3">Severity counts per scan</p>
        <SeverityStack series={stackPoints} />
      </section>

      <section>
        <p className="eyebrow mb-3">Most recent scan</p>
        {latest ? (
          <div className="grid grid-cols-1 lg:grid-cols-[320px_1fr] gap-5">
            <SeverityDonut summary={latest.severity_counts} />
            <div className="formal-surface p-5">
              <p className="font-mono text-[10px] uppercase tracking-[0.16em] text-mist">
                Commit
              </p>
              <p className="mt-1 font-mono text-[14px] text-ink">
                {shortSha(latest.commit_sha)}
              </p>
              <p className="mt-3 font-mono text-[10px] uppercase tracking-[0.16em] text-mist">
                Scanner duration (ms)
              </p>
              <ul className="mt-2 space-y-1">
                {Object.entries(latest.scanner_durations_ms)
                  .sort((a, b) => b[1] - a[1])
                  .slice(0, 8)
                  .map(([scanner, ms]) => (
                    <li
                      key={scanner}
                      className="flex items-center justify-between font-mono text-[12px]"
                    >
                      <span className="text-graphite">{scanner}</span>
                      <span className="text-mist">
                        {(ms / 1000).toFixed(1)}s
                      </span>
                    </li>
                  ))}
              </ul>
              <div className="mt-4">
                <Link
                  href={`/repos/scans/${latest.id}/dashboard`}
                  className="inline-block border border-graphite px-4 py-2 font-mono text-[11px] uppercase tracking-[0.08em] hover:bg-graphite hover:text-white"
                >
                  Open scan dashboard →
                </Link>
              </div>
            </div>
          </div>
        ) : (
          <p className="text-[13px] text-slate italic">
            No completed scan yet.
          </p>
        )}
      </section>
    </div>
  );
}

function RepoStatTile({
  label,
  value,
  hint,
  tone = "ink",
}: {
  label: string;
  value: number | string;
  hint?: string;
  tone?: "ink" | "forest";
}) {
  return (
    <div className="formal-surface p-5">
      <p className="font-mono text-[10px] uppercase tracking-[0.16em] text-mist">
        {label}
      </p>
      <p
        className={
          "mt-2 font-display text-[36px] leading-none " +
          (tone === "forest" ? "text-forest" : "text-ink")
        }
      >
        {value}
      </p>
      {hint && (
        <p className="mt-2 font-mono text-[10px] text-slate break-all">
          {hint}
        </p>
      )}
    </div>
  );
}
