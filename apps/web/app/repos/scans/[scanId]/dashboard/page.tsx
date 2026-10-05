"use client";

import Link from "next/link";
import { useEffect, useMemo, useState } from "react";
import { usePathname } from "next/navigation";
import { pathSegment } from "@/lib/route-params";
import { Button } from "@/components/brutal";
import { InlineLoading } from "@/components/loading";
import { CveTable } from "@/components/dashboard/repo/CveTable";
import { FileHotspotTreemap } from "@/components/dashboard/repo/FileHotspotTreemap";
import { FixStatusPie } from "@/components/dashboard/repo/FixStatusPie";
import { ScannerEffortBar } from "@/components/dashboard/repo/ScannerEffortBar";
import { SeverityDonut } from "@/components/dashboard/SeverityDonut";
import { api } from "@/lib/api";
import { normalizeSeverity, type Severity } from "@/lib/sev";

type RepoScan = {
  id: string;
  repository_id: string;
  commit_sha: string | null;
  status: string;
  trigger: string;
  scanners: string[] | null;
  stats: Record<
    string,
    { count?: number; error?: string; skipped?: string; duration_ms?: number }
  > | null;
  started_at: string | null;
  completed_at: string | null;
  error: string | null;
};

type RepoFinding = {
  id: string;
  scanner: string;
  severity: string;
  title: string;
  file_path: string | null;
  line_start: number | null;
  cve: string | null;
  package: string | null;
  installed_version: string | null;
  fixed_version: string | null;
  fix_status: string;
  fix_pr_url: string | null;
};

function shortSha(sha: string | null) {
  return sha ? sha.slice(0, 7) : "—";
}

export default function RepoScanDashboardPage() {
  const pathname = usePathname();
  const [mounted, setMounted] = useState(false);
  useEffect(() => setMounted(true), []);
  const scanId = mounted ? pathSegment(pathname, 3) : "";
  const [scan, setScan] = useState<RepoScan | null>(null);
  const [findings, setFindings] = useState<RepoFinding[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!scanId) return;
    let alive = true;
    setLoading(true);
    Promise.all([
      api<RepoScan>(`/repos/scans/${scanId}`).catch(() => null),
      api<RepoFinding[]>(`/repos/scans/${scanId}/findings`).catch(
        () => [] as RepoFinding[],
      ),
    ])
      .then(([s, f]) => {
        if (!alive) return;
        setScan(s);
        setFindings(f || []);
      })
      .finally(() => {
        if (alive) setLoading(false);
      });
    return () => {
      alive = false;
    };
  }, [scanId]);

  const summary = useMemo(() => {
    const counts: Record<Severity, number> = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
    };
    for (const f of findings) {
      counts[normalizeSeverity(f.severity)] += 1;
    }
    return counts;
  }, [findings]);

  const totalDurationMs = useMemo(() => {
    if (!scan?.stats) return 0;
    return Object.values(scan.stats).reduce(
      (acc, s) => acc + (s.duration_ms || 0),
      0,
    );
  }, [scan]);

  const fixStats = useMemo(() => {
    const total = findings.length;
    const merged = findings.filter((f) => f.fix_status === "merged").length;
    const open = findings.filter((f) => f.fix_status === "pr_open").length;
    const proposed = findings.filter((f) => f.fix_status === "proposed").length;
    return { total, merged, open, proposed };
  }, [findings]);

  if (loading || !scan) {
    return (
      <div className="py-6">
        <InlineLoading label="Loading repo dashboard…" />
      </div>
    );
  }

  if (scan.status !== "succeeded") {
    return (
      <div className="space-y-6">
        <header className="flex items-start justify-between flex-wrap gap-6">
          <div>
            <p className="eyebrow-gilt">Repo dashboard</p>
            <h1 className="mt-4 font-display text-[32px] md:text-[40px] leading-[1.05] tracking-[-0.015em] text-ink">
              Scan @{shortSha(scan.commit_sha)}
            </h1>
          </div>
          <Link href={`/repos/scans/${scanId}`}>
            <Button variant="lime">← Back to scan</Button>
          </Link>
        </header>
        <section className="formal-surface p-10 text-center">
          <p className="eyebrow-gilt">Scan {scan.status}</p>
          <h3 className="mt-4 font-display text-[24px] text-ink">
            Dashboard available once the scan succeeds.
          </h3>
          <p className="mt-3 text-[14px] text-slate max-w-[52ch] mx-auto">
            Charts depend on the full findings register. Track scan status
            below; the dashboard populates automatically when the scan
            completes.
          </p>
          <div className="mt-6 flex justify-center">
            <Link href={`/repos/scans/${scanId}`}>
              <Button variant="pink">View scan progress</Button>
            </Link>
          </div>
        </section>
      </div>
    );
  }

  return (
    <div className="space-y-8">
      <header className="flex items-start justify-between flex-wrap gap-6">
        <div>
          <p className="eyebrow-gilt">Repo dashboard</p>
          <h1 className="mt-4 font-display text-[36px] md:text-[42px] leading-[1.05] tracking-[-0.015em] text-ink">
            Scan @{shortSha(scan.commit_sha)}
          </h1>
          <p className="mt-2 font-mono text-[12px] text-mist">
            {scan.completed_at
              ? `Completed ${scan.completed_at.replace("T", " · ").slice(0, 22)}`
              : "Completed"}
            {" · "}
            {scan.trigger}
          </p>
        </div>
        <div className="flex items-center gap-3">
          <Link href={`/repos/${scan.repository_id}`}>
            <Button variant="lime">↑ Repository</Button>
          </Link>
          <Link href={`/repos/scans/${scanId}`}>
            <Button variant="lime">← Findings</Button>
          </Link>
        </div>
      </header>

      {/* Top tiles */}
      <section className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <RepoStatTile
          label="Total findings"
          value={fixStats.total}
          hint="Active in this scan"
        />
        <RepoStatTile
          label="Scanners run"
          value={Object.keys(scan.stats || {}).length}
          hint={(scan.scanners || []).join(" · ")}
        />
        <RepoStatTile
          label="Scan duration"
          value={
            totalDurationMs > 0
              ? `${(totalDurationMs / 1000).toFixed(1)}s`
              : "—"
          }
          hint="Sum across scanners"
        />
        <RepoStatTile
          label="Fix progress"
          value={`${fixStats.merged + fixStats.open} / ${fixStats.total}`}
          hint={`${fixStats.merged} merged · ${fixStats.open} open · ${fixStats.proposed} proposed`}
        />
      </section>

      {/* Severity + scanner effort */}
      <section>
        <p className="eyebrow mb-3">Severity · Scanner effort</p>
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
          <SeverityDonut summary={summary} />
          <ScannerEffortBar stats={scan.stats} />
        </div>
      </section>

      {/* File hotspot + fix status */}
      <section>
        <p className="eyebrow mb-3">File hotspots · Fix status</p>
        <div className="grid grid-cols-1 lg:grid-cols-[1fr_320px] gap-5">
          <FileHotspotTreemap findings={findings} />
          <FixStatusPie findings={findings} />
        </div>
      </section>

      {/* CVEs */}
      <section>
        <p className="eyebrow mb-3">Top CVEs</p>
        <CveTable findings={findings} />
      </section>
    </div>
  );
}

function RepoStatTile({
  label,
  value,
  hint,
}: {
  label: string;
  value: number | string;
  hint?: string;
}) {
  return (
    <div className="formal-surface p-5">
      <p className="font-mono text-[10px] uppercase tracking-[0.16em] text-mist">
        {label}
      </p>
      <p className="mt-2 font-display text-[36px] leading-none text-ink">
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
