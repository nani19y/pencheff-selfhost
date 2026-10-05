"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { pathSegment } from "@/lib/route-params";
import { useEffect, useMemo, useState } from "react";
import { Button } from "@/components/brutal";
import { InlineLoading } from "@/components/loading";
import { FixAllAgentButton } from "@/components/fix-all-agent-button";
import { api } from "@/lib/api";

type Scan = {
  id: string;
  repository_id: string;
  commit_sha: string | null;
  status: string;
  trigger: string;
  scanners: string[] | null;
  stats: Record<
    string,
    { count?: number; error?: string; skipped?: string }
  > | null;
  started_at: string | null;
  completed_at: string | null;
  error: string | null;
};

type Finding = {
  id: string;
  scanner: string;
  rule_id: string | null;
  severity: string;
  title: string;
  description: string | null;
  file_path: string | null;
  line_start: number | null;
  line_end: number | null;
  code_snippet: string | null;
  cve: string | null;
  package: string | null;
  installed_version: string | null;
  fixed_version: string | null;
  fix_status: string;
  fix_pr_url: string | null;
};

const SEV_ORDER = ["critical", "high", "medium", "low", "info"];
const SCANNER_NAMES = new Set([
  // SAST replacements after the CodeQL removal (Phase 0.1):
  "semgrep",
  "bandit",
  "gosec",
  "brakeman",
  "eslint",
  // Existing non-SAST scanners — unchanged.
  "gitleaks",
  "ghsa",
  "yara",
  "trivy_iac",
  "checkov",
]);
const SEV_CLASS: Record<string, string> = {
  critical: "bg-oxblood text-paper",
  high: "bg-gilt text-ink",
  medium: "bg-vellum text-ink",
  low: "bg-paper text-slate",
  info: "bg-paper text-slate",
};

export default function RepoScanPage() {
  const pathname = usePathname();
  const [mounted, setMounted] = useState(false);
  useEffect(() => setMounted(true), []);
  const scanId = mounted ? pathSegment(pathname, 3) : "";
  const router = useRouter();
  const [scan, setScan] = useState<Scan | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [filter, setFilter] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [deleting, setDeleting] = useState(false);

  async function handleDelete() {
    if (!scan) return;
    if (
      !window.confirm(
        "Delete this repo scan and all its findings? This cannot be undone.",
      )
    )
      return;
    setDeleting(true);
    try {
      await api(`/repos/scans/${scanId}`, { method: "DELETE" });
      router.push(`/repos/${scan.repository_id}`);
    } catch (e) {
      setErr((e as Error).message);
      setDeleting(false);
    }
  }

  async function reload() {
    try {
      const [s, f] = await Promise.all([
        api<Scan>(`/repos/scans/${scanId}`),
        api<Finding[]>(`/repos/scans/${scanId}/findings`),
      ]);
      setScan(s);
      setFindings(f);
    } catch (e) {
      setErr((e as Error).message);
    }
  }
  useEffect(() => {
    if (!scanId) return;
    reload();
  }, [scanId]);

  useEffect(() => {
    if (!scan) return;
    if (scan.status === "queued" || scan.status === "running") {
      const id = setInterval(reload, 4000);
      return () => clearInterval(id);
    }
  }, [scan]);

  const grouped = useMemo(() => {
    const map: Record<string, Finding[]> = {};
    for (const f of findings) {
      if (filter && f.scanner !== filter) continue;
      (map[f.severity] ??= []).push(f);
    }
    return map;
  }, [findings, filter]);

  if (!scan) {
    if (err) return <p className="text-[14px] text-oxblood">{err}</p>;
    return (
      <div className="py-6">
        <InlineLoading label="Loading…" />
      </div>
    );
  }

  return (
    <div>
      <div className="mb-4 flex items-center justify-between gap-4">
        <Link
          href={`/repos/${scan.repository_id}`}
          className="text-[13px] text-slate hover:text-ink underline underline-offset-[6px] decoration-gilt decoration-1"
        >
          ← Back to repo
        </Link>
        <Button variant="danger" onClick={handleDelete} disabled={deleting}>
          {deleting ? "Deleting…" : "Delete"}
        </Button>
      </div>

      <h1 className="font-display text-[36px] leading-[1.05] tracking-[-0.015em] text-ink">
        Scan findings
      </h1>
      <p className="mt-3 text-[13px] text-slate">
        {scan.status} · commit {scan.commit_sha?.slice(0, 7) ?? "—"} · trigger{" "}
        {scan.trigger}
        {scan.completed_at && ` · completed ${fmtDate(scan.completed_at)}`}
      </p>
      {scan.error && (
        <div className="mt-4 border border-oxblood rounded-md px-4 py-3 text-[13px] text-oxblood bg-vellum">
          {scan.error}
        </div>
      )}

      {scan.stats && (
        <div className="mt-6 flex flex-wrap gap-2">
          <ScannerChip
            name="all"
            active={filter === null}
            onClick={() => setFilter(null)}
          />
          {Object.entries(scan.stats)
            .filter(([name]) => SCANNER_NAMES.has(name))
            .map(([name, v]) => (
              <ScannerChip
                key={name}
                name={`${name} · ${v.error ?? v.skipped ?? v.count ?? 0}`}
                active={filter === name}
                onClick={() => setFilter(name)}
              />
            ))}
        </div>
      )}

      {(scan.status === "succeeded" || scan.status === "completed") && (
        <div className="mt-6 flex flex-wrap items-center gap-3">
          {findings.length > 0 && (
            <div className="flex flex-col gap-3 w-full">
              <FixAllAgentButton scope="repo" id={scanId} />
            </div>
          )}
          <Link
            href={`/repos/scans/${scanId}/dashboard`}
            className="inline-block border border-graphite px-4 py-2 font-mono text-[12px] uppercase tracking-[0.08em] hover:bg-graphite hover:text-white"
          >
            View dashboard →
          </Link>
          <Link
            href={`/repos/scans/${scanId}/compliance`}
            className="inline-block border border-graphite px-4 py-2 font-mono text-[12px] uppercase tracking-[0.08em] hover:bg-graphite hover:text-white"
          >
            View compliance mapping →
          </Link>
        </div>
      )}

      <div className="mt-10">
        {SEV_ORDER.map((sev) => {
          const rows = grouped[sev] ?? [];
          if (rows.length === 0) return null;
          return (
            <div key={sev} className="mb-10">
              <h2 className="font-display text-[20px] text-ink mb-3 flex items-center gap-3">
                <span
                  className={`inline-flex items-center rounded-sm border border-hairline px-2 py-0.5 font-body text-[10px] font-medium uppercase tracking-[0.16em] ${SEV_CLASS[sev]}`}
                >
                  {sev}
                </span>
                <span>{rows.length} findings</span>
              </h2>
              <div className="bg-paper border border-hairline rounded-md shadow-subtle divide-y divide-hairline">
                {rows.map((f) => (
                  <FindingRow key={f.id} f={f} />
                ))}
              </div>
            </div>
          );
        })}
        {findings.length === 0 && scan.status === "succeeded" && (
          <p className="text-[14px] text-slate">No findings — nice work.</p>
        )}
        {findings.length === 0 &&
          (scan.status === "queued" || scan.status === "running") && (
            <p className="text-[14px] text-slate">
              Scan is still running — findings will appear here.
            </p>
          )}
      </div>
    </div>
  );
}

function FindingRow({ f }: { f: Finding }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="p-5">
      <button
        className="w-full text-left flex items-start justify-between gap-6"
        onClick={() => setOpen((v) => !v)}
      >
        <div>
          <div className="font-medium text-ink">{f.title}</div>
          <div className="mt-1 text-[12px] text-slate font-mono">
            {f.scanner} {f.rule_id ? `· ${f.rule_id}` : ""}
            {f.file_path
              ? ` · ${f.file_path}${f.line_start ? `:${f.line_start}` : ""}`
              : ""}
            {f.cve ? ` · ${f.cve}` : ""}
            {f.package ? ` · ${f.package}@${f.installed_version}` : ""}
          </div>
        </div>
        <div className="text-[12px] text-slate">{open ? "−" : "+"}</div>
      </button>
      {open && (
        <div className="mt-4 text-[13px] text-graphite space-y-3">
          {f.description && (
            <p className="whitespace-pre-wrap">{f.description}</p>
          )}
          {f.code_snippet && (
            <pre className="bg-vellum border border-hairline rounded-sm p-3 text-[12px] overflow-x-auto">
              <code>{f.code_snippet}</code>
            </pre>
          )}
          {f.fixed_version && (
            <p>
              Fixed in <span className="font-mono">{f.fixed_version}</span>.
            </p>
          )}
          {f.fix_pr_url ? (
            <p>
              <a
                className="text-ink hover:underline underline-offset-[6px] decoration-gilt decoration-1"
                href={f.fix_pr_url}
                target="_blank"
                rel="noreferrer"
              >
                View fix PR ↗
              </a>
            </p>
          ) : (
            <p className="text-slate">
              AI fix suggestion — coming in the next release.
            </p>
          )}
        </div>
      )}
    </div>
  );
}

function ScannerChip({
  name,
  active,
  onClick,
}: {
  name: string;
  active: boolean;
  onClick: () => void;
}) {
  return (
    <button
      onClick={onClick}
      className={
        "inline-flex items-center rounded-sm border px-3 py-1 font-body text-[12px] font-medium tracking-[0.05em] " +
        (active
          ? "border-ink bg-ink text-paper"
          : "border-hairline bg-paper text-graphite hover:text-ink")
      }
    >
      {name}
    </button>
  );
}

function fmtDate(iso: string): string {
  try {
    return new Date(iso).toLocaleString(undefined, {
      dateStyle: "medium",
      timeStyle: "short",
    });
  } catch {
    return iso;
  }
}
