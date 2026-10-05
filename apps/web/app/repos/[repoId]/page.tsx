"use client";

import Link from "next/link";
import { usePathname, useSearchParams } from "next/navigation";
import { pathSegment } from "@/lib/route-params";
//import { useEffect, useMemo, useState } from "react";
import { Suspense, useEffect, useMemo, useState } from "react";
import { Button, Input } from "@/components/brutal";
import { InlineLoading } from "@/components/loading";
import { Paginator } from "@/components/paginator";
import { ApiError, api } from "@/lib/api";

const SCAN_HISTORY_PAGE_SIZE = 20;

type Repo = {
  id: string;
  full_name: string;
  default_branch: string;
  html_url: string;
  language: string | null;
  last_scan_id: string | null;
  last_scan_at: string | null;
  severity_counts: Record<string, number> | null;
};

type ScanRow = {
  id: string;
  commit_sha: string | null;
  trigger: string;
  status: string;
  started_at: string | null;
  completed_at: string | null;
  created_at: string;
  stats: Record<
    string,
    { count?: number; error?: string; skipped?: string }
  > | null;
};

type RepoSbom = {
  id: string;
  repository_id: string;
  commit_sha: string | null;
  format: string;
  component_count: number | null;
  content: any;
  created_at: string;
};

type SbomRow = {
  name: string;
  version: string;
  type: string;
  purl: string;
  license: string;
};

const SCANNER_NAMES = new Set([
  "codeql",
  "gitleaks",
  "ghsa",
  "yara",
  "trivy_iac",
  "checkov",
]);

function scannerStats(stats: ScanRow["stats"]) {
  return Object.entries(stats ?? {}).filter(([name]) =>
    SCANNER_NAMES.has(name),
  );
}

function formatScannerStat(
  name: string,
  value: { count?: number; error?: string; skipped?: string },
) {
  if (value.error) return `${name}:error`;
  if (value.skipped) return `${name}:skipped`;
  return `${name}:${value.count ?? 0}`;
}

function sbomLicense(c: any): string {
  const licenses = c?.licenses;
  if (Array.isArray(licenses) && licenses.length > 0) {
    const first = licenses[0];
    if (typeof first?.expression === "string" && first.expression)
      return first.expression;
    const lic = first?.license;
    if (typeof lic?.id === "string" && lic.id) return lic.id;
    if (typeof lic?.name === "string" && lic.name) return lic.name;
  }
  if (typeof c?.license === "string" && c.license) return c.license;
  return "—";
}

function extractSbomRows(sbom: RepoSbom | null): SbomRow[] {
  const content = sbom?.content;
  if (!content) return [];
  if (sbom?.format === "cyclonedx") {
    const components = Array.isArray(content.components)
      ? content.components
      : [];
    return components.map((c: any) => ({
      name: c?.name ?? "—",
      version: c?.version ?? "—",
      type: c?.type ?? "—",
      purl: c?.purl ?? "—",
      license: sbomLicense(c),
    }));
  }
  if (sbom?.format === "spdx") {
    const packages = Array.isArray(content.packages) ? content.packages : [];
    return packages.map((p: any) => {
      const refs = Array.isArray(p?.externalRefs) ? p.externalRefs : [];
      const purl = refs.find(
        (r: any) => (r?.referenceType ?? "").toLowerCase() === "purl",
      )?.referenceLocator;
      return {
        name: p?.name ?? "—",
        version: p?.versionInfo ?? "—",
        type: "package",
        purl: purl ?? "—",
        license: p?.licenseConcluded ?? p?.licenseDeclared ?? "—",
      };
    });
  }
  return [];
}

//export default function RepoDetailPage() {
function RepoDetailPageContent() {
  const pathname = usePathname();
  const [mounted, setMounted] = useState(false);
  useEffect(() => setMounted(true), []);
  const repoId = mounted ? pathSegment(pathname, 2) : "";
  const searchParams = useSearchParams();
  const [repo, setRepo] = useState<Repo | null>(null);
  const [scans, setScans] = useState<ScanRow[]>([]);
  const [busy, setBusy] = useState(false);
  const [sbomBusy, setSbomBusy] = useState(false);
  const [sbom, setSbom] = useState<RepoSbom | null>(null);
  const [sbomView, setSbomView] = useState<"table" | "json">("table");
  const [err, setErr] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const [page, setPage] = useState(1);

  const filteredScans = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return scans;
    return scans.filter(
      (s) =>
        (s.commit_sha ?? "").toLowerCase().includes(q) ||
        s.trigger.toLowerCase().includes(q) ||
        s.status.toLowerCase().includes(q) ||
        s.id.toLowerCase().includes(q),
    );
  }, [scans, query]);

  const pageCount = Math.max(
    1,
    Math.ceil(filteredScans.length / SCAN_HISTORY_PAGE_SIZE),
  );
  const safePage = Math.min(page, pageCount);
  const visibleScans = filteredScans.slice(
    (safePage - 1) * SCAN_HISTORY_PAGE_SIZE,
    safePage * SCAN_HISTORY_PAGE_SIZE,
  );
  useEffect(() => {
    if (page > pageCount) setPage(1);
  }, [pageCount, page]);

  async function reload() {
    try {
      const [r, s, b] = await Promise.all([
        api<Repo>(`/repos/${repoId}`),
        api<ScanRow[]>(`/repos/${repoId}/scans`),
        api<RepoSbom>(`/repos/${repoId}/sbom`).catch((e) => {
          if (e instanceof ApiError && e.status === 404) return null;
          return null;
        }),
      ]);
      setRepo(r);
      setScans(s);
      setSbom(b);
    } catch (e) {
      setErr((e as Error).message);
    }
  }

  useEffect(() => {
    if (!repoId) return;
    reload();
  }, [repoId]);

  // Light polling so users see the scan move queued → running → succeeded.
  useEffect(() => {
    const anyLive = scans.some(
      (s) => s.status === "queued" || s.status === "running",
    );
    if (!anyLive) return;
    const id = setInterval(reload, 4000);
    return () => clearInterval(id);
  }, [scans]);

  async function startScan() {
    setBusy(true);
    try {
      await api(`/repos/${repoId}/scan`, { method: "POST", json: {} });
      await reload();
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function deleteScan(scanId: string) {
    if (
      !window.confirm(
        "Delete this scan and all its findings? This cannot be undone.",
      )
    ) {
      return;
    }
    try {
      await api(`/repos/scans/${scanId}`, { method: "DELETE" });
      setScans((prev) => prev.filter((x) => x.id !== scanId));
    } catch (e: any) {
      alert(e?.message || "Unable to delete scan.");
    }
  }

  async function generateSbom() {
    setSbomBusy(true);
    try {
      const res = await api<RepoSbom>(`/repos/${repoId}/sbom`, {
        method: "POST",
        json: { format: "cyclonedx" },
      });
      setSbom(res);
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setSbomBusy(false);
    }
  }

  function downloadSbom() {
    if (!sbom) return;
    const base = (repo?.full_name ?? "repo").replace("/", "-");
    const ext = sbom.format === "spdx" ? "spdx.json" : "cdx.json";
    const name = `${base}${sbom.commit_sha ? `-${sbom.commit_sha.slice(0, 7)}` : ""}.${ext}`;
    const blob = new Blob([JSON.stringify(sbom.content ?? {}, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = name;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  }

  useEffect(() => {
    const wants = searchParams.get("sbom") === "1";
    if (!wants || !sbom) return;
    document.getElementById("repo-sbom")?.scrollIntoView({ block: "start" });
  }, [searchParams, sbom]);

  const sbomRows = useMemo(() => extractSbomRows(sbom), [sbom]);
  const sbomRowsLimited = sbomRows.slice(0, 500);

  if (!repo) {
    if (err) return <p className="text-[14px] text-oxblood">{err}</p>;
    return (
      <div className="py-6">
        <InlineLoading label="Loading…" />
      </div>
    );
  }

  return (
    <div>
      <div className="mb-4">
        <Link
          href="/dashboard"
          className="text-[13px] text-slate hover:text-ink underline underline-offset-[6px] decoration-gilt decoration-1"
        >
          ← Dashboard
        </Link>
      </div>

      <div className="flex items-start justify-between gap-6 flex-wrap mb-6">
        <div>
          <h1 className="font-display text-[36px] leading-[1.05] tracking-[-0.015em] text-ink">
            {repo.full_name}
          </h1>
          <div className="mt-3 flex items-center gap-3 text-[13px] text-slate">
            <span>default: {repo.default_branch}</span>
            {repo.language && <span>· {repo.language}</span>}
            <a
              href={repo.html_url}
              target="_blank"
              rel="noreferrer"
              className="text-graphite hover:text-ink underline underline-offset-[6px] decoration-gilt decoration-1"
            >
              View on GitHub ↗
            </a>
          </div>
        </div>
        <div className="flex items-center gap-3">
          <Button variant="ink" onClick={generateSbom} disabled={sbomBusy}>
            {sbomBusy ? "Generating…" : "Generate SBOM"}
          </Button>
          <Button variant="pink" onClick={startScan} disabled={busy}>
            {busy ? "Queuing…" : "Run scan"}
          </Button>
        </div>
      </div>

      <div id="repo-sbom" className="mb-6">
        <div className="flex items-end justify-between gap-4 flex-wrap mb-3">
          <h2 className="font-display text-[22px] text-ink">SBOM</h2>
          {sbom && (
            <div className="flex items-center gap-2">
              <div className="inline-flex border border-hairline rounded-sm overflow-hidden bg-vellum">
                <button
                  type="button"
                  className={
                    "px-3 py-1.5 text-[12px] font-medium " +
                    (sbomView === "table"
                      ? "bg-ink text-paper"
                      : "text-graphite hover:bg-paper")
                  }
                  onClick={() => setSbomView("table")}
                >
                  Table
                </button>
                <button
                  type="button"
                  className={
                    "px-3 py-1.5 text-[12px] font-medium border-l border-hairline " +
                    (sbomView === "json"
                      ? "bg-ink text-paper"
                      : "text-graphite hover:bg-paper")
                  }
                  onClick={() => setSbomView("json")}
                >
                  JSON
                </button>
              </div>
              <Button variant="cyan" onClick={downloadSbom}>
                Download
              </Button>
            </div>
          )}
        </div>
        <div className="bg-paper border border-hairline rounded-md shadow-subtle overflow-hidden">
          {!sbom ? (
            <div className="px-4 py-6 text-[14px] text-slate italic">
              No SBOM generated yet.
            </div>
          ) : (
            <>
              <div className="px-4 py-3 border-b border-hairline flex flex-wrap items-center justify-between gap-3">
                <div className="flex items-center gap-3 text-[12px] text-mist font-mono">
                  <span>format:{sbom.format}</span>
                  {sbom.commit_sha && (
                    <span>sha:{sbom.commit_sha.slice(0, 7)}</span>
                  )}
                  {typeof sbom.component_count === "number" && (
                    <span>components:{sbom.component_count}</span>
                  )}
                  <span>
                    generated:{new Date(sbom.created_at).toLocaleString()}
                  </span>
                </div>
                {sbomView === "table" && (
                  <div className="font-mono text-[12px] text-mist">
                    showing:{sbomRowsLimited.length}
                    {sbomRows.length > sbomRowsLimited.length
                      ? ` of ${sbomRows.length}`
                      : ""}
                  </div>
                )}
              </div>
              {sbomView === "json" ? (
                <pre className="p-4 text-[11px] leading-[1.45] overflow-x-auto max-h-[520px] overflow-y-auto bg-vellum/50">
                  {JSON.stringify(sbom.content ?? {}, null, 2)}
                </pre>
              ) : sbomRowsLimited.length === 0 ? (
                <div className="px-4 py-6 text-[14px] text-slate italic">
                  No components found in this SBOM.
                </div>
              ) : (
                <div className="overflow-x-auto max-h-[520px] overflow-y-auto bg-vellum/50">
                  <table className="w-full">
                    <thead className="bg-vellum border-b border-hairline">
                      <tr>
                        <Th>Name</Th>
                        <Th>Version</Th>
                        <Th>Type</Th>
                        <Th>License</Th>
                        <Th>PURL</Th>
                      </tr>
                    </thead>
                    <tbody>
                      {sbomRowsLimited.map((r, idx) => (
                        <tr
                          key={`${r.name}-${r.version}-${idx}`}
                          className="border-b border-hairline last:border-0"
                        >
                          <Td className="font-body text-[13px] text-ink">
                            {r.name}
                          </Td>
                          <Td className="font-mono text-[12px]">{r.version}</Td>
                          <Td className="font-mono text-[12px]">{r.type}</Td>
                          <Td className="font-mono text-[12px]">{r.license}</Td>
                          <Td className="font-mono text-[12px]">
                            <span className="block max-w-[560px] truncate">
                              {r.purl}
                            </span>
                          </Td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </>
          )}
        </div>
      </div>

      <div className="flex items-end justify-between gap-4 flex-wrap mb-4">
        <h2 className="font-display text-[22px] text-ink">Scan history</h2>
        <div className="flex items-center gap-3">
          {scans.length >= 2 && (
            <Link
              href={`/repos/${repoId}/dashboard`}
              className="inline-block border border-graphite px-3 py-1.5 font-mono text-[11px] uppercase tracking-[0.08em] hover:bg-graphite hover:text-white"
            >
              View dashboard →
            </Link>
          )}
          <span className="font-mono text-[12px] text-mist">
            {filteredScans.length}
            {query ? ` matching · ${scans.length} total` : " on record"}
          </span>
        </div>
      </div>

      {scans.length > 0 && (
        <div className="flex items-center justify-between gap-4 flex-wrap mb-4">
          <div className="w-full sm:w-[420px] max-w-full">
            <Input
              type="search"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search by commit, trigger, or status…"
              aria-label="Search scan history"
            />
          </div>
          <Paginator page={safePage} pageCount={pageCount} onChange={setPage} />
        </div>
      )}

      <div className="bg-paper border border-hairline rounded-md shadow-subtle overflow-hidden">
        <table className="w-full">
          <thead className="bg-vellum border-b border-hairline">
            <tr>
              <Th>Started</Th>
              <Th>Trigger</Th>
              <Th>Commit</Th>
              <Th>Status</Th>
              <Th>Scanner counts</Th>
              <Th className="text-right">Actions</Th>
            </tr>
          </thead>
          <tbody>
            {scans.length === 0 ? (
              <tr>
                <td
                  colSpan={6}
                  className="px-4 py-10 text-center text-[14px] text-slate"
                >
                  No scans yet. Click <b>Run scan</b> to start one.
                </td>
              </tr>
            ) : filteredScans.length === 0 ? (
              <tr>
                <td
                  colSpan={6}
                  className="px-4 py-10 text-center text-[14px] text-slate italic"
                >
                  No scans match “{query}”.
                </td>
              </tr>
            ) : (
              visibleScans.map((s) => (
                <tr
                  key={s.id}
                  className="border-b border-hairline last:border-0"
                >
                  <Td>{fmtDate(s.started_at ?? s.created_at)}</Td>
                  <Td>
                    <span className="inline-flex items-center gap-1 border border-hairline rounded-sm px-2 py-0.5 font-body text-[10px] font-medium uppercase tracking-[0.16em] text-slate bg-vellum">
                      {s.trigger}
                    </span>
                  </Td>
                  <Td className="font-mono text-[12px]">
                    {s.commit_sha ? s.commit_sha.slice(0, 7) : "—"}
                  </Td>
                  <Td>
                    <StatusBadge status={s.status} />
                  </Td>
                  <Td className="font-mono text-[12px]">
                    {s.stats
                      ? scannerStats(s.stats)
                          .map(([k, v]) => formatScannerStat(k, v))
                          .join(" · ")
                      : "—"}
                  </Td>
                  <Td className="text-right">
                    <div className="inline-flex items-center gap-3">
                      <Link
                        href={`/repos/scans/${s.id}`}
                        className="font-body text-[13px] text-graphite hover:text-ink underline underline-offset-[6px] decoration-gilt decoration-1"
                      >
                        View findings
                      </Link>
                      <Button
                        variant="danger"
                        className="text-[12px] px-3 py-1.5"
                        onClick={() => deleteScan(s.id)}
                      >
                        Delete
                      </Button>
                    </div>
                  </Td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function StatusBadge({ status }: { status: string }) {
  const cls =
    status === "succeeded"
      ? "text-forest"
      : status === "failed"
        ? "text-oxblood"
        : status === "running"
          ? "text-ink"
          : "text-slate";
  return (
    <span
      className={`inline-flex items-center gap-1 border border-hairline rounded-sm px-2 py-0.5 font-body text-[10px] font-medium uppercase tracking-[0.16em] bg-vellum ${cls}`}
    >
      {status}
    </span>
  );
}

function Th({
  children,
  className = "",
}: {
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <th
      className={
        "text-left px-4 py-3 font-body text-[11px] font-medium uppercase tracking-[0.16em] text-slate " +
        className
      }
    >
      {children}
    </th>
  );
}

function Td({
  children,
  className = "",
}: {
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <td
      className={
        "px-4 py-3.5 text-[14px] text-graphite align-middle " + className
      }
    >
      {children}
    </td>
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

export default function RepoDetailPage() {
  return (
    <Suspense fallback={<InlineLoading />}>
      <RepoDetailPageContent />
    </Suspense>
  );
}
