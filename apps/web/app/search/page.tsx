"use client";

import Link from "next/link";
import { useSearchParams } from "next/navigation";
//import { useEffect, useMemo, useState } from "react";
//import { Suspense, useEffect, useState } from "react";
import { Suspense, useEffect, useMemo, useState } from "react";
import { PageLoading } from "@/components/loading";
import { api } from "@/lib/api";

type Target = { id: string; name: string; base_url: string; kind?: string | null };
type Repo = { id: string; full_name: string; html_url: string };
type Scan = { id: string; target_id: string; target_name: string; created_at: string; status: string };
type Finding = { id: string; title: string; severity: string; source: string; resource_url: string | null };

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="space-y-3">
      <div className="flex items-end justify-between gap-6">
        <h2 className="font-display text-[20px] text-ink">{title}</h2>
      </div>
      {children}
    </section>
  );
}

function List({ children }: { children: React.ReactNode }) {
  return (
    <div className="bg-paper border border-hairline rounded-md shadow-subtle overflow-hidden">
      <ul className="divide-y divide-hairline">{children}</ul>
    </div>
  );
}

function Row({
  title,
  meta,
  href,
}: {
  title: string;
  meta?: string;
  href: string;
}) {
  return (
    <li className="px-4 py-3">
      <Link
        href={href}
        className="block hover:bg-vellum/70 -mx-4 px-4 py-3"
      >
        <div className="flex items-start justify-between gap-6">
          <div className="min-w-0">
            <div className="font-body text-[14px] text-ink truncate">{title}</div>
            {meta && <div className="text-[12px] text-slate mt-1 truncate">{meta}</div>}
          </div>
          <span className="text-[12px] text-mist shrink-0">↗</span>
        </div>
      </Link>
    </li>
  );
}

//export default function SearchPage() {
function SearchPageContent() {
  const params = useSearchParams();
  const q = (params.get("q") ?? "").trim();

  const [loading, setLoading] = useState(false);
  const [targets, setTargets] = useState<Target[]>([]);
  const [repos, setRepos] = useState<Repo[]>([]);
  const [scans, setScans] = useState<Scan[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);

  useEffect(() => {
    if (!q) return;
    let cancelled = false;
    setLoading(true);
    Promise.all([
      api<Target[]>("/targets").catch(() => [] as Target[]),
      api<Repo[]>("/repos").catch(() => [] as Repo[]),
      api<Scan[]>("/scans").catch(() => [] as Scan[]),
      api<{ items: Finding[] }>("/unified-findings?limit=50").then((r) => r.items).catch(() => [] as Finding[]),
    ])
      .then(([t, r, s, f]) => {
        if (cancelled) return;
        setTargets(t);
        setRepos(r);
        setScans(s);
        setFindings(f);
      })
      .finally(() => !cancelled && setLoading(false));
    return () => {
      cancelled = true;
    };
  }, [q]);

  const needle = q.toLowerCase();
  const targetMatches = useMemo(() => {
    if (!q) return [];
    return targets
      .filter((t) => (t.name ?? "").toLowerCase().includes(needle) || (t.base_url ?? "").toLowerCase().includes(needle))
      .slice(0, 10);
  }, [targets, needle, q]);
  const repoMatches = useMemo(() => {
    if (!q) return [];
    return repos
      .filter((r) => (r.full_name ?? "").toLowerCase().includes(needle))
      .slice(0, 10);
  }, [repos, needle, q]);
  const scanMatches = useMemo(() => {
    if (!q) return [];
    return scans
      .filter((s) => (s.target_name ?? "").toLowerCase().includes(needle) || (s.id ?? "").toLowerCase().includes(needle))
      .slice(0, 10);
  }, [scans, needle, q]);
  const findingMatches = useMemo(() => {
    if (!q) return [];
    return findings
      .filter((f) => (f.title ?? "").toLowerCase().includes(needle))
      .slice(0, 10);
  }, [findings, needle, q]);

  if (!q) {
    return (
      <div className="space-y-6">
        <header>
          <p className="eyebrow-gilt">Search</p>
          <h1 className="mt-3 font-display text-[32px] md:text-[40px] leading-[1.05] tracking-[-0.015em] text-ink">
            Search
          </h1>
          <p className="mt-3 text-[14px] text-slate">
            Type a query in the top bar and press Enter.
          </p>
        </header>
      </div>
    );
  }

  if (loading && targets.length === 0 && repos.length === 0 && scans.length === 0 && findings.length === 0) {
    return <PageLoading title={`Search: ${q}`} cards={6} />;
  }

  return (
    <div className="space-y-8">
      <header className="flex items-end justify-between flex-wrap gap-6">
        <div>
          <p className="eyebrow-gilt">Search</p>
          <h1 className="mt-3 font-display text-[32px] md:text-[40px] leading-[1.05] tracking-[-0.015em] text-ink">
            {q}
          </h1>
        </div>
        <div className="font-mono text-[12px] text-mist">
          {targetMatches.length + repoMatches.length + scanMatches.length + findingMatches.length} results shown
        </div>
      </header>

      <div className="grid lg:grid-cols-2 gap-6">
        <Section title="Targets">
          {targetMatches.length === 0 ? (
            <p className="text-[13px] text-slate italic">No matching targets.</p>
          ) : (
            <List>
              {targetMatches.map((t) => (
                <Row key={t.id} title={t.name} meta={t.base_url} href={`/targets/${t.id}`} />
              ))}
            </List>
          )}
        </Section>

        <Section title="Repositories">
          {repoMatches.length === 0 ? (
            <p className="text-[13px] text-slate italic">No matching repositories.</p>
          ) : (
            <List>
              {repoMatches.map((r) => (
                <Row key={r.id} title={r.full_name} meta={r.html_url} href={`/repos/${r.id}`} />
              ))}
            </List>
          )}
        </Section>

        <Section title="Assessments">
          {scanMatches.length === 0 ? (
            <p className="text-[13px] text-slate italic">No matching assessments.</p>
          ) : (
            <List>
              {scanMatches.map((s) => (
                <Row
                  key={s.id}
                  title={`${s.target_name}`}
                  meta={`${s.status} · ${new Date(s.created_at).toLocaleString()}`}
                  href={`/scans/${s.id}`}
                />
              ))}
            </List>
          )}
        </Section>

        <Section title="Findings">
          {findingMatches.length === 0 ? (
            <p className="text-[13px] text-slate italic">No matching findings.</p>
          ) : (
            <List>
              {findingMatches.map((f) => (
                <Row
                  key={f.id}
                  title={f.title}
                  meta={`${f.severity.toUpperCase()} · ${f.source}`}
                  href={`/findings/${f.id}`}
                />
              ))}
            </List>
          )}
        </Section>
      </div>
    </div>
  );
}
export default function SearchPage() {
  return (
    <Suspense fallback={null}>
      <SearchPageContent />
    </Suspense>
  );
}
