"use client";

import { useEffect, useState } from "react";
import { usePathname } from "next/navigation";
import { pathSegment } from "@/lib/route-params";
import { Button } from "@/components/brutal";
import { api } from "@/lib/api";

type Sbom = {
  id: string;
  format: string;
  component_count: number | null;
  created_at: string;
};

type SbomDetail = Sbom & { content: Record<string, unknown> };

export default function SbomPage() {
  const pathname = usePathname();
  const [mounted, setMounted] = useState(false);
  useEffect(() => setMounted(true), []);
  const scanId = mounted ? pathSegment(pathname, 2) : "";
  const [list, setList] = useState<Sbom[]>([]);
  const [detail, setDetail] = useState<SbomDetail | null>(null);

  useEffect(() => {
    if (!scanId) return;
    api<Sbom[]>(`/sboms/${scanId}`).then(setList);
  }, [scanId]);

  async function load(id: string) {
    setDetail(await api<SbomDetail>(`/sboms/${scanId}/${id}`));
  }

  function download() {
    if (!detail) return;
    const blob = new Blob([JSON.stringify(detail.content, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${detail.format}-${detail.id}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }

  return (
    <div>
      <h1 className="font-display text-[40px] leading-[1.05] tracking-[-0.015em] text-ink">
        SBOM
      </h1>
      <p className="mt-3 mb-8 text-[14px] text-slate max-w-[60ch]">
        Software Bill of Materials for scan{" "}
        <code className="font-mono text-[13px] bg-vellum px-1 py-0.5 rounded-sm">
          {scanId}
        </code>
        . Export as CycloneDX 1.5 or SPDX 2.3 for downstream tooling.
      </p>

      {list.length === 0 ? (
        <div className="bg-vellum border border-hairline rounded-md p-10 text-center">
          <p className="font-display text-[22px] text-ink mb-2">
            No SBOMs generated for this scan
          </p>
          <p className="text-[14px] text-slate max-w-[52ch] mx-auto">
            Run a scan with the{" "}
            <code className="font-mono text-[13px] bg-paper px-1 py-0.5 rounded-sm">
              supply-chain
            </code>{" "}
            or{" "}
            <code className="font-mono text-[13px] bg-paper px-1 py-0.5 rounded-sm">
              compliance-full
            </code>{" "}
            profile to produce CycloneDX and SPDX documents automatically.
          </p>
        </div>
      ) : (
        <div className="grid md:grid-cols-[260px,1fr] gap-6">
          <ul className="space-y-3">
            {list.map((s) => {
              const active = detail?.id === s.id;
              return (
                <li key={s.id}>
                  <button
                    onClick={() => load(s.id)}
                    className={
                      "w-full text-left bg-paper border rounded-md shadow-subtle p-4 transition-colors duration-150 " +
                      (active
                        ? "border-ink"
                        : "border-hairline hover:border-ink")
                    }
                  >
                    <div className="font-body text-[10px] font-medium uppercase tracking-[0.16em] text-slate mb-1">
                      {s.format}
                    </div>
                    <div className="font-display text-[18px] text-ink">
                      {s.component_count ?? "?"} components
                    </div>
                    <div className="text-[12px] text-slate mt-1">
                      {new Date(s.created_at).toLocaleString()}
                    </div>
                  </button>
                </li>
              );
            })}
          </ul>
          <div>
            {detail ? (
              <div className="bg-paper border border-hairline rounded-md shadow-subtle overflow-hidden">
                <div className="bg-vellum border-b border-hairline px-4 py-2.5 flex items-center justify-between">
                  <span className="font-body text-[11px] font-medium uppercase tracking-[0.16em] text-slate">
                    {detail.format} · {detail.component_count} components
                  </span>
                  <Button
                    variant="yellow"
                    onClick={download}
                    className="!py-1.5 !text-[12px]"
                  >
                    Download JSON
                  </Button>
                </div>
                <pre className="font-mono text-[12px] text-graphite p-5 overflow-auto max-h-[600px] leading-[1.55]">
                  {JSON.stringify(detail.content, null, 2)}
                </pre>
              </div>
            ) : (
              <div className="bg-vellum border border-hairline rounded-md p-10 text-center">
                <p className="text-[14px] text-slate">
                  Select an SBOM to view.
                </p>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
