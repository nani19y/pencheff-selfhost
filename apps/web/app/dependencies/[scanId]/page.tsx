"use client";

import { useEffect, useState } from "react";
import { usePathname } from "next/navigation";
import { pathSegment } from "@/lib/route-params";
import { api } from "@/lib/api";

type Dep = {
  id: string;
  ecosystem: string;
  name: string;
  version: string;
  license: string | null;
  scope: string;
  vulnerabilities: Array<{
    id: string;
    severity: string;
    summary?: string;
  }> | null;
};

export default function DepsPage() {
  const pathname = usePathname();
  const [mounted, setMounted] = useState(false);
  useEffect(() => setMounted(true), []);
  const scanId = mounted ? pathSegment(pathname, 2) : "";
  const [deps, setDeps] = useState<Dep[]>([]);
  const [vulnerableOnly, setVulnerableOnly] = useState(false);

  useEffect(() => {
    if (!scanId) return;
    const q = vulnerableOnly ? "?vulnerable_only=true" : "";
    api<Dep[]>(`/dependencies/${scanId}${q}`).then(setDeps);
  }, [scanId, vulnerableOnly]);

  const vulnCount = deps.filter(
    (d) => d.vulnerabilities && d.vulnerabilities.length > 0,
  ).length;

  return (
    <div>
      <div className="flex items-end justify-between mb-8 gap-6 flex-wrap">
        <div>
          <h1 className="font-display text-[40px] leading-[1.05] tracking-[-0.015em] text-ink">
            Dependencies
          </h1>
          <p className="mt-3 text-[14px] text-slate max-w-[60ch]">
            Software Composition Analysis for scan{" "}
            <code className="font-mono text-[13px] bg-vellum px-1 py-0.5 rounded-sm">
              {scanId}
            </code>
            . {deps.length} total · {vulnCount} with known vulnerabilities.
          </p>
        </div>
        <label className="inline-flex items-center gap-2 cursor-pointer select-none">
          <input
            type="checkbox"
            checked={vulnerableOnly}
            onChange={(e) => setVulnerableOnly(e.target.checked)}
            className="w-4 h-4 accent-ink"
          />
          <span className="font-body text-[13px] text-graphite">
            Vulnerable only
          </span>
        </label>
      </div>

      {deps.length === 0 ? (
        <div className="bg-vellum border border-hairline rounded-md p-10 text-center">
          <p className="font-display text-[22px] text-ink mb-2">
            No dependencies captured
          </p>
          <p className="text-[14px] text-slate max-w-[52ch] mx-auto">
            Run a scan that includes{" "}
            <code className="font-mono text-[13px] bg-paper px-1 py-0.5 rounded-sm">
              scan_dependencies
            </code>{" "}
            (e.g. the{" "}
            <code className="font-mono text-[13px] bg-paper px-1 py-0.5 rounded-sm">
              supply-chain
            </code>{" "}
            profile) to populate this table.
          </p>
        </div>
      ) : (
        <div className="bg-paper border border-hairline rounded-md shadow-subtle overflow-hidden">
          <table className="w-full">
            <thead className="bg-vellum border-b border-hairline">
              <tr>
                <Th>Ecosystem</Th>
                <Th>Name</Th>
                <Th>Version</Th>
                <Th>License</Th>
                <Th>Scope</Th>
                <Th>Vulnerabilities</Th>
              </tr>
            </thead>
            <tbody>
              {deps.map((d) => (
                <tr
                  key={d.id}
                  className="border-b border-hairline last:border-0"
                >
                  <Td>
                    <span className="inline-flex items-center gap-1 border border-hairline rounded-sm px-2 py-0.5 font-body text-[10px] font-medium uppercase tracking-[0.16em] text-slate bg-vellum">
                      {d.ecosystem}
                    </span>
                  </Td>
                  <Td className="font-medium text-ink">{d.name}</Td>
                  <Td className="font-mono text-[13px]">{d.version}</Td>
                  <Td>
                    {d.license ? (
                      <span className="font-mono text-[12px] text-graphite">
                        {d.license}
                      </span>
                    ) : (
                      <span className="text-slate">—</span>
                    )}
                  </Td>
                  <Td className="text-slate">{d.scope}</Td>
                  <Td>
                    {d.vulnerabilities && d.vulnerabilities.length > 0 ? (
                      <span className="inline-flex items-center gap-1 font-body text-[13px] text-oxblood">
                        <span className="inline-block w-1.5 h-1.5 rounded-full bg-sev-high" />
                        {d.vulnerabilities.length} ·{" "}
                        <span className="font-mono text-[12px]">
                          {d.vulnerabilities
                            .slice(0, 2)
                            .map((v) => v.id)
                            .join(", ")}
                          {d.vulnerabilities.length > 2 ? "…" : ""}
                        </span>
                      </span>
                    ) : (
                      <span className="text-slate">—</span>
                    )}
                  </Td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function Th({ children }: { children: React.ReactNode }) {
  return (
    <th className="text-left px-4 py-3 font-body text-[11px] font-medium uppercase tracking-[0.16em] text-slate">
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
