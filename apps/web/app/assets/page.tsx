"use client";

import { useEffect, useState } from "react";
import { Button, Input } from "@/components/brutal";
import { api } from "@/lib/api";

type Asset = {
  id: string;
  type: string;
  value: string;
  meta: Record<string, unknown> | null;
  first_seen: string;
  last_seen: string;
};

export default function AssetsPage() {
  const [assets, setAssets] = useState<Asset[]>([]);
  const [filter, setFilter] = useState<string>("");
  const [rootDomain, setRootDomain] = useState("");
  const [status, setStatus] = useState<string | null>(null);

  async function reload() {
    const q = filter ? `?asset_type=${filter}` : "";
    setAssets(await api<Asset[]>(`/assets${q}`));
  }
  useEffect(() => {
    reload();
  }, [filter]);

  async function discover() {
    if (!rootDomain) return;
    setStatus("Queueing discovery…");
    await api("/assets/discover", {
      method: "POST",
      json: { root_domain: rootDomain },
    });
    setStatus(
      "Discovery queued — assets will appear once enumeration completes."
    );
  }

  const types = Array.from(new Set(assets.map((a) => a.type)));

  return (
    <div>
      <div className="flex items-end justify-between mb-10 gap-6 flex-wrap">
        <div>
          <h1 className="font-display text-[40px] leading-[1.05] tracking-[-0.015em] text-ink">
            Attack Surface
          </h1>
          <p className="mt-3 text-[14px] text-slate max-w-[56ch]">
            Discovered assets across your organisation. Passive only —
            subdomains, certs, and exposed services enumerated via crt.sh and
            subfinder.
          </p>
        </div>
        <div className="flex gap-3 items-end">
          <div className="w-[260px]">
            <label className="block font-body font-medium text-[11px] text-slate uppercase tracking-[0.18em] mb-2">
              Root domain
            </label>
            <Input
              value={rootDomain}
              onChange={(e) => setRootDomain(e.target.value)}
              placeholder="example.com"
            />
          </div>
          <Button variant="pink" onClick={discover} disabled={!rootDomain}>
            Discover
          </Button>
        </div>
      </div>

      {status && (
        <div className="mb-6 bg-vellum border border-hairline rounded-md px-4 py-3 text-[14px] text-forest">
          {status}
        </div>
      )}

      {assets.length > 0 && (
        <div className="mb-5 flex gap-2 flex-wrap">
          <FilterChip
            active={filter === ""}
            onClick={() => setFilter("")}
          >
            All ({assets.length})
          </FilterChip>
          {types.map((t) => (
            <FilterChip
              key={t}
              active={filter === t}
              onClick={() => setFilter(t)}
            >
              {t} ({assets.filter((a) => a.type === t).length})
            </FilterChip>
          ))}
        </div>
      )}

      {assets.length === 0 ? (
        <div className="bg-vellum border border-hairline rounded-md p-10 text-center">
          <p className="font-display text-[22px] text-ink mb-2">
            No assets discovered yet
          </p>
          <p className="text-[14px] text-slate max-w-[48ch] mx-auto">
            Enter a root domain above and click <strong>Discover</strong> to
            enumerate the attack surface.
          </p>
        </div>
      ) : (
        <div className="bg-paper border border-hairline rounded-md shadow-subtle overflow-hidden">
          <table className="w-full">
            <thead className="bg-vellum border-b border-hairline">
              <tr>
                <Th>Type</Th>
                <Th>Value</Th>
                <Th>First seen</Th>
                <Th>Last seen</Th>
              </tr>
            </thead>
            <tbody>
              {assets.map((a) => (
                <tr key={a.id} className="border-b border-hairline last:border-0">
                  <Td>
                    <span className="inline-flex items-center gap-1 border border-hairline rounded-sm px-2 py-0.5 font-body text-[10px] font-medium uppercase tracking-[0.16em] text-slate bg-vellum">
                      {a.type}
                    </span>
                  </Td>
                  <Td className="font-mono text-[13px] text-ink break-all">
                    {a.value}
                  </Td>
                  <Td className="text-slate">{fmtDate(a.first_seen)}</Td>
                  <Td className="text-slate">{fmtDateTime(a.last_seen)}</Td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function FilterChip({
  active,
  onClick,
  children,
}: {
  active: boolean;
  onClick: () => void;
  children: React.ReactNode;
}) {
  return (
    <button
      onClick={onClick}
      className={
        "inline-flex items-center gap-1 border rounded-sm px-2.5 py-1 font-body text-[12px] font-medium tracking-[0.04em] transition-colors duration-150 " +
        (active
          ? "bg-ink text-paper border-ink"
          : "bg-paper text-graphite border-hairline hover:border-ink hover:text-ink")
      }
    >
      {children}
    </button>
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
    <td className={"px-4 py-3.5 text-[14px] text-graphite align-middle " + className}>
      {children}
    </td>
  );
}

function fmtDate(iso: string): string {
  try {
    return new Date(iso).toLocaleDateString();
  } catch {
    return iso;
  }
}
function fmtDateTime(iso: string): string {
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return iso;
  }
}
