"use client";

import { useState } from "react";
import { Button } from "@/components/brutal";

type AssetType = "subdomain" | "ip" | "cert" | "endpoint";

type Asset = {
  id: string;
  value: string;
  type: AssetType;
  firstSeen: string;
  lastSeen: string;
};

const MOCK_ASSETS: Asset[] = [
  { id: "1", value: "api.example.com",     type: "subdomain", firstSeen: "2026-04-01", lastSeen: "2026-05-07" },
  { id: "2", value: "staging.example.com", type: "subdomain", firstSeen: "2026-03-15", lastSeen: "2026-05-06" },
  { id: "3", value: "cdn.example.com",     type: "subdomain", firstSeen: "2026-02-20", lastSeen: "2026-05-07" },
  { id: "4", value: "192.0.2.10",          type: "ip",        firstSeen: "2026-04-10", lastSeen: "2026-05-05" },
  { id: "5", value: "*.example.com",       type: "cert",      firstSeen: "2026-01-01", lastSeen: "2026-05-07" },
  { id: "6", value: "admin.example.com",   type: "subdomain", firstSeen: "2026-05-06", lastSeen: "2026-05-07" },
];

const TYPE_LABEL: Record<AssetType, string> = {
  subdomain: "Subdomain",
  ip: "IP",
  cert: "Certificate",
  endpoint: "Endpoint",
};

const TYPE_COLOR: Record<AssetType, string> = {
  subdomain: "text-forest bg-vellum",
  ip: "text-slate bg-paper",
  cert: "text-graphite bg-paper",
  endpoint: "text-ink bg-paper",
};

export default function ASMPage() {
  const [running, setRunning] = useState(false);

  function runDiscovery() {
    setRunning(true);
    setTimeout(() => {
      setRunning(false);
      alert(
        "Discovery queued.\n\nIn a connected deployment, this triggers subfinder + crt.sh enumeration for registered root domains and refreshes the inventory."
      );
    }, 600);
  }

  const newLast24h = MOCK_ASSETS.filter((a) => a.firstSeen === "2026-05-06" || a.firstSeen === "2026-05-07").length;
  const expiringCerts = MOCK_ASSETS.filter((a) => a.type === "cert").length;

  return (
    <div className="space-y-8 md:space-y-10">
      {/* Header */}
      <header className="flex items-end justify-between flex-wrap gap-4 md:gap-6">
        <div>
          <p className="eyebrow-gilt">Attack Surface</p>
          <h1 className="mt-4 font-display text-[32px] md:text-[48px] leading-[1.05] tracking-[-0.015em] text-ink">
            Attack Surface Monitoring
          </h1>
          <p className="mt-3 text-[14px] text-slate max-w-[56ch]">
            Continuous passive enumeration of subdomains, IPs, certificates, and
            exposed endpoints for your registered root domains.
          </p>
        </div>
        <Button variant="pink" onClick={runDiscovery} disabled={running}>
          {running ? "Queuing…" : "Run discovery"}
        </Button>
      </header>

      {/* Metric cards */}
      <section className="grid grid-cols-1 sm:grid-cols-3 gap-5">
        <article className="bg-paper border border-hairline rounded-md shadow-subtle p-6">
          <p className="eyebrow">Inventory</p>
          <p className="mt-3 font-display text-[40px] text-ink leading-none">
            {MOCK_ASSETS.length}
          </p>
          <p className="mt-2 text-[13px] text-slate">Total assets</p>
        </article>
        <article className="bg-paper border border-hairline rounded-md shadow-subtle p-6">
          <p className="eyebrow">Delta</p>
          <p className="mt-3 font-display text-[40px] text-ink leading-none">
            {newLast24h}
          </p>
          <p className="mt-2 text-[13px] text-slate">New subdomains (last 24 h)</p>
        </article>
        <article className="bg-paper border border-hairline rounded-md shadow-subtle p-6">
          <p className="eyebrow">Certs</p>
          <p className="mt-3 font-display text-[40px] text-gilt leading-none">
            {expiringCerts}
          </p>
          <p className="mt-2 text-[13px] text-slate">Expiring certs (next 30 days)</p>
        </article>
      </section>

      {/* Asset table */}
      <section>
        <div className="flex items-end justify-between mb-6">
          <div>
            <p className="eyebrow">Inventory — Assets</p>
            <h2 className="mt-2 font-display text-[24px] text-ink">
              Discovered assets
            </h2>
          </div>
          <span className="font-mono text-[12px] text-mist">
            {MOCK_ASSETS.length} on record
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-hairline">
                <th className="pb-3 pr-6 font-body text-[11px] font-medium uppercase tracking-[0.16em] text-slate">
                  Asset
                </th>
                <th className="pb-3 pr-6 font-body text-[11px] font-medium uppercase tracking-[0.16em] text-slate">
                  Type
                </th>
                <th className="pb-3 pr-6 font-body text-[11px] font-medium uppercase tracking-[0.16em] text-slate">
                  First seen
                </th>
                <th className="pb-3 font-body text-[11px] font-medium uppercase tracking-[0.16em] text-slate">
                  Last seen
                </th>
              </tr>
            </thead>
            <tbody>
              {MOCK_ASSETS.map((asset) => (
                <tr
                  key={asset.id}
                  className="border-b border-hairline hover:bg-vellum transition-colors duration-100"
                >
                  <td className="py-3 pr-6 font-mono text-[13px] text-ink">
                    {asset.value}
                  </td>
                  <td className="py-3 pr-6">
                    <span
                      className={`inline-flex items-center border border-hairline rounded-sm px-2 py-0.5 font-body text-[10px] font-medium uppercase tracking-[0.16em] whitespace-nowrap ${TYPE_COLOR[asset.type]}`}
                    >
                      {TYPE_LABEL[asset.type]}
                    </span>
                  </td>
                  <td className="py-3 pr-6 font-mono text-[12px] text-slate">
                    {asset.firstSeen}
                  </td>
                  <td className="py-3 font-mono text-[12px] text-slate">
                    {asset.lastSeen}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
