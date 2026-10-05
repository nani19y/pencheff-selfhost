"use client";

import { useEffect, useState } from "react";
import { usePathname } from "next/navigation";
import { pathSegment } from "@/lib/route-params";
import { Badge, Button, Card, Input, Label } from "@/components/brutal";
import { Markdown } from "@/components/markdown";
import { api } from "@/lib/api";

type StrideRow = {
  asset: string;
  category: string;
  threats: string[];
  mitigations: string[];
};

type DreadRow = {
  asset: string;
  category: string;
  threat: string;
  damage: number;
  reproducibility: number;
  exploitability: number;
  affected_users: number;
  discoverability: number;
  score: number;
  priority: "critical" | "high" | "medium" | "low";
  mitigations: string[];
};

type ThreatModel = {
  method: "STRIDE" | "DREAD";
  generated_at: string;
  method_summary: string;
  assets: { name: string; type: string }[];
  table?: StrideRow[];
  threats?: DreadRow[];
  category_scores?: Record<string, number>;
};

type ThreatModelOut = {
  threat_model: ThreatModel | null;
  threat_model_updated_at: string | null;
  markdown: string | null;
  module_priority_bias: string[];
};

const PRIORITY_RANK: Record<DreadRow["priority"], number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
};

export default function ThreatModelPage() {
  const pathname = usePathname();
  const [mounted, setMounted] = useState(false);
  useEffect(() => setMounted(true), []);
  const engagementId = mounted ? pathSegment(pathname, 2) : "";

  const [data, setData] = useState<ThreatModelOut | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [view, setView] = useState<"table" | "markdown" | "json">("table");

  // Generate-form state
  const [method, setMethod] = useState<"stride" | "dread">("stride");
  const [targetUrl, setTargetUrl] = useState("");
  const [assetTypesText, setAssetTypesText] = useState("");

  useEffect(() => {
    if (!engagementId) return;
    refresh();
  }, [engagementId]);

  async function refresh() {
    setLoading(true);
    setError(null);
    try {
      const out = await api<ThreatModelOut>(
        `/engagements/${engagementId}/threat-model`,
      );
      setData(out);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }

  async function generate() {
    setBusy(true);
    setError(null);
    try {
      const asset_types = assetTypesText
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean);
      const out = await api<ThreatModelOut>(
        `/engagements/${engagementId}/threat-model`,
        {
          method: "POST",
          json: {
            method,
            target_url: targetUrl || null,
            asset_types: asset_types.length ? asset_types : null,
          },
        },
      );
      setData(out);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  async function clearModel() {
    if (
      !confirm("Remove this threat model? Adaptive scan biasing will stop.")
    ) {
      return;
    }
    setBusy(true);
    setError(null);
    try {
      await api(`/engagements/${engagementId}/threat-model`, {
        method: "DELETE",
      });
      await refresh();
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="container mx-auto p-6 max-w-5xl">
      <div className="mb-6">
        <h1 className="text-3xl font-black">Threat model</h1>
        <p className="text-sm text-zinc-600 mt-1">
          Engagement-scoped STRIDE / DREAD model. When set, Pencheff biases scan
          module ordering toward the highest-scoring categories so the most
          impactful tests fire first.
        </p>
      </div>

      {error ? (
        <Card className="p-4 mb-4 bg-red-50 border-red-300">
          <p className="text-sm font-mono text-red-900">{error}</p>
        </Card>
      ) : null}

      {/* ── Generate form ─────────────────────────────────────────── */}
      <Card className="p-5 mb-6">
        <p className="eyebrow-gilt mb-3 text-[10px]">Generate</p>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3 mb-3">
          <div>
            <Label>Method</Label>
            <select
              className="w-full border-2 border-zinc-900 px-3 py-2 font-mono text-sm"
              value={method}
              onChange={(e) => setMethod(e.target.value as "stride" | "dread")}
            >
              <option value="stride">STRIDE</option>
              <option value="dread">DREAD (per-threat scoring)</option>
            </select>
          </div>
          <div>
            <Label>Target URL (optional)</Label>
            <Input
              value={targetUrl}
              onChange={(e) => setTargetUrl(e.target.value)}
              placeholder="https://api.example.com"
            />
          </div>
          <div>
            <Label>Asset types (comma)</Label>
            <Input
              value={assetTypesText}
              onChange={(e) => setAssetTypesText(e.target.value)}
              placeholder="webapp, api, cloud"
            />
          </div>
        </div>
        <div className="flex gap-2">
          <Button onClick={generate} disabled={busy}>
            {busy
              ? "Generating…"
              : data?.threat_model
                ? "Regenerate"
                : "Generate"}
          </Button>
          {data?.threat_model ? (
            <Button variant="danger" onClick={clearModel} disabled={busy}>
              Clear
            </Button>
          ) : null}
        </div>
      </Card>

      {loading ? (
        <p className="text-sm text-zinc-500">Loading…</p>
      ) : !data?.threat_model ? (
        <Card className="p-6 text-center text-zinc-600">
          No threat model attached to this engagement yet. Generate one above to
          bias scan module ordering and include it in the report.
        </Card>
      ) : (
        <>
          {/* Method & timestamp */}
          <div className="flex items-baseline justify-between mb-4">
            <div className="flex items-baseline gap-3">
              <span className="font-bold text-xl">
                {data.threat_model.method}
              </span>
              <span className="text-xs text-zinc-500 font-mono">
                generated {data.threat_model_updated_at?.slice(0, 19)}
              </span>
            </div>
            <div className="flex gap-1">
              {(["table", "markdown", "json"] as const).map((v) => (
                <button
                  key={v}
                  type="button"
                  className={
                    "px-3 py-1 text-xs border " +
                    (view === v
                      ? "border-zinc-900 bg-zinc-900 text-white"
                      : "border-zinc-300 hover:bg-zinc-100")
                  }
                  onClick={() => setView(v)}
                >
                  {v}
                </button>
              ))}
            </div>
          </div>

          {/* Adaptive scan bias */}
          {data.module_priority_bias.length > 0 ? (
            <Card className="p-4 mb-4">
              <p className="eyebrow-gilt mb-2 text-[10px]">
                Adaptive scan: module priority order
              </p>
              <p className="text-xs text-zinc-600 mb-2">
                When a scan is started against this engagement, Pencheff runs
                the modules in this order so the highest-impact threats are
                tested first.
              </p>
              <div className="flex flex-wrap gap-1">
                {data.module_priority_bias.map((m, i) => (
                  <code
                    key={m}
                    className="text-xs bg-zinc-100 px-2 py-1 rounded font-mono"
                    title={`rank ${i + 1}`}
                  >
                    {i + 1}. {m}
                  </code>
                ))}
              </div>
            </Card>
          ) : null}

          {/* Body — switchable view */}
          {view === "json" ? (
            <Card className="p-4">
              <pre className="text-xs font-mono whitespace-pre-wrap overflow-x-auto">
                {JSON.stringify(data.threat_model, null, 2)}
              </pre>
            </Card>
          ) : view === "markdown" ? (
            <Card className="p-6">
              <Markdown>{data.markdown ?? ""}</Markdown>
            </Card>
          ) : (
            <ThreatModelTable model={data.threat_model} />
          )}
        </>
      )}
    </div>
  );
}

function ThreatModelTable({ model }: { model: ThreatModel }) {
  if (model.method === "DREAD") {
    const ranked = (model.threats ?? [])
      .slice()
      .sort(
        (a, b) =>
          PRIORITY_RANK[b.priority] - PRIORITY_RANK[a.priority] ||
          b.score - a.score,
      );
    return (
      <>
        {model.category_scores ? (
          <Card className="p-4 mb-4">
            <p className="eyebrow-gilt mb-2 text-[10px]">Category scores</p>
            <div className="grid grid-cols-2 md:grid-cols-3 gap-2">
              {Object.entries(model.category_scores)
                .sort((a, b) => b[1] - a[1])
                .map(([cat, score]) => (
                  <div
                    key={cat}
                    className="flex items-baseline justify-between border border-zinc-200 px-3 py-2"
                  >
                    <span className="text-sm">{cat}</span>
                    <span className="font-mono font-bold">
                      {score.toFixed(1)}
                    </span>
                  </div>
                ))}
            </div>
          </Card>
        ) : null}
        <Card className="p-0 overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-zinc-200 bg-zinc-50 text-left">
                <Th>Asset</Th>
                <Th>Category</Th>
                <Th>Threat</Th>
                <Th>D</Th>
                <Th>R</Th>
                <Th>E</Th>
                <Th>A</Th>
                <Th>D</Th>
                <Th>Score</Th>
                <Th>Priority</Th>
              </tr>
            </thead>
            <tbody>
              {ranked.map((t, i) => (
                <tr key={i} className="border-b border-zinc-100">
                  <Td className="font-mono text-xs">{t.asset}</Td>
                  <Td>{t.category}</Td>
                  <Td>{t.threat}</Td>
                  <Td className="font-mono text-xs text-center">{t.damage}</Td>
                  <Td className="font-mono text-xs text-center">
                    {t.reproducibility}
                  </Td>
                  <Td className="font-mono text-xs text-center">
                    {t.exploitability}
                  </Td>
                  <Td className="font-mono text-xs text-center">
                    {t.affected_users}
                  </Td>
                  <Td className="font-mono text-xs text-center">
                    {t.discoverability}
                  </Td>
                  <Td className="font-mono font-bold text-center">
                    {t.score.toFixed(1)}
                  </Td>
                  <Td>
                    <Badge>{t.priority}</Badge>
                  </Td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      </>
    );
  }

  // STRIDE
  return (
    <Card className="p-0 overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-zinc-200 bg-zinc-50 text-left">
            <Th>Asset</Th>
            <Th>Category</Th>
            <Th>Threats</Th>
            <Th>Mitigations</Th>
          </tr>
        </thead>
        <tbody>
          {(model.table ?? []).map((row, i) => (
            <tr key={i} className="border-b border-zinc-100 align-top">
              <Td className="font-mono text-xs">{row.asset}</Td>
              <Td className="font-bold">{row.category}</Td>
              <Td>
                <ul className="list-disc list-inside text-sm">
                  {row.threats.map((t, j) => (
                    <li key={j}>{t}</li>
                  ))}
                </ul>
              </Td>
              <Td>
                <ul className="list-disc list-inside text-sm text-zinc-600">
                  {row.mitigations.map((m, j) => (
                    <li key={j}>{m}</li>
                  ))}
                </ul>
              </Td>
            </tr>
          ))}
        </tbody>
      </table>
    </Card>
  );
}

function Th({ children }: { children: React.ReactNode }) {
  return (
    <th className="px-3 py-2 text-xs uppercase tracking-wider">{children}</th>
  );
}

function Td({
  children,
  className,
}: {
  children: React.ReactNode;
  className?: string;
}) {
  return <td className={"px-3 py-2 " + (className ?? "")}>{children}</td>;
}
