"use client";

import { useState } from "react";

import { Input, Label } from "@/components/brutal";

export type GraphqlOperation = "query" | "mutation" | "subscription";

export type GraphqlConfig = {
  kind: "graphql";
  introspection_enabled: boolean;
  schema_sdl?: string;
  max_query_depth: number;
  operations_to_test: GraphqlOperation[];
  // WAF evasion — clean egress + custom headers for WAF-fronted targets.
  proxy?: string;
  headers?: Record<string, string>;
};

export const DEFAULT_GRAPHQL_CONFIG: GraphqlConfig = {
  kind: "graphql",
  introspection_enabled: true,
  schema_sdl: "",
  max_query_depth: 10,
  operations_to_test: ["query", "mutation"],
  proxy: "",
};

function parseHeaderLines(text: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const line of text.split("\n")) {
    const i = line.indexOf(":");
    if (i <= 0) continue;
    const k = line.slice(0, i).trim();
    if (k) out[k] = line.slice(i + 1).trim();
  }
  return out;
}

function headersToText(h?: Record<string, string>): string {
  return h
    ? Object.entries(h)
        .map(([k, v]) => `${k}: ${v}`)
        .join("\n")
    : "";
}

export type GraphqlCredentials = {
  username: string;
  password: string;
  api_key: string;
  token: string;
  cookie: string;
};

export const EMPTY_GRAPHQL_CREDS: GraphqlCredentials = {
  username: "",
  password: "",
  api_key: "",
  token: "",
  cookie: "",
};

const OPERATIONS: Array<{ id: GraphqlOperation; label: string; hint: string }> =
  [
    {
      id: "query",
      label: "Query",
      hint: "Read operations — always safe to fuzz.",
    },
    {
      id: "mutation",
      label: "Mutation",
      hint: "Write operations — disable if the target is shared / prod.",
    },
    {
      id: "subscription",
      label: "Subscription",
      hint: "Long-lived WS — limited coverage.",
    },
  ];

export function GraphqlFormSection({
  value,
  onChange,
  name,
  setName,
  endpoint,
  setEndpoint,
  creds,
  setCreds,
}: {
  value: GraphqlConfig;
  onChange: (v: GraphqlConfig) => void;
  name: string;
  setName: (v: string) => void;
  endpoint: string;
  setEndpoint: (v: string) => void;
  creds: GraphqlCredentials;
  setCreds: (v: GraphqlCredentials) => void;
}) {
  const [headersText, setHeadersText] = useState<string>(() =>
    headersToText(value.headers),
  );

  function toggleOperation(op: GraphqlOperation) {
    const next = value.operations_to_test.includes(op)
      ? value.operations_to_test.filter((o) => o !== op)
      : [...value.operations_to_test, op];
    if (next.length === 0) return; // require at least one
    onChange({ ...value, operations_to_test: next });
  }

  return (
    <>
      <section>
        <div className="flex items-baseline gap-3 mb-5">
          <span className="eyebrow-gilt">G1</span>
          <h2 className="font-display text-[18px] text-ink">GraphQL API</h2>
        </div>
        <div className="grid md:grid-cols-2 gap-5">
          <div className="md:col-span-2">
            <Label>GraphQL endpoint</Label>
            <Input
              required
              type="url"
              placeholder="https://api.example.com/graphql"
              value={endpoint}
              onChange={(e) => setEndpoint(e.target.value)}
            />
          </div>
          <div className="md:col-span-2">
            <Label>Name (optional)</Label>
            <Input
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="Public GraphQL"
            />
          </div>
        </div>
      </section>

      <hr className="rule" />

      <section>
        <div className="flex items-baseline gap-3 mb-1">
          <span className="eyebrow-gilt">G2</span>
          <h2 className="font-display text-[18px] text-ink">
            Schema discovery
          </h2>
        </div>
        <p className="text-[13px] text-slate italic mb-4">
          When introspection is on, the scanner fetches the schema at runtime
          via the standard
          <code> __schema</code> query. When off, paste the SDL — required for
          fuzzing.
        </p>

        <label className="flex items-center gap-3 cursor-pointer mb-4">
          <input
            type="checkbox"
            checked={value.introspection_enabled}
            onChange={(e) =>
              onChange({
                ...value,
                introspection_enabled: e.target.checked,
                schema_sdl: e.target.checked ? "" : value.schema_sdl,
              })
            }
            className="w-[16px] h-[16px] border border-hairline rounded-sm accent-ink"
          />
          <span className="font-body text-[13px] text-ink">
            Introspection is enabled on the endpoint
          </span>
        </label>

        {!value.introspection_enabled && (
          <div>
            <Label>Schema SDL (required when introspection is off)</Label>
            <textarea
              required
              rows={10}
              value={value.schema_sdl ?? ""}
              onChange={(e) =>
                onChange({ ...value, schema_sdl: e.target.value })
              }
              placeholder={`type Query {\n  user(id: ID!): User\n}\n\ntype User { id: ID!  email: String! }`}
              className="w-full font-mono text-[11px] bg-paper border border-hairline rounded-sm p-3 focus:outline-none focus:border-ink"
            />
          </div>
        )}
      </section>

      <hr className="rule" />

      <section>
        <div className="flex items-baseline gap-3 mb-4">
          <span className="eyebrow-gilt">G3</span>
          <h2 className="font-display text-[18px] text-ink">
            Operations to test
          </h2>
        </div>
        <div className="grid sm:grid-cols-3 gap-3">
          {OPERATIONS.map((op) => {
            const active = value.operations_to_test.includes(op.id);
            return (
              <label
                key={op.id}
                className={
                  "block border rounded-sm p-4 cursor-pointer transition-colors " +
                  (active
                    ? "border-ink bg-vellum"
                    : "border-hairline bg-paper hover:border-ink")
                }
              >
                <span className="flex items-center gap-2">
                  <input
                    type="checkbox"
                    checked={active}
                    onChange={() => toggleOperation(op.id)}
                    className="w-[16px] h-[16px] border border-hairline rounded-sm accent-ink"
                  />
                  <span className="font-mono text-[12px] text-ink">
                    {op.label}
                  </span>
                </span>
                <span className="mt-1 block font-mono text-[11px] text-mist">
                  {op.hint}
                </span>
              </label>
            );
          })}
        </div>
      </section>

      <hr className="rule" />

      <section>
        <div className="flex items-baseline gap-3 mb-4">
          <span className="eyebrow-gilt">G4</span>
          <h2 className="font-display text-[18px] text-ink">Query depth</h2>
        </div>
        <div className="grid sm:grid-cols-2 gap-5">
          <div>
            <Label>Max query depth (1–50)</Label>
            <Input
              type="number"
              min={1}
              max={50}
              value={value.max_query_depth}
              onChange={(e) =>
                onChange({
                  ...value,
                  max_query_depth: Math.max(
                    1,
                    Math.min(50, Number(e.target.value) || 1),
                  ),
                })
              }
            />
            <p className="mt-1.5 font-mono text-[11px] text-mist">
              graphql-cop + InQL use this to bound nested-query DoS probes.
            </p>
          </div>
        </div>
      </section>

      <hr className="rule" />

      <section>
        <div className="flex items-baseline gap-3 mb-1">
          <span className="eyebrow-gilt">G5</span>
          <h2 className="font-display text-[18px] text-ink">
            Credentials (optional)
          </h2>
        </div>
        <p className="text-[13px] text-slate italic mb-6">
          Fernet-encrypted at rest.
        </p>
        <div className="grid sm:grid-cols-2 gap-5">
          <div>
            <Label>Bearer token</Label>
            <Input
              value={creds.token}
              onChange={(e) => setCreds({ ...creds, token: e.target.value })}
              autoComplete="off"
            />
          </div>
          <div>
            <Label>API key</Label>
            <Input
              value={creds.api_key}
              onChange={(e) => setCreds({ ...creds, api_key: e.target.value })}
              autoComplete="off"
            />
          </div>
          <div className="sm:col-span-2">
            <Label>Cookie header</Label>
            <Input
              value={creds.cookie}
              onChange={(e) => setCreds({ ...creds, cookie: e.target.value })}
              placeholder="session=abc123"
              autoComplete="off"
            />
          </div>
          <div>
            <Label>Username (Basic auth)</Label>
            <Input
              value={creds.username}
              onChange={(e) => setCreds({ ...creds, username: e.target.value })}
              autoComplete="off"
            />
          </div>
          <div>
            <Label>Password (Basic auth)</Label>
            <Input
              type="password"
              value={creds.password}
              onChange={(e) => setCreds({ ...creds, password: e.target.value })}
              autoComplete="off"
            />
          </div>
        </div>
      </section>

      <hr className="rule" />

      <section>
        <div className="flex items-baseline gap-3 mb-1">
          <span className="eyebrow-gilt">G6</span>
          <h2 className="font-display text-[18px] text-ink">
            WAF evasion (optional)
          </h2>
        </div>
        <p className="text-[13px] text-slate italic mb-4">
          Route scanner traffic through a clean egress and send realistic
          headers to get past a WAF that blocks by IP or signature (e.g. ThreatX
          / Cloudflare returning 403). Only use against targets you are
          authorized to test.
        </p>
        <div className="grid gap-5">
          <div>
            <Label>Egress proxy URL</Label>
            <Input
              type="text"
              placeholder="http://user:pass@proxy.example.com:8080"
              value={value.proxy ?? ""}
              onChange={(e) => onChange({ ...value, proxy: e.target.value })}
              autoComplete="off"
            />
            <p className="mt-1.5 font-mono text-[11px] text-mist">
              http(s):// egress applied to the HTTP client + graphql-cop / InQL.
              Blank = direct.
            </p>
          </div>
          <div>
            <Label>Custom request headers (one per line — Header: value)</Label>
            <textarea
              rows={4}
              value={headersText}
              onChange={(e) => {
                setHeadersText(e.target.value);
                onChange({
                  ...value,
                  headers: parseHeaderLines(e.target.value),
                });
              }}
              placeholder={
                "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) ...\nOrigin: https://app.example.com"
              }
              className="w-full font-mono text-[11px] bg-paper border border-hairline rounded-sm p-3 focus:outline-none focus:border-ink"
            />
            <p className="mt-1.5 font-mono text-[11px] text-mist">
              Merged into every request; a realistic User-Agent is sent by
              default.
            </p>
          </div>
        </div>
      </section>
    </>
  );
}
